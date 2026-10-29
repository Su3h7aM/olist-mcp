package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbot/olist-mcp/internal/config"
	"github.com/openbot/olist-mcp/internal/owner"
	"github.com/openbot/olist-mcp/internal/store"
	"golang.org/x/crypto/argon2"
)

// Secrets are compared with strings.Contains and never printed.
const (
	secretA       = "client-secret-A-7731"
	secretB       = "client-secret-B-2208"
	ownerPassword = "owner passphrase for runtime tests"
	publicOrigin  = "https://olist.example.com"
)

// fakeProvider is the OAuth token endpoint. It exchanges known codes and refresh
// tokens, and it checks the client secret sent in the form.
type fakeProvider struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls int
	// seenSecrets records which client IDs presented a matching secret.
	seenClients []string
}

var providerCodes = map[string]struct{ access, refresh string }{
	"code-a": {"tok-a-1", "refresh-a-1"},
	"code-b": {"tok-b-1", "refresh-b-1"},
}

var providerSecrets = map[string]string{"client-a": secretA, "client-b": secretB}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	p := &fakeProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.calls++
		p.mu.Unlock()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		clientID := r.PostForm.Get("client_id")
		if providerSecrets[clientID] == "" || r.PostForm.Get("client_secret") != providerSecrets[clientID] {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		p.mu.Lock()
		p.seenClients = append(p.seenClients, clientID)
		p.mu.Unlock()
		if r.PostForm.Get("grant_type") != "authorization_code" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		tok, ok := providerCodes[r.PostForm.Get("code")]
		if !ok {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"token_type":"Bearer","expires_in":14400}`, tok.access, tok.refresh)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// olistReq is one request the fake Olist API received.
type olistReq struct {
	path  string
	token string
}

// fakeOlist serves the Olist API. Each access token maps to an account label,
// and the records it returns carry that label so tests can detect leakage.
type fakeOlist struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []olistReq
	owners map[string]string // access token -> account label
	counts map[string]int    // account label -> number of products, contacts and orders
}

func newFakeOlist(t *testing.T, counts map[string]int) *fakeOlist {
	t.Helper()
	f := &fakeOlist{
		owners: map[string]string{"tok-a-1": "a", "tok-b-1": "b"},
		counts: counts,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		f.reqs = append(f.reqs, olistReq{path: r.URL.Path, token: token})
		label, ok := f.owners[token]
		n := f.counts[label]
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rest := strings.TrimPrefix(r.URL.Path, "/public-api/v3/")
		resource, id, isDetail := strings.Cut(rest, "/")
		if isDetail {
			fmt.Fprintf(w, `{"id":%s,"resource":%q,"tag":%q}`, id, resource, label)
			return
		}
		offset := 0
		fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &offset)
		var items []string
		for i := offset + 1; i <= n && i <= offset+100; i++ {
			items = append(items, fmt.Sprintf(`{"id":%d}`, i))
		}
		fmt.Fprintf(w, `{"itens":[%s],"paginacao":{"limit":100,"offset":%d,"total":%d}}`,
			strings.Join(items, ","), offset, n)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOlist) requests() []olistReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]olistReq(nil), f.reqs...)
}

// ownerHash builds an argon2id hash of ownerPassword with the minimum allowed costs.
func ownerHash(t *testing.T) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(ownerPassword), salt, 1, 8192, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=8192,t=1,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// fixture is one composed runtime with its fake provider and Olist API.
type fixture struct {
	rt       *Runtime
	provider *fakeProvider
	olist    *fakeOlist
	dir      string
}

// setup composes two accounts. Account a allows readsPerMinute reads per minute.
func setup(t *testing.T, owner func(*http.Request) (string, error), readsPerMinute int) *fixture {
	t.Helper()
	dir := t.TempDir()
	secretPathA := filepath.Join(dir, "secret-a.txt")
	secretPathB := filepath.Join(dir, "secret-b.txt")
	if err := os.WriteFile(secretPathA, []byte(secretA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPathB, []byte(secretB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{
		"listen": "127.0.0.1:0",
		"public_url": %q,
		"data_dir": %q,
		"accounts": [
			{"id":"acc-a","display_name":"Account A","client_id":"client-a","client_secret_file":%q,"reads_per_minute":%d},
			{"id":"acc-b","display_name":"Account B","client_id":"client-b","client_secret_file":%q,"reads_per_minute":140}
		]
	}`, publicOrigin, dir, secretPathA, readsPerMinute, secretPathB)
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider(t)
	olistAPI := newFakeOlist(t, map[string]int{"a": 3, "b": 2})
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	rt, err := New(context.Background(), Options{
		Config:        cfg,
		OwnerAuth:     owner,
		TokenKey:      key,
		OAuthAuthURL:  "https://accounts.example/authorize",
		OAuthTokenURL: provider.srv.URL + "/token",
		APIBaseURL:    olistAPI.srv.URL + "/public-api/v3",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { rt.Close() })
	return &fixture{rt: rt, provider: provider, olist: olistAPI, dir: dir}
}

func acceptOwner(*http.Request) (string, error) { return "owner", nil }

func refuseOwner(*http.Request) (string, error) { return "", errors.New("not the owner") }

// startFlow posts the admin start form for an account and returns the state.
func startFlow(t *testing.T, rt *Runtime, account string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	form := url.Values{"account": {account}}
	r := httptest.NewRequest(http.MethodPost, "/oauth/olist/start", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", publicOrigin)
	rec := httptest.NewRecorder()
	rt.Admin().Start(rec, r)
	if rec.Code != http.StatusSeeOther {
		return rec, ""
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return rec, loc.Query().Get("state")
}

func callback(rt *Runtime, state, code string) *httptest.ResponseRecorder {
	q := url.Values{"state": {state}, "code": {code}}
	r := httptest.NewRequest(http.MethodGet, "/oauth/olist/callback?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	rt.Admin().Callback(rec, r)
	return rec
}

// connect runs the whole owner-driven flow for an account.
func connect(t *testing.T, rt *Runtime, account, code string) {
	t.Helper()
	rec, state := startFlow(t, rt, account)
	if state == "" {
		t.Fatalf("start for %s returned %d", account, rec.Code)
	}
	if got := callback(rt, state, code); got.Code != http.StatusOK {
		t.Fatalf("callback for %s returned %d", account, got.Code)
	}
}

func count(t *testing.T, rt *Runtime, account, resource string) int {
	t.Helper()
	recs, err := rt.Mirror().List(context.Background(), account, resource, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s.txt")
	if err := os.WriteFile(secret, []byte(secretA), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func() *config.Config {
		cfg, err := config.Parse([]byte(fmt.Sprintf(`{"listen":"127.0.0.1:0","public_url":%q,"data_dir":%q,
			"accounts":[{"id":"acc-a","display_name":"A","client_id":"client-a","client_secret_file":%q,"reads_per_minute":30}]}`,
			publicOrigin, dir, secret)))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	key := make([]byte, 32)
	cases := map[string]func(o *Options){
		"nil config":        func(o *Options) { o.Config = nil },
		"nil owner":         func(o *Options) { o.OwnerAuth = nil },
		"short key":         func(o *Options) { o.TokenKey = make([]byte, 16) },
		"http auth url":     func(o *Options) { o.OAuthAuthURL = "http://accounts.example/auth" },
		"remote http token": func(o *Options) { o.OAuthTokenURL = "http://accounts.example/token" },
		"userinfo in url":   func(o *Options) { o.OAuthTokenURL = "https://user:pw@accounts.example/token" },
		"unreadable secret": func(o *Options) { o.ReadSecret = func(string) ([]byte, error) { return nil, errors.New("denied") } },
		"empty secret":      func(o *Options) { o.ReadSecret = func(string) ([]byte, error) { return []byte(" \n"), nil } },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			opts := Options{Config: base(), OwnerAuth: acceptOwner, TokenKey: key}
			mutate(&opts)
			rt, err := New(context.Background(), opts)
			if err == nil {
				rt.Close()
				t.Fatal("invalid options accepted")
			}
			if strings.Contains(err.Error(), secretA) {
				t.Fatal("error message leaks a client secret")
			}
		})
	}
	relative := base()
	relative.DataDir = "relative/dir"
	if _, err := New(context.Background(), Options{Config: relative, OwnerAuth: acceptOwner, TokenKey: key}); err == nil {
		t.Fatal("relative data directory accepted")
	}
}

func TestAccountSelectionRefusesUnknownAccounts(t *testing.T) {
	f := setup(t, acceptOwner, 30)
	if got := f.rt.Accounts(); len(got) != 2 || got[0] != "acc-a" || got[1] != "acc-b" {
		t.Fatalf("accounts = %v", got)
	}
	for _, account := range []string{"", "missing", "ACC-A", "acc-a ", "acc-a&account=acc-b"} {
		rec, state := startFlow(t, f.rt, account)
		if state != "" || rec.Code != http.StatusBadRequest {
			t.Fatalf("account %q: start returned %d", account, rec.Code)
		}
	}
	rec, state := startFlow(t, f.rt, "acc-b")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("configured account refused: %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("client_id") != "client-b" {
		t.Fatalf("authorization URL carries client %q, want client-b", loc.Query().Get("client_id"))
	}
	if loc.Query().Get("redirect_uri") != publicOrigin+CallbackPath {
		t.Fatalf("redirect_uri = %q, want the shared callback", loc.Query().Get("redirect_uri"))
	}
	if strings.Contains(rec.Header().Get("Location"), secretB) {
		t.Fatal("authorization URL leaks the client secret")
	}
	// The state is bound to acc-b, so a callback completes that account only.
	if got := callback(f.rt, state, "code-b"); got.Code != http.StatusOK {
		t.Fatalf("callback returned %d", got.Code)
	}
	if count(t, f.rt, "acc-a", "produtos") != 0 {
		t.Fatal("callback for acc-b touched acc-a")
	}
}

func TestOwnerRejectionBlocksStartAndCallback(t *testing.T) {
	f := setup(t, refuseOwner, 30)
	rec, state := startFlow(t, f.rt, "acc-a")
	if rec.Code != http.StatusUnauthorized || state != "" {
		t.Fatalf("unauthenticated start returned %d", rec.Code)
	}
	if n := f.rt.states.Len(); n != 0 {
		t.Fatalf("unauthenticated start issued %d states", n)
	}
	if got := callback(f.rt, "anything", "code-a"); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated callback returned %d", got.Code)
	}
	if f.provider.callCount() != 0 {
		t.Fatal("unauthenticated callback reached the provider")
	}
}

// The real owner manager enforces CSRF on Start. Without a token the owner is
// refused, so no authorization flow begins.
func TestRealOwnerEnforcesCSRFOnStart(t *testing.T) {
	ownerMgr, err := owner.New(owner.Config{PasswordHash: ownerHash(t), PublicOrigin: publicOrigin})
	if err != nil {
		t.Fatal(err)
	}
	f := setup(t, ownerMgr.Owner, 30)

	login := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(url.Values{"password": {ownerPassword}}.Encode()))
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login.Header.Set("Origin", publicOrigin)
	login.RemoteAddr = "203.0.113.4:1000"
	loginRec := httptest.NewRecorder()
	ownerMgr.Login(loginRec, login)
	var cookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == owner.CookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("owner login failed: %d", loginRec.Code)
	}

	form := url.Values{"account": {"acc-a"}}
	noCSRF := httptest.NewRequest(http.MethodPost, "/oauth/olist/start", strings.NewReader(form.Encode()))
	noCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noCSRF.Header.Set("Origin", publicOrigin)
	noCSRF.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.rt.Admin().Start(rec, noCSRF)
	if rec.Code != http.StatusUnauthorized || f.rt.states.Len() != 0 {
		t.Fatalf("start without CSRF returned %d with %d states", rec.Code, f.rt.states.Len())
	}

	withCSRF := httptest.NewRequest(http.MethodPost, "/oauth/olist/start", strings.NewReader(form.Encode()))
	withCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withCSRF.Header.Set("Origin", publicOrigin)
	withCSRF.AddCookie(cookie)
	token, err := ownerMgr.CSRFToken(withCSRF)
	if err != nil {
		t.Fatal(err)
	}
	withCSRF.Header.Set(owner.CSRFHeader, token)
	rec = httptest.NewRecorder()
	f.rt.Admin().Start(rec, withCSRF)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start with CSRF returned %d", rec.Code)
	}
}

func TestTokenExchangePersistsAndSyncUsesIt(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	connect(t, f.rt, "acc-a", "code-a")

	if f.provider.callCount() != 1 {
		t.Fatalf("provider contacted %d times during the exchange, want 1", f.provider.callCount())
	}
	// The refresh token is stored encrypted, and the store can read it back.
	saved, err := f.rt.tokens.Get(context.Background(), "acc-a")
	if err != nil {
		t.Fatalf("exchanged token not persisted: %v", err)
	}
	if saved.RefreshToken != "refresh-a-1" || saved.AccessToken != "tok-a-1" {
		t.Fatal("persisted token does not match the provider response")
	}
	if !saved.Expiry.After(time.Now().Add(3 * time.Hour)) {
		t.Fatal("persisted expiry is not the provider's 4-hour lifetime")
	}
	// The client secret reached the provider only in the token request. Check
	// the provider accepted the right client, and nothing else.
	if got := f.provider.seenClients; len(got) != 1 || got[0] != "client-a" {
		t.Fatalf("provider saw clients %v, want [client-a]", got)
	}

	if err := f.rt.SyncOnce(context.Background(), "acc-a"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := count(t, f.rt, "acc-a", "produtos"); got != 3 {
		t.Fatalf("produtos stored = %d, want 3", got)
	}
	for _, req := range f.olist.requests() {
		if req.token != "tok-a-1" {
			t.Fatalf("sync request used token %q, want acc-a's token", req.token)
		}
	}
}

func TestRateLimitedSyncStopsAtBudget(t *testing.T) {
	// With 3 reads per minute, 20% is reserved for on-demand reads, so the
	// background budget is 2: one product list call and one detail call. The
	// third read must wait for a minute, so the context deadline ends the sync.
	f := setup(t, acceptOwner, 3)
	connect(t, f.rt, "acc-a", "code-a")
	before := len(f.olist.requests())

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	err := f.rt.SyncOnce(ctx, "acc-a")
	if err == nil {
		t.Fatal("sync finished with a budget of 2 background reads")
	}
	sent := len(f.olist.requests()) - before
	if sent != 2 {
		t.Fatalf("Olist received %d requests, want exactly 2 from the background budget", sent)
	}
	if got := count(t, f.rt, "acc-a", "produtos"); got != 1 {
		t.Fatalf("produtos stored = %d, want 1 before the budget ran out", got)
	}
	// The tracked job records the aborted run as an error, not complete.
	cov, err := f.rt.Mirror().GetCoverage(context.Background(), "acc-a", "produtos")
	if err != nil {
		t.Fatal(err)
	}
	if cov.Status != store.StatusError || !cov.LastSuccessAt.IsZero() {
		t.Fatalf("coverage after aborted sync = %+v; want error with no success time", cov)
	}
}

func TestAccountsAreIsolated(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	connect(t, f.rt, "acc-a", "code-a")
	connect(t, f.rt, "acc-b", "code-b")

	ctx := context.Background()
	if err := f.rt.SyncOnce(ctx, "acc-a"); err != nil {
		t.Fatal(err)
	}
	if err := f.rt.SyncOnce(ctx, "acc-b"); err != nil {
		t.Fatal(err)
	}

	if got := count(t, f.rt, "acc-a", "produtos"); got != 3 {
		t.Fatalf("acc-a produtos = %d, want 3", got)
	}
	if got := count(t, f.rt, "acc-b", "produtos"); got != 2 {
		t.Fatalf("acc-b produtos = %d, want 2", got)
	}
	// Each account's stored payloads carry only its own label.
	for _, pair := range []struct{ account, label string }{{"acc-a", "a"}, {"acc-b", "b"}} {
		recs, err := f.rt.Mirror().List(ctx, pair.account, "produtos", 1000, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range recs {
			if !strings.Contains(string(rec.Payload), fmt.Sprintf(`"tag":%q`, pair.label)) {
				t.Fatalf("%s stored a record from another account: %s", pair.account, rec.Payload)
			}
		}
	}
	// Each account's requests used only its own token.
	for _, req := range f.olist.requests() {
		switch req.token {
		case "tok-a-1", "tok-b-1":
		default:
			t.Fatalf("request with unexpected token %q", req.token)
		}
	}
	// Coverage is tracked per account.
	for _, account := range []string{"acc-a", "acc-b"} {
		cov, err := f.rt.Mirror().GetCoverage(ctx, account, "pedidos")
		if err != nil || cov.Status != store.StatusComplete {
			t.Fatalf("%s pedidos coverage = %+v, %v", account, cov, err)
		}
	}
}

func TestSyncWithoutConnectionFailsClosed(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	err := f.rt.SyncOnce(context.Background(), "acc-a")
	if err == nil {
		t.Fatal("sync succeeded for an account that never connected")
	}
	if len(f.olist.requests()) != 0 {
		t.Fatalf("unconnected account reached Olist: %d requests", len(f.olist.requests()))
	}
	cov, err := f.rt.Mirror().GetCoverage(context.Background(), "acc-a", "produtos")
	if err != nil || cov.Status != store.StatusError {
		t.Fatalf("coverage for unconnected account = %+v, %v", cov, err)
	}
}

func TestJobsCoverEveryResourceAndRejectUnknownAccount(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	connect(t, f.rt, "acc-a", "code-a")
	jobs, err := f.rt.Jobs("acc-a")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, j := range jobs {
		names = append(names, j.Name)
	}
	if strings.Join(names, ",") != "produtos,contatos,pedidos" {
		t.Fatalf("job order = %v", names)
	}
	if _, err := f.rt.Jobs("missing"); err == nil {
		t.Fatal("jobs returned for an unknown account")
	}
	if err := f.rt.SyncOnce(context.Background(), "missing"); err == nil {
		t.Fatal("sync ran for an unknown account")
	}
	if err := f.rt.SyncOnce(context.Background(), "acc-a"); err != nil {
		t.Fatal(err)
	}
	for _, resource := range []string{"produtos", "contatos", "pedidos"} {
		cov, err := f.rt.Mirror().GetCoverage(context.Background(), "acc-a", resource)
		if err != nil || cov.Status != store.StatusComplete || cov.LastSuccessAt.IsZero() {
			t.Fatalf("%s coverage = %+v, %v", resource, cov, err)
		}
	}
}

func TestSecretsNeverAppearInResponses(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	rec, state := startFlow(t, f.rt, "acc-a")
	bad := callback(f.rt, "unknown-state", "code-a")
	good := callback(f.rt, state, "code-a")
	for _, body := range []string{rec.Body.String(), rec.Header().Get("Location"), bad.Body.String(), good.Body.String()} {
		for _, secret := range []string{secretA, secretB, "tok-a-1", "refresh-a-1"} {
			if strings.Contains(body, secret) {
				t.Fatal("a handler response leaks a credential")
			}
		}
	}
}

func TestCloseReleasesDatabases(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	if err := f.rt.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.rt.tokens.Get(context.Background(), "acc-a"); err == nil {
		t.Fatal("token store still usable after Close")
	}
	// Both database files exist under the data directory, with private modes for the token store.
	for _, name := range []string{"olist.db", "control.db"} {
		if _, err := os.Stat(filepath.Join(f.dir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	info, err := os.Stat(filepath.Join(f.dir, "control.db"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("control.db mode = %v, %v", info.Mode().Perm(), err)
	}
}

// The token store is exercised through the runtime, so its encryption must hold
// for the persisted row: the raw access token is not in the file.
func TestPersistedTokenIsEncryptedOnDisk(t *testing.T) {
	f := setup(t, acceptOwner, 60)
	connect(t, f.rt, "acc-a", "code-a")
	if err := f.rt.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"control.db", "control.db-wal"} {
		raw, err := os.ReadFile(filepath.Join(f.dir, name))
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte("refresh-a-1")) || bytes.Contains(raw, []byte("tok-a-1")) {
			t.Fatalf("plaintext token found in %s", name)
		}
	}
}

func TestSyncOnceCancelledWhileWaitingForAccount(t *testing.T) {
	a := &account{syncSlot: make(chan struct{}, 1)}
	a.syncSlot <- struct{}{}
	rt := &Runtime{accounts: map[string]*account{"a": a}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rt.SyncOnce(ctx, "a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbot/olist-mcp/internal/oauthstate"
	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
)

// Credential sentinels are checked with strings.Contains and never printed.
const (
	secClientSecret = "sec-sentinel-client-secret-6b2a"
	secCode         = "sec-sentinel-auth-code-18fd"
	secRefresh      = "sec-sentinel-refresh-token-e4c9"
	secAccess       = "sec-sentinel-access-token-0a57"
)

const secOwnerHeader = "X-Test-Owner"

// secStore records writes and can be told to fail them.
type secStore struct {
	mu      sync.Mutex
	puts    int
	putErr  error
	tokens  map[string]tokenstore.Token
	getErrs int
}

func (s *secStore) Get(_ context.Context, account string) (tokenstore.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[account]
	if !ok {
		return tokenstore.Token{}, errors.New("token not found")
	}
	return tok, nil
}

func (s *secStore) Put(_ context.Context, account string, tok tokenstore.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	if s.putErr != nil {
		return s.putErr
	}
	if s.tokens == nil {
		s.tokens = map[string]tokenstore.Token{}
	}
	s.tokens[account] = tok
	return nil
}

func (s *secStore) putCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

// secProvider is a token endpoint double whose behavior each test chooses.
type secProvider struct {
	calls atomic.Int32
	srv   *httptest.Server
}

func newSecProvider(t *testing.T, handler http.HandlerFunc) *secProvider {
	t.Helper()
	p := &secProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func secOKProvider(t *testing.T) *secProvider {
	return newSecProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"` + secAccess + `","refresh_token":"` + secRefresh + `","token_type":"Bearer","expires_in":3600}`))
	})
}

// secOwner authenticates requests by a header. Requests without it are unauthenticated.
func secOwner(r *http.Request) (string, error) {
	o := r.Header.Get(secOwnerHeader)
	if o == "" {
		return "", errors.New("unauthenticated")
	}
	return o, nil
}

type secEnv struct {
	h        *Handler
	registry *oauthstate.Registry
	store    *secStore
	provider *secProvider
}

func newSecEnv(t *testing.T, ttl time.Duration, provider *secProvider) *secEnv {
	t.Helper()
	registry, err := oauthstate.New(ttl, 100)
	if err != nil {
		t.Fatal(err)
	}
	store := &secStore{}
	cfg := oauth2.Config{
		ClientID:     "sec-client",
		ClientSecret: secClientSecret,
		RedirectURL:  "https://example.com/oauth/olist/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.example/authorize",
			TokenURL:  provider.srv.URL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	configs := func(a string) (oauth2.Config, bool) { return cfg, a == "account-a" || a == "account-b" }
	h, err := New(secOwner, configs, registry, store)
	if err != nil {
		t.Fatal(err)
	}
	return &secEnv{h: h, registry: registry, store: store, provider: provider}
}

func (e *secEnv) start(t *testing.T, owner, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/olist/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if owner != "" {
		req.Header.Set(secOwnerHeader, owner)
	}
	rec := httptest.NewRecorder()
	e.h.Start(rec, req)
	return rec
}

// startState runs a valid start for owner and account and returns the state.
func (e *secEnv) startState(t *testing.T, owner, account string) string {
	t.Helper()
	rec := e.start(t, owner, "account="+account)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start returned %d, want 303", rec.Code)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("redirect carries no state")
	}
	return state
}

func (e *secEnv) callback(owner, rawQuery string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oauth/olist/callback?"+rawQuery, nil)
	if owner != "" {
		req.Header.Set(secOwnerHeader, owner)
	}
	rec := httptest.NewRecorder()
	e.h.Callback(rec, req)
	return rec
}

func assertNoSecrets(t *testing.T, body string, extra ...string) {
	t.Helper()
	for _, s := range append([]string{secClientSecret, secCode, secRefresh, secAccess}, extra...) {
		if s != "" && strings.Contains(body, s) {
			t.Fatal("response body leaks a credential or submitted value")
		}
	}
}

func TestStartRequiresAuthentication(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	rec := env.start(t, "", "account=account-a")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated start returned %d, want 401", rec.Code)
	}
	if env.registry.Len() != 0 {
		t.Fatal("unauthenticated start issued a state")
	}
}

func TestStartRejectsEmptyOwnerWithoutError(t *testing.T) {
	registry, _ := oauthstate.New(time.Minute, 10)
	h, err := New(func(*http.Request) (string, error) { return "", nil },
		func(string) (oauth2.Config, bool) { return oauth2.Config{}, true }, registry, &secStore{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/start", strings.NewReader("account=account-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Start(rec, req)
	if rec.Code != http.StatusUnauthorized || registry.Len() != 0 {
		t.Fatalf("empty owner returned %d with %d states; want 401 and none", rec.Code, registry.Len())
	}
}

func TestMethodRestrictions(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/oauth/olist/start?account=account-a", nil)
		req.Header.Set(secOwnerHeader, "owner-a")
		rec := httptest.NewRecorder()
		env.h.Start(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("Start %s returned %d, want 405", method, rec.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/oauth/olist/callback?state=x&code=y", nil)
		req.Header.Set(secOwnerHeader, "owner-a")
		rec := httptest.NewRecorder()
		env.h.Callback(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("Callback %s returned %d, want 405", method, rec.Code)
		}
	}
	if env.registry.Len() != 0 || env.store.putCount() != 0 {
		t.Fatal("rejected methods changed state")
	}
}

func TestCallbackRequiresAuthenticationAndKeepsState(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")

	rec := env.callback("", "state="+state+"&code="+secCode)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated callback returned %d, want 401", rec.Code)
	}
	if env.provider.calls.Load() != 0 || env.store.putCount() != 0 {
		t.Fatal("unauthenticated callback reached the provider or store")
	}
	// The rightful owner can still complete the flow, so the failed request did not burn the state.
	if rec := env.callback("owner-a", "state="+state+"&code=ok"); rec.Code != http.StatusOK {
		t.Fatalf("owner could not complete after unauthenticated attempt: %d", rec.Code)
	}
}

func TestCallbackRejectsMissingOrDuplicateParameters(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")
	cases := map[string]string{
		"missing state":   "code=" + secCode,
		"missing code":    "state=" + state,
		"empty state":     "state=&code=" + secCode,
		"empty code":      "state=" + state + "&code=",
		"blank code":      "state=" + state + "&code=%20%20",
		"duplicate state": "state=" + state + "&state=" + state + "&code=" + secCode,
		"duplicate code":  "state=" + state + "&code=" + secCode + "&code=other",
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			rec := env.callback("owner-a", query)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("returned %d, want 400", rec.Code)
			}
			assertNoSecrets(t, rec.Body.String(), state)
		})
	}
	if env.provider.calls.Load() != 0 || env.store.putCount() != 0 {
		t.Fatal("malformed callback reached the provider or store")
	}
	// None of the malformed requests consumed the valid state.
	if rec := env.callback("owner-a", "state="+state+"&code=ok"); rec.Code != http.StatusOK {
		t.Fatalf("valid state lost after malformed requests: %d", rec.Code)
	}
}

func TestUnknownAccountRejected(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	for _, body := range []string{"account=missing", "account=", "", "account=account-a%00x"} {
		rec := env.start(t, "owner-a", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("start with %q returned %d, want 400", body, rec.Code)
		}
	}
	if env.registry.Len() != 0 {
		t.Fatal("unknown account issued a state")
	}
}

func TestStartIgnoresAccountInQueryString(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	req := httptest.NewRequest(http.MethodPost, "/oauth/olist/start?account=account-a", nil)
	req.Header.Set(secOwnerHeader, "owner-a")
	rec := httptest.NewRecorder()
	env.h.Start(rec, req)
	if rec.Code != http.StatusBadRequest || env.registry.Len() != 0 {
		t.Fatalf("query-string account accepted: %d", rec.Code)
	}
}

func TestStartBodySizeLimit(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	huge := "account=account-a&pad=" + strings.Repeat("x", 1<<20)
	rec := env.start(t, "owner-a", huge)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body returned %d, want 400", rec.Code)
	}
	if env.registry.Len() != 0 {
		t.Fatal("oversized body issued a state")
	}
}

func TestStartRedirectHasNoClientSecret(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	rec := env.start(t, "owner-a", "account=account-a")
	assertNoSecrets(t, rec.Header().Get("Location")+rec.Body.String())
	if strings.Contains(rec.Header().Get("Location"), "client_secret") {
		t.Fatal("redirect exposes a client secret parameter")
	}
}

func TestExpiredStateRejected(t *testing.T) {
	env := newSecEnv(t, 20*time.Millisecond, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")
	time.Sleep(60 * time.Millisecond)
	rec := env.callback("owner-a", "state="+state+"&code=ok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expired state returned %d, want 400", rec.Code)
	}
	if env.provider.calls.Load() != 0 || env.store.putCount() != 0 {
		t.Fatal("expired state reached the provider or store")
	}
}

func TestReplayedStateRejectedAndExchangedOnce(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")
	if rec := env.callback("owner-a", "state="+state+"&code=ok"); rec.Code != http.StatusOK {
		t.Fatalf("first use returned %d", rec.Code)
	}
	rec := env.callback("owner-a", "state="+state+"&code=ok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay returned %d, want 400", rec.Code)
	}
	if n := env.provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; replay must not exchange", n)
	}
	if n := env.store.putCount(); n != 1 {
		t.Fatalf("store written %d times; want 1", n)
	}
}

func TestWrongOwnerRejectedWithoutExchange(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")
	rec := env.callback("owner-b", "state="+state+"&code="+secCode)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong owner returned %d, want 400", rec.Code)
	}
	assertNoSecrets(t, rec.Body.String(), state)
	if env.provider.calls.Load() != 0 || env.store.putCount() != 0 {
		t.Fatal("wrong owner reached the provider or store")
	}
}

// Every rejection of a state must look identical, so a caller cannot tell an
// unknown, expired, replayed or foreign state apart.
func TestStateRejectionsAreIndistinguishable(t *testing.T) {
	env := newSecEnv(t, 20*time.Millisecond, secOKProvider(t))

	unknown := env.callback("owner-a", "state=never-issued&code=ok")

	foreign := env.startState(t, "owner-a", "account-a")
	wrongOwner := env.callback("owner-b", "state="+foreign+"&code=ok")

	expired := env.startState(t, "owner-a", "account-a")
	time.Sleep(60 * time.Millisecond)
	expiredRec := env.callback("owner-a", "state="+expired+"&code=ok")

	used := env.startState(t, "owner-a", "account-a")
	env.callback("owner-a", "state="+used+"&code=ok")
	replay := env.callback("owner-a", "state="+used+"&code=ok")

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"unknown": unknown, "wrong owner": wrongOwner, "expired": expiredRec, "replay": replay,
	} {
		if rec.Code != unknown.Code || rec.Body.String() != unknown.Body.String() {
			t.Fatalf("%s response differs from unknown-state response", name)
		}
	}
}

func TestProviderFailureDoesNotPersistOrLeak(t *testing.T) {
	provider := newSecProvider(t, func(w http.ResponseWriter, r *http.Request) {
		// Echo the submitted code and the client secret back, as a hostile or buggy provider might.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","echo_code":"` + r.FormValue("code") + `","echo_secret":"` + r.FormValue("client_secret") + `"}`))
	})
	env := newSecEnv(t, time.Minute, provider)
	state := env.startState(t, "owner-a", "account-a")

	rec := env.callback("owner-a", "state="+state+"&code="+secCode)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("provider failure returned %d, want 502", rec.Code)
	}
	if env.store.putCount() != 0 {
		t.Fatal("failed exchange persisted credentials")
	}
	assertNoSecrets(t, rec.Body.String(), state)
}

func TestPersistenceFailureDoesNotLeakCredentials(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	env.store.putErr = errors.New("write failed")
	state := env.startState(t, "owner-a", "account-a")

	rec := env.callback("owner-a", "state="+state+"&code="+secCode)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("persistence failure returned %d, want 502", rec.Code)
	}
	assertNoSecrets(t, rec.Body.String(), state)
}

func TestCallbackUnknownAccountAfterConsume(t *testing.T) {
	registry, _ := oauthstate.New(time.Minute, 10)
	provider := secOKProvider(t)
	cfg := oauth2.Config{ClientID: "c", ClientSecret: secClientSecret, RedirectURL: "https://example.com/cb",
		Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example/auth", TokenURL: provider.srv.URL, AuthStyle: oauth2.AuthStyleInParams}}
	store := &secStore{}
	removed := false
	var mu sync.Mutex
	configs := func(string) (oauth2.Config, bool) {
		mu.Lock()
		defer mu.Unlock()
		return cfg, !removed
	}
	h, err := New(secOwner, configs, registry, store)
	if err != nil {
		t.Fatal(err)
	}
	state, err := registry.Issue("owner-a", "account-a")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	removed = true
	mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/oauth/olist/callback?state="+state+"&code=ok", nil)
	req.Header.Set(secOwnerHeader, "owner-a")
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	if rec.Code != http.StatusBadRequest || provider.calls.Load() != 0 || store.putCount() != 0 {
		t.Fatalf("removed account returned %d, provider %d, puts %d", rec.Code, provider.calls.Load(), store.putCount())
	}
}

func TestCallbackDoesNotEchoSubmittedValues(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	probe := "probe-value-7d41"
	rec := env.callback("owner-a", "state="+probe+"&code="+probe)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("returned %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), probe) {
		t.Fatal("error response echoes the submitted state or code")
	}
}

func TestResponsesAreNotCacheable(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")
	cases := []*httptest.ResponseRecorder{
		env.start(t, "", "account=account-a"),
		env.callback("owner-a", "state=bad&code=x"),
		env.callback("owner-a", "state="+state+"&code=ok"),
	}
	for _, rec := range cases {
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", got)
		}
	}
	if got := env.callback("owner-a", "state=x&code=y").Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
}

// Concurrent callbacks with one valid state must exchange exactly once.
func TestConcurrentCallbacksExchangeOnce(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	state := env.startState(t, "owner-a", "account-a")

	var wg sync.WaitGroup
	codes := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- env.callback("owner-a", "state="+state+"&code=ok").Code
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d callbacks succeeded; want exactly 1", ok)
	}
	if n := env.provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; want 1", n)
	}
}

// Design check: Start does not verify same-origin or CSRF itself. It trusts the
// injected Owner function to do so. The test below documents that a cross-site
// POST is accepted when Owner accepts it, so the Owner wiring must enforce CSRF.
func TestStartTrustsOwnerForCSRF(t *testing.T) {
	env := newSecEnv(t, time.Minute, secOKProvider(t))
	req := httptest.NewRequest(http.MethodPost, "/oauth/olist/start", strings.NewReader("account=account-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set(secOwnerHeader, "owner-a")
	rec := httptest.NewRecorder()
	env.h.Start(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("cross-site POST returned %d; handler itself does not gate CSRF", rec.Code)
	}
}

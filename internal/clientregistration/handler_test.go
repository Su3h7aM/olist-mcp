package clientregistration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbot/olist-mcp/internal/clientregistry"
	_ "modernc.org/sqlite"
)

// Sentinels are checked with strings.Contains and never printed.
const regSentinel = "reg-sentinel-javascript-payload-4c1e"

type fixture struct {
	h    *Handler
	reg  *clientregistry.Registry
	path string
	now  *atomic.Pointer[time.Time]
}

func (f *fixture) clock() time.Time { return *f.now.Load() }

func (f *fixture) advance(d time.Duration) {
	t := f.clock().Add(d)
	f.now.Store(&t)
}

// storedCount counts rows in the registry file. The registry exposes no count,
// so the test reads the file directly; production code uses cfg.Count.
func (f *fixture) storedCount(t *testing.T) int {
	t.Helper()
	db, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM oauth_clients`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func newFixture(t *testing.T, mutate ...func(*Config)) *fixture {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "clients.db")
	reg, err := clientregistry.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reg.Close() })
	f := &fixture{reg: reg, path: path, now: &atomic.Pointer[time.Time]{}}
	start := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	f.now.Store(&start)
	cfg := Config{
		Registry: reg,
		Count: func(context.Context) (int, error) {
			db, err := sql.Open("sqlite", path)
			if err != nil {
				return 0, err
			}
			defer db.Close()
			var n int
			err = db.QueryRow(`SELECT count(*) FROM oauth_clients`).Scan(&n)
			return n, err
		},
		Now: f.clock,
		// Generous defaults keep unrelated tests clear of the limits.
		PerHostPerHour: 1000,
		GlobalPerHour:  1000,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

func post(h http.Handler, body string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.20:4000"
	for _, m := range mutate {
		m(r)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	return body["error"]
}

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func TestNewRequiresRegistryAndDefaultsCount(t *testing.T) {
	if _, err := New(Config{Count: func(context.Context) (int, error) { return 0, nil }}); err == nil {
		t.Fatal("missing registry accepted")
	}
	f := newFixture(t)
	if _, err := New(Config{Registry: f.reg}); err != nil {
		t.Fatalf("registry count default rejected: %v", err)
	}
	if _, err := New(Config{Registry: f.reg, Count: f.h.count, MaxClients: -1}); err == nil {
		t.Fatal("negative capacity accepted")
	}
}

func TestValidRegistrationIsStoredUnapproved(t *testing.T) {
	f := newFixture(t)
	body := `{"redirect_uris":["https://client.example/callback"],"client_name":"Test client"}`
	rec := post(f.h, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp registrationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !clientIDPattern.MatchString(resp.ClientID) {
		t.Fatalf("client ID %q is not 43 base64url characters", resp.ClientID)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Fatalf("auth method = %q, want none", resp.TokenEndpointAuthMethod)
	}
	if strings.Join(resp.GrantTypes, ",") != "authorization_code" || strings.Join(resp.ResponseTypes, ",") != "code" {
		t.Fatalf("defaults = %v / %v", resp.GrantTypes, resp.ResponseTypes)
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://client.example/callback" {
		t.Fatalf("redirect URIs = %v", resp.RedirectURIs)
	}
	if strings.Contains(rec.Body.String(), "client_secret") {
		t.Fatal("response includes a client secret")
	}
	stored, err := f.reg.Get(context.Background(), resp.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Approved {
		t.Fatal("registered client is approved; registration must grant nothing")
	}
	if stored.CreatedAt.Unix() != resp.ClientIDIssuedAt {
		t.Fatal("client_id_issued_at does not match the stored creation time")
	}
}

func TestRegistrationStaysUnapprovedAfterRestart(t *testing.T) {
	f := newFixture(t)
	rec := post(f.h, `{"redirect_uris":["http://127.0.0.1:8123/cb"]}`)
	var resp registrationResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if err := f.reg.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := clientregistry.Open(context.Background(), f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Get(context.Background(), resp.ClientID)
	if err != nil || got.Approved {
		t.Fatalf("after restart: %+v, %v", got, err)
	}
}

func TestClientIDsAreUniqueAndRandom(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxClients = 500 })
	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		rec := post(f.h, fmt.Sprintf(`{"redirect_uris":["https://c%d.example/cb"]}`, i),
			func(r *http.Request) { r.RemoteAddr = fmt.Sprintf("203.0.113.%d:1", i) })
		if rec.Code != http.StatusCreated {
			t.Fatalf("registration %d returned %d", i, rec.Code)
		}
		var resp registrationResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if seen[resp.ClientID] {
			t.Fatal("duplicate client ID issued")
		}
		seen[resp.ClientID] = true
	}
}

func TestInvalidRedirectURIsRejectedAndNotStored(t *testing.T) {
	f := newFixture(t)
	cases := map[string]string{
		"missing":          `{}`,
		"empty list":       `{"redirect_uris":[]}`,
		"empty entry":      `{"redirect_uris":[""]}`,
		"relative":         `{"redirect_uris":["/callback"]}`,
		"plain http":       `{"redirect_uris":["http://client.example/cb"]}`,
		"fragment":         `{"redirect_uris":["https://client.example/cb#x"]}`,
		"user info":        `{"redirect_uris":["https://u:p@client.example/cb"]}`,
		"javascript":       `{"redirect_uris":["javascript:alert('` + regSentinel + `')"]}`,
		"duplicates":       `{"redirect_uris":["https://c.example/cb","https://c.example/cb"]}`,
		"too many":         `{"redirect_uris":[` + strings.TrimSuffix(strings.Repeat(`"https://c.example/x",`, 17), ",") + `]}`,
		"non-string entry": `{"redirect_uris":[42]}`,
		"string not array": `{"redirect_uris":"https://c.example/cb"}`,
		"too long":         `{"redirect_uris":["https://c.example/` + strings.Repeat("a", 2100) + `"]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := post(f.h, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			code := errorCode(t, rec)
			if code != "invalid_redirect_uri" && code != "invalid_client_metadata" {
				t.Fatalf("error = %q", code)
			}
			if strings.Contains(rec.Body.String(), regSentinel) {
				t.Fatal("error response echoes the submitted URI")
			}
		})
	}
	if n := f.storedCount(t); n != 0 {
		t.Fatalf("%d clients stored from rejected requests", n)
	}
}

func TestUnsupportedMetadataRejected(t *testing.T) {
	f := newFixture(t)
	cases := map[string]string{
		"client secret basic": `{"redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`,
		"client secret post":  `{"redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
		"private key jwt":     `{"redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`,
		"auth method number":  `{"redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":3}`,
		"client credentials":  `{"redirect_uris":["https://c.example/cb"],"grant_types":["client_credentials"]}`,
		"implicit":            `{"redirect_uris":["https://c.example/cb"],"grant_types":["implicit"]}`,
		"password grant":      `{"redirect_uris":["https://c.example/cb"],"grant_types":["password"]}`,
		"refresh only":        `{"redirect_uris":["https://c.example/cb"],"grant_types":["refresh_token"]}`,
		"empty grants":        `{"redirect_uris":["https://c.example/cb"],"grant_types":[]}`,
		"duplicate grants":    `{"redirect_uris":["https://c.example/cb"],"grant_types":["authorization_code","authorization_code"]}`,
		"token response":      `{"redirect_uris":["https://c.example/cb"],"response_types":["token"]}`,
		"id token response":   `{"redirect_uris":["https://c.example/cb"],"response_types":["id_token"]}`,
		"code and token":      `{"redirect_uris":["https://c.example/cb"],"response_types":["code","token"]}`,
		"empty responses":     `{"redirect_uris":["https://c.example/cb"],"response_types":[]}`,
		"grant not array":     `{"redirect_uris":["https://c.example/cb"],"grant_types":"authorization_code"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := post(f.h, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec); code != "invalid_client_metadata" {
				t.Fatalf("error = %q", code)
			}
		})
	}
	if n := f.storedCount(t); n != 0 {
		t.Fatalf("%d clients stored from unsupported requests", n)
	}
}

func TestSupportedGrantCombinationsAccepted(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxClients = 100 })
	cases := []string{
		`{"redirect_uris":["https://c.example/cb"],"grant_types":["authorization_code"]}`,
		`{"redirect_uris":["https://c.example/cb"],"grant_types":["authorization_code","refresh_token"]}`,
		`{"redirect_uris":["https://c.example/cb"],"grant_types":["refresh_token","authorization_code"],"response_types":["code"]}`,
		`{"redirect_uris":["https://c.example/cb"],"token_endpoint_auth_method":"none"}`,
		`{"redirect_uris":["https://c.example/cb"],"scope":"olist:read","software_id":"x","client_uri":"https://c.example"}`,
	}
	for _, body := range cases {
		if rec := post(f.h, body); rec.Code != http.StatusCreated {
			t.Fatalf("%s returned %d: %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestRefreshGrantEchoedButNotPersisted(t *testing.T) {
	f := newFixture(t)
	rec := post(f.h, `{"redirect_uris":["https://c.example/cb"],"grant_types":["authorization_code","refresh_token"]}`)
	var resp registrationResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if strings.Join(resp.GrantTypes, ",") != "authorization_code,refresh_token" {
		t.Fatalf("grant types echoed = %v", resp.GrantTypes)
	}
	// The registry has no grant column. The stored row cannot show the requested
	// refresh grant, which is a gap for the provider; the test records it.
	stored, err := f.reg.Get(context.Background(), resp.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != resp.ClientID {
		t.Fatal("stored ID mismatch")
	}
}

func TestMethodRestrictions(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		r := httptest.NewRequest(method, "/oauth/register", strings.NewReader(`{"redirect_uris":["https://c.example/cb"]}`))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, r)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Fatalf("%s returned %d with Allow %q", method, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if n := f.storedCount(t); n != 0 {
		t.Fatalf("%d clients stored by non-POST requests", n)
	}
}

func TestContentTypeRequired(t *testing.T) {
	f := newFixture(t)
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/jsonx"} {
		rec := post(f.h, `{"redirect_uris":["https://c.example/cb"]}`, func(r *http.Request) {
			if ct == "" {
				r.Header.Del("Content-Type")
			} else {
				r.Header.Set("Content-Type", ct)
			}
		})
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("content type %q returned %d", ct, rec.Code)
		}
	}
	rec := post(f.h, `{"redirect_uris":["https://c.example/cb"]}`, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("json with charset returned %d", rec.Code)
	}
}

func TestMalformedBodiesRejected(t *testing.T) {
	f := newFixture(t)
	bodies := []string{
		``,
		`{`,
		`not json`,
		`[]`,
		`"string"`,
		`{"redirect_uris":["https://c.example/cb"]} {"x":1}`,
		`{"redirect_uris":["https://c.example/cb"]}garbage`,
	}
	for _, body := range bodies {
		rec := post(f.h, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q returned %d", body, rec.Code)
		}
	}
	if n := f.storedCount(t); n != 0 {
		t.Fatalf("%d clients stored from malformed bodies", n)
	}
}

func TestUnknownMetadataIgnored(t *testing.T) {
	f := newFixture(t)
	rec := post(f.h, `{"redirect_uris":["https://c.example/cb"],"unknown_member":{"nested":true},"contacts":["a@b.example"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("unknown members rejected: %d", rec.Code)
	}
}

func TestBodySizeLimit(t *testing.T) {
	f := newFixture(t)
	big := `{"redirect_uris":["https://c.example/cb"],"client_name":"` + strings.Repeat("x", 20<<10) + `"}`
	rec := post(f.h, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body returned %d, want 413", rec.Code)
	}
	if n := f.storedCount(t); n != 0 {
		t.Fatal("oversized body stored a client")
	}
}

func TestPerHostRateLimit(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.PerHostPerHour = 3; c.GlobalPerHour = 100 })
	body := `{"redirect_uris":["https://c.example/cb"]}`
	for i := 0; i < 3; i++ {
		if rec := post(f.h, body); rec.Code != http.StatusCreated {
			t.Fatalf("attempt %d returned %d", i, rec.Code)
		}
	}
	rec := post(f.h, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fourth attempt returned %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 carries no Retry-After")
	}
	// Another host is not affected.
	other := post(f.h, body, func(r *http.Request) { r.RemoteAddr = "192.0.2.77:9" })
	if other.Code != http.StatusCreated {
		t.Fatalf("other host blocked: %d", other.Code)
	}
	// The window slides: an hour later the host may register again.
	f.advance(time.Hour + time.Second)
	if rec := post(f.h, body); rec.Code != http.StatusCreated {
		t.Fatalf("after the window, host still blocked: %d", rec.Code)
	}
}

func TestGlobalRateLimit(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.PerHostPerHour = 100; c.GlobalPerHour = 4; c.MaxClients = 100 })
	body := `{"redirect_uris":["https://c.example/cb"]}`
	for i := 0; i < 4; i++ {
		rec := post(f.h, body, func(r *http.Request) { r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1", i+1) })
		if rec.Code != http.StatusCreated {
			t.Fatalf("attempt %d returned %d", i, rec.Code)
		}
	}
	rec := post(f.h, body, func(r *http.Request) { r.RemoteAddr = "192.0.2.200:1" })
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("global limit did not block a fresh host: %d", rec.Code)
	}
}

func TestFailedAttemptsCountTowardRateLimit(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.PerHostPerHour = 2; c.GlobalPerHour = 100 })
	for i := 0; i < 2; i++ {
		if rec := post(f.h, `{"redirect_uris":["http://c.example/cb"]}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid registration returned %d", rec.Code)
		}
	}
	if rec := post(f.h, `{"redirect_uris":["https://c.example/cb"]}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("invalid attempts did not count: %d", rec.Code)
	}
}

func TestCapacityCapRefusesWithoutStoring(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxClients = 3 })
	body := `{"redirect_uris":["https://c.example/cb"]}`
	for i := 0; i < 3; i++ {
		if rec := post(f.h, body, func(r *http.Request) { r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1", i+1) }); rec.Code != http.StatusCreated {
			t.Fatalf("registration %d returned %d", i, rec.Code)
		}
	}
	rec := post(f.h, body, func(r *http.Request) { r.RemoteAddr = "192.0.2.50:1" })
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("over capacity returned %d, want 503", rec.Code)
	}
	if n := f.storedCount(t); n != 3 {
		t.Fatalf("stored = %d, want 3", n)
	}
}

func TestCountErrorFailsClosed(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.Count = func(context.Context) (int, error) { return 0, fmt.Errorf("count failed") }
	})
	rec := post(f.h, `{"redirect_uris":["https://c.example/cb"]}`)
	if rec.Code == http.StatusCreated {
		t.Fatal("registration succeeded without a capacity count")
	}
	if n := f.storedCount(t); n != 0 {
		t.Fatal("client stored without a capacity check")
	}
}

// Concurrent registrations race for the last slots. The mutex keeps the cap exact.
func TestConcurrentRegistrationsRespectCapacity(t *testing.T) {
	const cap = 10
	f := newFixture(t, func(c *Config) { c.MaxClients = cap; c.PerHostPerHour = 1000; c.GlobalPerHour = 1000 })
	var created, refused atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := post(f.h, fmt.Sprintf(`{"redirect_uris":["https://c%d.example/cb"]}`, i),
				func(r *http.Request) { r.RemoteAddr = fmt.Sprintf("198.18.0.%d:1", i+1) })
			switch rec.Code {
			case http.StatusCreated:
				created.Add(1)
			case http.StatusServiceUnavailable:
				refused.Add(1)
			default:
				t.Errorf("unexpected status %d", rec.Code)
			}
		}(i)
	}
	wg.Wait()
	if created.Load() != cap {
		t.Fatalf("created %d clients under concurrency, want exactly %d", created.Load(), cap)
	}
	if n := f.storedCount(t); n != cap {
		t.Fatalf("stored = %d, want %d", n, cap)
	}
}

func TestErrorsDoNotLeakInputOrInternals(t *testing.T) {
	f := newFixture(t)
	payloads := []string{
		`{"redirect_uris":["javascript:` + regSentinel + `"]}`,
		`{"token_endpoint_auth_method":"` + regSentinel + `","redirect_uris":["https://c.example/cb"]}`,
		`{"grant_types":["` + regSentinel + `"],"redirect_uris":["https://c.example/cb"]}`,
		`{"redirect_uris":["https://c.example/cb"]` + regSentinel,
	}
	for _, body := range payloads {
		rec := post(f.h, body)
		if strings.Contains(rec.Body.String(), regSentinel) {
			t.Fatal("error response echoes client input")
		}
		if strings.Contains(strings.ToLower(rec.Body.String()), "sqlite") || strings.Contains(rec.Body.String(), "oauth_clients") {
			t.Fatal("error response exposes storage details")
		}
	}
}

func TestSuccessResponseHasNoSecretsOrTokens(t *testing.T) {
	f := newFixture(t)
	rec := post(f.h, `{"redirect_uris":["https://c.example/cb"]}`)
	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"client_secret", "access_token", "refresh_token", "registration_access_token"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response contains %s", forbidden)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("registration response is cacheable")
	}
}

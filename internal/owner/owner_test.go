package owner

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// Passwords and hashes are only compared or used to build requests. Failure
// messages never print them.
const (
	testPassword = "correct horse battery staple 2026"
	testOrigin   = "https://olist.example.com"
	testRemote   = "203.0.113.10:5555"
)

// makeHash builds an argon2id PHC string for password with the given costs.
func makeHash(password string, m uint32, tc uint32, p uint8) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, tc, m, p, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, tc, p,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

var testHash = mustHash(testPassword)

func mustHash(password string) string {
	h, err := makeHash(password, minMemoryKiB, 1, 1)
	if err != nil {
		panic(err)
	}
	return h
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestManager(t *testing.T, mutate ...func(*Config)) (*Manager, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)}
	cfg := Config{PasswordHash: testHash, PublicOrigin: testOrigin, Now: clock.now}
	for _, f := range mutate {
		f(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m, clock
}

func loginRequest(password string) *http.Request {
	form := url.Values{"password": {password}}
	r := httptest.NewRequest(http.MethodPost, testOrigin+"/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", testOrigin)
	r.RemoteAddr = testRemote
	return r
}

func doLogin(m *Manager, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	m.Login(rec, r)
	return rec
}

func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			return c
		}
	}
	t.Fatal("response set no session cookie")
	return nil
}

func login(t *testing.T, m *Manager) *http.Cookie {
	t.Helper()
	rec := doLogin(m, loginRequest(testPassword))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login returned %d, want 303", rec.Code)
	}
	return sessionCookieFrom(t, rec)
}

// stateRequest builds a request carrying the session cookie and an origin.
func stateRequest(method string, c *http.Cookie) *http.Request {
	r := httptest.NewRequest(method, testOrigin+"/admin/action", strings.NewReader(""))
	r.Header.Set("Origin", testOrigin)
	r.RemoteAddr = testRemote
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func csrfFor(t *testing.T, m *Manager, c *http.Cookie) string {
	t.Helper()
	r := stateRequest(http.MethodGet, c)
	token, err := m.CSRFToken(r)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestNewRejectsMalformedHashes(t *testing.T) {
	valid := testHash
	parts := strings.Split(valid, "$") // "", "argon2id", "v=19", params, salt, key
	bad := map[string]string{
		"empty":                "",
		"plaintext":            testPassword,
		"argon2i":              strings.Replace(valid, "$argon2id$", "$argon2i$", 1),
		"argon2d":              strings.Replace(valid, "$argon2id$", "$argon2d$", 1),
		"wrong version":        strings.Replace(valid, "v=19", "v=16", 1),
		"no version":           parts[0] + "$argon2id$" + strings.Join(parts[3:], "$"),
		"memory too low":       makeRaw(parts, "m=4096,t=1,p=1"),
		"memory too high":      makeRaw(parts, "m=1048576,t=1,p=1"),
		"time zero":            makeRaw(parts, "m=8192,t=0,p=1"),
		"time too high":        makeRaw(parts, "m=8192,t=11,p=1"),
		"parallelism zero":     makeRaw(parts, "m=8192,t=1,p=0"),
		"parallelism too high": makeRaw(parts, "m=8192,t=1,p=9"),
		"params reordered":     makeRaw(parts, "t=1,m=8192,p=1"),
		"params missing":       makeRaw(parts, "m=8192,t=1"),
		"params non-numeric":   makeRaw(parts, "m=8192,t=x,p=1"),
		"params negative":      makeRaw(parts, "m=-8192,t=1,p=1"),
		"salt too short":       makeRaw(parts, "m=8192,t=1,p=1", base64.RawStdEncoding.EncodeToString(make([]byte, 8)), parts[5]),
		"key too short":        makeRaw(parts, "m=8192,t=1,p=1", parts[4], base64.RawStdEncoding.EncodeToString(make([]byte, 8))),
		"padded base64":        makeRaw(parts, "m=8192,t=1,p=1", parts[4], parts[5]+"=="),
		"bad base64":           makeRaw(parts, "m=8192,t=1,p=1", parts[4], "!!!notbase64!!!"),
		"extra segment":        valid + "$extra",
		"missing key":          strings.TrimSuffix(valid, "$"+parts[5]),
	}
	for name, h := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{PasswordHash: h, PublicOrigin: testOrigin})
			if err == nil {
				t.Fatal("malformed hash accepted")
			}
			if strings.Contains(err.Error(), testPassword) {
				t.Fatal("error message leaks the configured password")
			}
		})
	}
	if _, err := New(Config{PasswordHash: valid, PublicOrigin: testOrigin}); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
}

// makeRaw rebuilds a PHC string from parts with the given params and optional
// salt and key replacements.
func makeRaw(parts []string, params string, salt ...string) string {
	s, k := parts[4], parts[5]
	if len(salt) == 2 {
		s, k = salt[0], salt[1]
	}
	return "$argon2id$v=19$" + params + "$" + s + "$" + k
}

func TestNewValidatesOriginAndPolicy(t *testing.T) {
	origins := map[string]bool{
		"https://olist.example.com":      true,
		"https://olist.example.com/":     true,
		"HTTPS://OLIST.example.com":      true,
		"http://olist.example.com":       false,
		"https://olist.example.com/path": false,
		"https://olist.example.com?x=1":  false,
		"https://user@olist.example.com": false,
		"https://":                       false,
		"":                               false,
	}
	for origin, ok := range origins {
		_, err := New(Config{PasswordHash: testHash, PublicOrigin: origin})
		if ok && err != nil {
			t.Fatalf("origin %q rejected: %v", origin, err)
		}
		if !ok && err == nil {
			t.Fatalf("origin %q accepted", origin)
		}
	}
	bad := []Config{
		{PasswordHash: testHash, PublicOrigin: testOrigin, SessionTTL: 25 * time.Hour},
		{PasswordHash: testHash, PublicOrigin: testOrigin, SessionTTL: -time.Second},
		{PasswordHash: testHash, PublicOrigin: testOrigin, MaxSessions: -1},
		{PasswordHash: testHash, PublicOrigin: testOrigin, ClientFailureLimit: -1},
		{PasswordHash: testHash, PublicOrigin: testOrigin, Lockout: -time.Minute},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Fatalf("bad config %d accepted", i)
		}
	}
}

func TestLoginFailureIsGenericAndSetsNoCookie(t *testing.T) {
	m, _ := newTestManager(t)
	cases := map[string]*http.Request{
		"wrong password": loginRequest("not the password"),
		"empty password": loginRequest(""),
		"no field": func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, testOrigin+"/admin/login", strings.NewReader("other=1"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", testOrigin)
			r.RemoteAddr = testRemote
			return r
		}(),
		"overlong password": loginRequest(strings.Repeat("p", 2000)),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			rec := doLogin(m, r)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("returned %d, want 401", rec.Code)
			}
			if rec.Body.String() != "invalid credentials\n" {
				t.Fatalf("body = %q; failures must be generic", rec.Body.String())
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Fatal("failed login set a cookie")
			}
		})
	}
}

func TestLoginSuccessCookieFlags(t *testing.T) {
	m, _ := newTestManager(t)
	rec := doLogin(m, loginRequest(testPassword))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/" {
		t.Fatalf("login returned %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionCookieFrom(t, rec)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags: Secure=%v HttpOnly=%v SameSite=%v", c.Secure, c.HttpOnly, c.SameSite)
	}
	if c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie scope: Path=%q Domain=%q; __Host- requires Path=/ and no Domain", c.Path, c.Domain)
	}
	if c.MaxAge != int((8 * time.Hour).Seconds()) {
		t.Fatalf("MaxAge = %d, want 8h", c.MaxAge)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatal("cookie name lacks the __Host- prefix")
	}
	raw := rec.Header().Get("Set-Cookie")
	if !strings.Contains(raw, "Secure") || !strings.Contains(raw, "HttpOnly") || !strings.Contains(raw, "SameSite=Lax") {
		t.Fatalf("Set-Cookie attributes incomplete: %q", raw)
	}
	if len(c.Value) != 43 {
		t.Fatalf("session ID length = %d, want 43 (32 random bytes)", len(c.Value))
	}
}

func TestSessionIDsAreUniqueAndNotInResponses(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.MaxSessions = 100 })
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		rec := doLogin(m, loginRequest(testPassword))
		c := sessionCookieFrom(t, rec)
		if seen[c.Value] {
			t.Fatal("session ID repeated")
		}
		seen[c.Value] = true
		if strings.Contains(rec.Body.String(), c.Value) {
			t.Fatal("session ID appears in the response body")
		}
	}
}

func TestLoginRejectsCrossSiteAndMissingOrigin(t *testing.T) {
	m, _ := newTestManager(t)
	crossOrigin := loginRequest(testPassword)
	crossOrigin.Header.Set("Origin", "https://attacker.example")
	noHeaders := loginRequest(testPassword)
	noHeaders.Header.Del("Origin")
	crossFetch := loginRequest(testPassword)
	crossFetch.Header.Del("Origin")
	crossFetch.Header.Set("Sec-Fetch-Site", "cross-site")
	for name, r := range map[string]*http.Request{
		"foreign origin": crossOrigin, "no origin or fetch metadata": noHeaders, "cross-site fetch": crossFetch,
	} {
		t.Run(name, func(t *testing.T) {
			rec := doLogin(m, r)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("returned %d, want 403", rec.Code)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Fatal("refused login set a cookie")
			}
		})
	}
	sameSite := loginRequest(testPassword)
	sameSite.Header.Del("Origin")
	sameSite.Header.Set("Sec-Fetch-Site", "same-origin")
	if rec := doLogin(m, sameSite); rec.Code != http.StatusSeeOther {
		t.Fatalf("same-origin fetch metadata refused: %d", rec.Code)
	}
}

func TestLoginMethodAndBodyLimits(t *testing.T) {
	m, _ := newTestManager(t)
	get := httptest.NewRequest(http.MethodGet, testOrigin+"/admin/login?password="+url.QueryEscape(testPassword), nil)
	get.Header.Set("Origin", testOrigin)
	if rec := doLogin(m, get); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET login returned %d, want 405", rec.Code)
	}
	big := httptest.NewRequest(http.MethodPost, testOrigin+"/admin/login",
		strings.NewReader("password="+testPassword+"&pad="+strings.Repeat("x", 10000)))
	big.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	big.Header.Set("Origin", testOrigin)
	big.RemoteAddr = testRemote
	rec := doLogin(m, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized login returned %d, want 413", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("oversized login set a cookie")
	}
}

func TestOwnerAcceptsValidSessionAndExpires(t *testing.T) {
	m, clock := newTestManager(t)
	c := login(t, m)
	r := stateRequest(http.MethodGet, c)
	if id, err := m.Owner(r); err != nil || id != "owner" {
		t.Fatalf("valid session rejected: %q, %v", id, err)
	}
	clock.advance(8*time.Hour - time.Second)
	if _, err := m.Owner(r); err != nil {
		t.Fatalf("session expired early: %v", err)
	}
	clock.advance(2 * time.Second)
	if _, err := m.Owner(r); err != ErrUnauthenticated {
		t.Fatalf("expired session accepted: %v", err)
	}
}

func TestMalformedAndUnknownCookiesRejected(t *testing.T) {
	m, _ := newTestManager(t)
	login(t, m)
	cookies := []*http.Cookie{
		{Name: CookieName, Value: ""},
		{Name: CookieName, Value: "short"},
		{Name: CookieName, Value: strings.Repeat("!", 43)},
		{Name: CookieName, Value: strings.Repeat("A", 43)},
		{Name: "olist_owner", Value: strings.Repeat("A", 43)},
	}
	for _, c := range cookies {
		if _, err := m.Owner(stateRequest(http.MethodGet, c)); err == nil {
			t.Fatalf("cookie %q accepted", c.Name)
		}
	}
	if _, err := m.Owner(stateRequest(http.MethodGet, nil)); err == nil {
		t.Fatal("request without a cookie accepted")
	}
}

func TestLogoutEndsSessionAndExpiresCookie(t *testing.T) {
	m, _ := newTestManager(t)
	c := login(t, m)
	token := csrfFor(t, m, c)

	r := stateRequest(http.MethodPost, c)
	r.Header.Set(CSRFHeader, token)
	rec := httptest.NewRecorder()
	m.Logout(rec, r)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d, want 303", rec.Code)
	}
	cleared := sessionCookieFrom(t, rec)
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Fatalf("logout did not expire the cookie: MaxAge=%d", cleared.MaxAge)
	}
	if _, err := m.Owner(stateRequest(http.MethodGet, c)); err == nil {
		t.Fatal("session still valid after logout")
	}
}

func TestLogoutRequiresSessionAndCSRF(t *testing.T) {
	m, _ := newTestManager(t)
	c := login(t, m)

	noCSRF := stateRequest(http.MethodPost, c)
	rec := httptest.NewRecorder()
	m.Logout(rec, noCSRF)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout without CSRF returned %d, want 401", rec.Code)
	}
	if _, err := m.Owner(stateRequest(http.MethodGet, c)); err != nil {
		t.Fatal("failed logout ended the session")
	}

	noSession := stateRequest(http.MethodPost, nil)
	rec = httptest.NewRecorder()
	m.Logout(rec, noSession)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout without session returned %d, want 401", rec.Code)
	}
}

func TestCrossSitePostRejectedEvenWithValidSession(t *testing.T) {
	m, _ := newTestManager(t)
	c := login(t, m)
	token := csrfFor(t, m, c)

	foreign := stateRequest(http.MethodPost, c)
	foreign.Header.Set("Origin", "https://attacker.example")
	foreign.Header.Set(CSRFHeader, token)
	if _, err := m.Owner(foreign); err != ErrOrigin {
		t.Fatalf("foreign origin with valid token: %v, want ErrOrigin", err)
	}

	noOrigin := stateRequest(http.MethodPost, c)
	noOrigin.Header.Del("Origin")
	noOrigin.Header.Set("Sec-Fetch-Site", "cross-site")
	noOrigin.Header.Set(CSRFHeader, token)
	if _, err := m.Owner(noOrigin); err != ErrOrigin {
		t.Fatalf("cross-site fetch with valid token: %v, want ErrOrigin", err)
	}

	neither := stateRequest(http.MethodPost, c)
	neither.Header.Del("Origin")
	neither.Header.Set(CSRFHeader, token)
	if _, err := m.Owner(neither); err != ErrOrigin {
		t.Fatalf("request with no origin metadata: %v, want ErrOrigin", err)
	}
}

func TestStateChangeRequiresCSRFToken(t *testing.T) {
	m, _ := newTestManager(t)
	c := login(t, m)
	token := csrfFor(t, m, c)

	none := stateRequest(http.MethodPost, c)
	if _, err := m.Owner(none); err != ErrCSRF {
		t.Fatalf("POST without token: %v, want ErrCSRF", err)
	}
	wrong := stateRequest(http.MethodPost, c)
	wrong.Header.Set(CSRFHeader, token+"x")
	if _, err := m.Owner(wrong); err != ErrCSRF {
		t.Fatalf("POST with wrong token: %v, want ErrCSRF", err)
	}
	good := stateRequest(http.MethodPost, c)
	good.Header.Set(CSRFHeader, token)
	if id, err := m.Owner(good); err != nil || id != "owner" {
		t.Fatalf("POST with header token rejected: %v", err)
	}
	// GET and HEAD need no token.
	if _, err := m.Owner(stateRequest(http.MethodGet, c)); err != nil {
		t.Fatalf("GET without token rejected: %v", err)
	}
}

func TestFormCSRFFieldAcceptedAndBodyRestored(t *testing.T) {
	m, _ := newTestManager(t)
	c := login(t, m)
	token := csrfFor(t, m, c)

	body := url.Values{"csrf_token": {token}, "account": {"account-a"}}.Encode()
	r := httptest.NewRequest(http.MethodPost, testOrigin+"/admin/connect", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", testOrigin)
	r.RemoteAddr = testRemote
	r.AddCookie(c)
	if _, err := m.Owner(r); err != nil {
		t.Fatalf("form token rejected: %v", err)
	}
	// The handler that runs next must still see the original form fields.
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if r.PostForm.Get("account") != "account-a" {
		t.Fatal("request body was consumed by the CSRF check")
	}
}

func TestCSRFBoundToSession(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.MaxSessions = 10 })
	cookieA := login(t, m)
	cookieB := login(t, m)
	tokenA := csrfFor(t, m, cookieA)
	tokenB := csrfFor(t, m, cookieB)
	if tokenA == tokenB {
		t.Fatal("two sessions share a CSRF token")
	}

	swapped := stateRequest(http.MethodPost, cookieB)
	swapped.Header.Set(CSRFHeader, tokenA)
	if _, err := m.Owner(swapped); err != ErrCSRF {
		t.Fatalf("session B accepted session A's token: %v", err)
	}
	own := stateRequest(http.MethodPost, cookieB)
	own.Header.Set(CSRFHeader, tokenB)
	if _, err := m.Owner(own); err != nil {
		t.Fatalf("session B with its own token rejected: %v", err)
	}
}

func TestCSRFTokenReplayAfterLogoutRejected(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.MaxSessions = 10 })
	oldCookie := login(t, m)
	oldToken := csrfFor(t, m, oldCookie)

	// Logout, then log in again. The stolen token must not work with the new session.
	logout := stateRequest(http.MethodPost, oldCookie)
	logout.Header.Set(CSRFHeader, oldToken)
	m.Logout(httptest.NewRecorder(), logout)

	newCookie := login(t, m)
	replay := stateRequest(http.MethodPost, newCookie)
	replay.Header.Set(CSRFHeader, oldToken)
	if _, err := m.Owner(replay); err != ErrCSRF {
		t.Fatalf("replayed token accepted in a new session: %v", err)
	}
	// Replaying the old cookie with its old token is refused too.
	stale := stateRequest(http.MethodPost, oldCookie)
	stale.Header.Set(CSRFHeader, oldToken)
	if _, err := m.Owner(stale); err == nil {
		t.Fatal("old session accepted after logout")
	}
}

func TestLoginRotatesSessionID(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) { c.MaxSessions = 10 })
	before := login(t, m)
	r := loginRequest(testPassword)
	r.AddCookie(before)
	rec := doLogin(m, r)
	after := sessionCookieFrom(t, rec)
	if after.Value == before.Value {
		t.Fatal("login reused the existing session ID")
	}
	if _, err := m.Owner(stateRequest(http.MethodGet, before)); err == nil {
		t.Fatal("pre-login session still valid after login (session fixation)")
	}
}

func TestCSRFTokenRequiresSession(t *testing.T) {
	m, _ := newTestManager(t)
	if _, err := m.CSRFToken(stateRequest(http.MethodGet, nil)); err != ErrUnauthenticated {
		t.Fatalf("CSRFToken without session: %v", err)
	}
}

func TestClientThrottleLocksThenReleases(t *testing.T) {
	m, clock := newTestManager(t, func(c *Config) {
		c.ClientFailureLimit = 5
		c.GlobalFailureLimit = 1000
		c.Lockout = 15 * time.Minute
	})
	for i := 0; i < 5; i++ {
		if rec := doLogin(m, loginRequest("wrong")); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d", i, rec.Code)
		}
	}
	// Even the correct password is refused while the client is locked.
	rec := doLogin(m, loginRequest(testPassword))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked client returned %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "900" {
		t.Fatalf("Retry-After = %q, want 900", rec.Header().Get("Retry-After"))
	}
	// Another client is not affected.
	other := loginRequest(testPassword)
	other.RemoteAddr = "198.51.100.7:4000"
	if rec := doLogin(m, other); rec.Code != http.StatusSeeOther {
		t.Fatalf("other client blocked: %d", rec.Code)
	}
	clock.advance(15*time.Minute + time.Second)
	if rec := doLogin(m, loginRequest(testPassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("client still locked after lockout: %d", rec.Code)
	}
}

func TestGlobalThrottleBlocksEveryClient(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) {
		c.ClientFailureLimit = 100
		c.GlobalFailureLimit = 4
	})
	for i := 0; i < 4; i++ {
		r := loginRequest("wrong")
		r.RemoteAddr = fmt.Sprintf("203.0.113.%d:1000", 50+i)
		doLogin(m, r)
	}
	fresh := loginRequest(testPassword)
	fresh.RemoteAddr = "198.51.100.99:1000"
	if rec := doLogin(m, fresh); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("global lockout did not block a fresh client: %d", rec.Code)
	}
}

func TestSuccessClearsOnlyClientFailures(t *testing.T) {
	m, _ := newTestManager(t, func(c *Config) {
		c.ClientFailureLimit = 5
		c.GlobalFailureLimit = 1000
	})
	for i := 0; i < 4; i++ {
		doLogin(m, loginRequest("wrong"))
	}
	if rec := doLogin(m, loginRequest(testPassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("correct password refused after four failures: %d", rec.Code)
	}
	for i := 0; i < 4; i++ {
		doLogin(m, loginRequest("wrong"))
	}
	if rec := doLogin(m, loginRequest(testPassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("success did not reset the client counter: %d", rec.Code)
	}
}

func TestFailuresOutsideWindowDoNotAccumulate(t *testing.T) {
	m, clock := newTestManager(t, func(c *Config) {
		c.ClientFailureLimit = 5
		c.GlobalFailureLimit = 1000
		c.FailureWindow = 15 * time.Minute
	})
	for i := 0; i < 4; i++ {
		doLogin(m, loginRequest("wrong"))
	}
	clock.advance(16 * time.Minute)
	for i := 0; i < 4; i++ {
		doLogin(m, loginRequest("wrong"))
	}
	if rec := doLogin(m, loginRequest(testPassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("old failures counted after the window: %d", rec.Code)
	}
}

func TestSessionCapRefusesNewSessions(t *testing.T) {
	m, clock := newTestManager(t, func(c *Config) { c.MaxSessions = 2 })
	login(t, m)
	login(t, m)
	rec := doLogin(m, loginRequest(testPassword))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("third session returned %d, want 503", rec.Code)
	}
	// Once the earlier sessions expire, new logins succeed again.
	clock.advance(9 * time.Hour)
	if rec := doLogin(m, loginRequest(testPassword)); rec.Code != http.StatusSeeOther {
		t.Fatalf("login after expiry returned %d", rec.Code)
	}
}

func TestResponsesNeverContainSecrets(t *testing.T) {
	m, _ := newTestManager(t)
	var bodies []string
	record := func(rec *httptest.ResponseRecorder) {
		// Set-Cookie carries the session ID by design, so only the password and
		// hash are checked there.
		bodies = append(bodies, rec.Body.String(), rec.Header().Get("Location"))
	}
	record(doLogin(m, loginRequest("wrong")))
	ok := doLogin(m, loginRequest(testPassword))
	record(ok)
	c := sessionCookieFrom(t, ok)
	badOrigin := loginRequest(testPassword)
	badOrigin.Header.Set("Origin", "https://attacker.example")
	record(doLogin(m, badOrigin))
	logout := stateRequest(http.MethodPost, c)
	logout.Header.Set(CSRFHeader, "wrong")
	out := httptest.NewRecorder()
	m.Logout(out, logout)
	record(out)

	secrets := []string{testPassword, testHash, c.Value}
	for _, body := range bodies {
		for _, s := range secrets {
			if s != "" && strings.Contains(body, s) {
				t.Fatal("response leaks the password, hash or session ID")
			}
		}
	}
}

func TestFullFlowLoginActionLogout(t *testing.T) {
	m, _ := newTestManager(t)
	c := login(t, m)
	token := csrfFor(t, m, c)

	action := stateRequest(http.MethodPost, c)
	action.Header.Set(CSRFHeader, token)
	if id, err := m.Owner(action); err != nil || id != "owner" {
		t.Fatalf("authorized action failed: %v", err)
	}
	out := httptest.NewRecorder()
	logout := stateRequest(http.MethodPost, c)
	logout.Header.Set(CSRFHeader, token)
	m.Logout(out, logout)
	if out.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d", out.Code)
	}
	if _, err := m.Owner(stateRequest(http.MethodGet, c)); err == nil {
		t.Fatal("session survived logout")
	}
}

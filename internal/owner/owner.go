// Package owner authenticates the single administrator of the Olist MCP. It
// checks a configured Argon2id password hash, issues an opaque server-side
// session cookie, and protects state-changing requests with a session-bound
// CSRF token and an exact origin check. It mounts no handlers itself; the
// caller wires Login, Logout and Owner into internal/admin.
//
// Sessions and the throttle live in memory. A restart signs the owner out and
// clears the failure counters.
package owner

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// CookieName uses the __Host- prefix, so browsers require Secure, Path=/
	// and no Domain attribute.
	CookieName = "__Host-olist_owner"
	// CSRFHeader is the header accepted for the CSRF token. The form field
	// csrf_token is accepted as well.
	CSRFHeader = "X-CSRF-Token"

	defaultSessionTTL    = 8 * time.Hour
	maxSessionTTL        = 24 * time.Hour
	defaultMaxSessions   = 64
	defaultMaxBody       = 4096
	maxPasswordBytes     = 1024
	sessionIDBytes       = 32
	csrfTokenBytes       = 32
	defaultClientLimit   = 5
	defaultGlobalLimit   = 50
	defaultFailureWindow = 15 * time.Minute
	defaultLockout       = 15 * time.Minute
	ownerID              = "owner"
)

var (
	ErrUnauthenticated = errors.New("owner session required")
	ErrCSRF            = errors.New("CSRF check failed")
	ErrOrigin          = errors.New("origin not allowed")
)

// Config holds the owner policy. Zero values take the defaults shown.
type Config struct {
	// PasswordHash is an argon2id PHC string. Required.
	PasswordHash string
	// PublicOrigin is the exact origin, for example https://olist.example.com.
	// Required. Only https is accepted.
	PublicOrigin string
	// SessionTTL is the absolute session lifetime. Default 8h, maximum 24h.
	SessionTTL time.Duration
	// MaxSessions caps live sessions. Default 64.
	MaxSessions int
	// MaxBodyBytes limits request bodies read for login and CSRF. Default 4096.
	MaxBodyBytes int64
	// ClientFailureLimit is failed logins per client before lockout. Default 5.
	ClientFailureLimit int
	// GlobalFailureLimit is failed logins overall before lockout. Default 50.
	GlobalFailureLimit int
	// FailureWindow is the period in which failures are counted. Default 15m.
	FailureWindow time.Duration
	// Lockout is how long logins are refused after a limit is hit. Default 15m.
	Lockout time.Duration
	// Now supplies the clock. Default time.Now.
	Now func() time.Time
}

type session struct {
	csrf    []byte
	expires time.Time
}

// Manager holds sessions and enforces the owner policy. It is safe for
// concurrent use.
type Manager struct {
	hash        argonHash
	origin      string
	ttl         time.Duration
	maxSessions int
	maxBody     int64
	now         func() time.Time
	throttle    *throttle
	loginMu     sync.Mutex // serialize expensive verification and throttle decisions

	mu       sync.Mutex
	sessions map[string]*session // keyed by SHA-256 of the session ID
}

// New validates cfg and returns a Manager. A malformed or out-of-bounds hash,
// a non-https origin, or an out-of-range TTL is rejected here.
func New(cfg Config) (*Manager, error) {
	h, err := parseArgon2idHash(cfg.PasswordHash)
	if err != nil {
		return nil, err
	}
	origin, err := normalizeOrigin(cfg.PublicOrigin)
	if err != nil {
		return nil, err
	}
	ttl := cfg.SessionTTL
	if ttl == 0 {
		ttl = defaultSessionTTL
	}
	if ttl <= 0 || ttl > maxSessionTTL {
		return nil, errors.New("session TTL must be positive and at most 24h")
	}
	maxSessions := cfg.MaxSessions
	if maxSessions == 0 {
		maxSessions = defaultMaxSessions
	}
	if maxSessions < 1 {
		return nil, errors.New("max sessions must be positive")
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody == 0 {
		maxBody = defaultMaxBody
	}
	if maxBody < 0 {
		return nil, errors.New("max body bytes must be positive")
	}
	clientLimit := cfg.ClientFailureLimit
	if clientLimit == 0 {
		clientLimit = defaultClientLimit
	}
	globalLimit := cfg.GlobalFailureLimit
	if globalLimit == 0 {
		globalLimit = defaultGlobalLimit
	}
	if clientLimit < 1 || globalLimit < 1 {
		return nil, errors.New("failure limits must be positive")
	}
	window := cfg.FailureWindow
	if window == 0 {
		window = defaultFailureWindow
	}
	lockout := cfg.Lockout
	if lockout == 0 {
		lockout = defaultLockout
	}
	if window <= 0 || lockout <= 0 {
		return nil, errors.New("failure window and lockout must be positive")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Manager{
		hash:        h,
		origin:      origin,
		ttl:         ttl,
		maxSessions: maxSessions,
		maxBody:     maxBody,
		now:         now,
		throttle:    newThrottle(clientLimit, globalLimit, window, lockout),
		sessions:    make(map[string]*session),
	}, nil
}

// Login verifies the password and starts a session. It accepts POST only, and
// it applies the origin check, the body limit and the throttle. Responses carry
// no detail about why a login failed.
func (m *Manager) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := m.checkOrigin(r); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	form, err := m.readForm(r)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	client := clientKey(r)
	m.loginMu.Lock()
	defer m.loginMu.Unlock()
	now := m.now()
	if ok, retry := m.throttle.allow(client, now); !ok {
		w.Header().Set("Retry-After", retryAfter(retry))
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	password := form.Get("password")
	if password == "" || len(password) > maxPasswordBytes || !m.hash.verify(password) {
		m.throttle.failure(client, now)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	m.throttle.success(client)

	id, err := m.newSession(r)
	if err != nil {
		http.Error(w, "cannot start session", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, cookie(id, m.ttl))
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// Logout ends the current session. It requires a valid session and CSRF token.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := m.Owner(r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, _ := sessionCookie(r)
	m.mu.Lock()
	delete(m.sessions, hashID(id))
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// Owner authenticates the request and returns the owner identity. It matches
// the signature internal/admin expects. For state-changing methods (anything
// except GET, HEAD and OPTIONS) it also requires the exact origin and the
// session's CSRF token.
func (m *Manager) Owner(r *http.Request) (string, error) {
	id, err := sessionCookie(r)
	if err != nil {
		return "", ErrUnauthenticated
	}
	s, err := m.lookup(id)
	if err != nil {
		return "", err
	}
	if !safeMethod(r.Method) {
		if err := m.checkOrigin(r); err != nil {
			return "", err
		}
		token, err := m.requestCSRF(r)
		if err != nil {
			return "", err
		}
		if subtle.ConstantTimeCompare([]byte(token), s.csrf) != 1 {
			return "", ErrCSRF
		}
	}
	return ownerID, nil
}

// CSRFToken returns the token for the current session, for embedding in forms.
// It requires a valid session.
func (m *Manager) CSRFToken(r *http.Request) (string, error) {
	id, err := sessionCookie(r)
	if err != nil {
		return "", ErrUnauthenticated
	}
	s, err := m.lookup(id)
	if err != nil {
		return "", err
	}
	return string(s.csrf), nil
}

// lookup returns the live session for id, or ErrUnauthenticated.
func (m *Manager) lookup(id string) (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hashID(id)]
	if !ok {
		return nil, ErrUnauthenticated
	}
	if !m.now().Before(s.expires) {
		delete(m.sessions, hashID(id))
		return nil, ErrUnauthenticated
	}
	return s, nil
}

// newSession creates a session, replacing any session the request already
// carried (so login rotates the ID). It returns the raw session ID for the cookie.
func (m *Manager) newSession(r *http.Request) (string, error) {
	id, err := randomToken(sessionIDBytes)
	if err != nil {
		return "", err
	}
	csrf, err := randomToken(csrfTokenBytes)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, err := sessionCookie(r); err == nil {
		delete(m.sessions, hashID(old))
	}
	now := m.now()
	if len(m.sessions) >= m.maxSessions {
		for k, s := range m.sessions {
			if !now.Before(s.expires) {
				delete(m.sessions, k)
			}
		}
		if len(m.sessions) >= m.maxSessions {
			return "", errors.New("session limit reached")
		}
	}
	m.sessions[hashID(id)] = &session{csrf: []byte(csrf), expires: now.Add(m.ttl)}
	return id, nil
}

// checkOrigin requires the request origin to match the configured origin
// exactly. Without an Origin header it requires Sec-Fetch-Site: same-origin.
// A request with neither is refused.
func (m *Manager) checkOrigin(r *http.Request) error {
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == m.origin {
			return nil
		}
		return ErrOrigin
	}
	if r.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return nil
	}
	return ErrOrigin
}

// requestCSRF returns the CSRF token from the header or the csrf_token form
// field. The body is read once, within the limit, and restored for later
// handlers.
func (m *Manager) requestCSRF(r *http.Request) (string, error) {
	if token := r.Header.Get(CSRFHeader); token != "" {
		return token, nil
	}
	form, err := m.readForm(r)
	if err != nil {
		return "", ErrCSRF
	}
	token := form.Get("csrf_token")
	if token == "" {
		return "", ErrCSRF
	}
	return token, nil
}

// readForm reads an application/x-www-form-urlencoded body within the size
// limit and restores it so the caller can read it again. Other content types
// yield no fields.
func (m *Manager) readForm(r *http.Request) (url.Values, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return url.Values{}, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, m.maxBody+1))
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > m.maxBody {
		return nil, errors.New("body too large")
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		return url.Values{}, nil
	}
	return url.ParseQuery(string(data))
}

func sessionCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || len(c.Value) != base64.RawURLEncoding.EncodedLen(sessionIDBytes) {
		return "", ErrUnauthenticated
	}
	if _, err := base64.RawURLEncoding.DecodeString(c.Value); err != nil {
		return "", ErrUnauthenticated
	}
	return c.Value, nil
}

func cookie(id string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("public origin must be an https origin with no path, query or fragment")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func hashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func retryAfter(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

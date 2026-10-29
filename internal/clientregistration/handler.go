// Package clientregistration serves OAuth 2.0 dynamic client registration
// (RFC 7591) for public MCP clients. A registered client is stored unapproved
// in internal/clientregistry and grants nothing. This package issues no tokens
// and approves no client.
package clientregistration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbot/olist-mcp/internal/clientregistry"
)

const (
	defaultMaxClients    = 200
	defaultMaxBodyBytes  = 8 << 10
	defaultPerHostPerHr  = 5
	defaultGlobalPerHr   = 100
	maxRedirectURIs      = 16
	maxRedirectURILength = 2048
	authMethodNone       = "none"
	grantAuthCode        = "authorization_code"
	grantRefresh         = "refresh_token"
	responseCode         = "code"
)

// Config controls registration. Registry is required.
type Config struct {
	Registry *clientregistry.Registry
	// Count optionally overrides the registry count, for testing.
	Count func(context.Context) (int, error)
	// MaxClients caps stored clients. Default 200.
	MaxClients int
	// MaxBodyBytes limits the request body. Default 8 KiB.
	MaxBodyBytes int64
	// PerHostPerHour limits registration attempts per client address. Default 5.
	PerHostPerHour int
	// GlobalPerHour limits registration attempts overall. Default 100.
	GlobalPerHour int
	// Now supplies the clock. Default time.Now.
	Now func() time.Time
}

// Handler serves POST registration. It is safe for concurrent use.
type Handler struct {
	reg        *clientregistry.Registry
	count      func(context.Context) (int, error)
	maxClients int
	maxBody    int64
	perHost    int
	global     int
	now        func() time.Time

	// mu serializes the capacity check with the insert, so concurrent requests
	// cannot exceed MaxClients. It also guards the attempt windows.
	mu       sync.Mutex
	attempts map[string][]time.Time
	overall  []time.Time
}

// New validates cfg and returns a Handler.
func New(cfg Config) (*Handler, error) {
	if cfg.Registry == nil {
		return nil, errors.New("client registry required")
	}
	if cfg.Count == nil {
		cfg.Count = cfg.Registry.Count
	}
	h := &Handler{
		reg:        cfg.Registry,
		count:      cfg.Count,
		maxClients: pick(cfg.MaxClients, defaultMaxClients),
		maxBody:    pick64(cfg.MaxBodyBytes, defaultMaxBodyBytes),
		perHost:    pick(cfg.PerHostPerHour, defaultPerHostPerHr),
		global:     pick(cfg.GlobalPerHour, defaultGlobalPerHr),
		now:        cfg.Now,
		attempts:   make(map[string][]time.Time),
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.maxClients < 1 || h.perHost < 1 || h.global < 1 || h.maxBody < 1 {
		return nil, errors.New("limits must be positive")
	}
	return h, nil
}

func pick(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func pick64(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}

// registrationRequest is the subset of RFC 7591 metadata this server accepts.
// Unknown members are ignored, as RFC 7591 permits.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// registrationResponse is the RFC 7591 client information response. It never
// includes a client secret, because only public clients are registered.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// ServeHTTP handles POST /oauth/register.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isJSON(r.Header.Get("Content-Type")) {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	host := clientHost(r)
	now := h.now()
	if ok, retry := h.admit(host, now); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		http.Error(w, "too many registrations", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "request body could not be read")
		return
	}
	var req registrationRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "request must be one JSON object")
		return
	}
	grants, responses, err := validateMetadata(&req)
	if err != nil {
		writeMetaError(w, err)
		return
	}
	client, err := h.register(r.Context(), req.RedirectURIs)
	if err != nil {
		var me *metaError
		if errors.As(err, &me) {
			writeMetaError(w, me)
			return
		}
		if errors.Is(err, errAtCapacity) {
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration capacity reached")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(registrationResponse{
		ClientID:                client.ID,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: authMethodNone,
		GrantTypes:              grants,
		ResponseTypes:           responses,
	})
}

var errAtCapacity = errors.New("registration capacity reached")

// register checks capacity and stores one unapproved client. The mutex covers
// the count and the insert, so concurrent requests cannot exceed the cap.
func (h *Handler) register(ctx context.Context, redirects []string) (clientregistry.Client, error) {
	if err := validateRedirects(redirects); err != nil {
		return clientregistry.Client{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := h.count(ctx)
	if err != nil {
		return clientregistry.Client{}, err
	}
	if n >= h.maxClients {
		return clientregistry.Client{}, errAtCapacity
	}
	for attempt := 0; attempt < 2; attempt++ {
		id, err := newClientID()
		if err != nil {
			return clientregistry.Client{}, err
		}
		client, err := h.reg.Create(ctx, id, redirects)
		if errors.Is(err, clientregistry.ErrDuplicate) {
			continue
		}
		return client, err
	}
	return clientregistry.Client{}, errors.New("could not allocate a client ID")
}

// admit records one attempt for host and reports whether it may proceed. The
// retry value is in seconds when refused.
func (h *Handler) admit(host string, now time.Time) (bool, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hour := now.Add(-time.Hour)
	h.overall = pruneAfter(h.overall, hour)
	h.attempts[host] = pruneAfter(h.attempts[host], hour)
	if len(h.overall) >= h.global {
		return false, retrySeconds(h.overall[0], now)
	}
	if len(h.attempts[host]) >= h.perHost {
		return false, retrySeconds(h.attempts[host][0], now)
	}
	h.overall = append(h.overall, now)
	h.attempts[host] = append(h.attempts[host], now)
	return true, 0
}

func pruneAfter(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

func retrySeconds(oldest, now time.Time) int {
	secs := int(oldest.Add(time.Hour).Sub(now).Seconds()) + 1
	if secs < 1 {
		secs = 1
	}
	return secs
}

type metaError struct {
	code string
	msg  string
}

func (e *metaError) Error() string { return e.msg }

func invalidMetadata(msg string) error {
	return &metaError{code: "invalid_client_metadata", msg: msg}
}

func writeMetaError(w http.ResponseWriter, err error) {
	var me *metaError
	if errors.As(err, &me) {
		writeError(w, http.StatusBadRequest, me.code, me.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
}

// validateMetadata checks the requested grant and response types and the auth
// method, and returns the normalized lists to echo back.
func validateMetadata(req *registrationRequest) ([]string, []string, error) {
	if req.TokenEndpointAuthMethod != nil && *req.TokenEndpointAuthMethod != authMethodNone {
		return nil, nil, invalidMetadata("only public clients are supported; token_endpoint_auth_method must be none")
	}
	grants := req.GrantTypes
	if grants == nil {
		grants = []string{grantAuthCode}
	}
	if len(grants) == 0 {
		return nil, nil, invalidMetadata("grant_types must not be empty")
	}
	seen := map[string]bool{}
	hasCode := false
	for _, g := range grants {
		if g != grantAuthCode && g != grantRefresh {
			return nil, nil, invalidMetadata("unsupported grant type")
		}
		if seen[g] {
			return nil, nil, invalidMetadata("duplicate grant type")
		}
		seen[g] = true
		if g == grantAuthCode {
			hasCode = true
		}
	}
	if !hasCode {
		return nil, nil, invalidMetadata("grant_types must include authorization_code")
	}
	responses := req.ResponseTypes
	if responses == nil {
		responses = []string{responseCode}
	}
	if len(responses) != 1 || responses[0] != responseCode {
		return nil, nil, invalidMetadata("only response_types [code] is supported")
	}
	return grants, responses, nil
}

// validateRedirects mirrors the clientregistry rules so a caller gets
// invalid_redirect_uri rather than a generic failure. The registry remains the
// authority: it re-checks on insert.
func validateRedirects(uris []string) error {
	bad := func(msg string) error { return &metaError{code: "invalid_redirect_uri", msg: msg} }
	if len(uris) == 0 {
		return bad("at least one redirect URI is required")
	}
	if len(uris) > maxRedirectURIs {
		return bad("too many redirect URIs")
	}
	seen := map[string]bool{}
	for _, raw := range uris {
		if raw == "" || len(raw) > maxRedirectURILength {
			return bad("redirect URI is empty or too long")
		}
		if seen[raw] {
			return bad("duplicate redirect URI")
		}
		seen[raw] = true
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil {
			return bad("redirect URI must be absolute, with no fragment or user information")
		}
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && isLoopback(u.Hostname()):
		default:
			return bad("redirect URI must use https, or http on a loopback host")
		}
	}
	return nil
}

func isLoopback(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// newClientID returns 256 random bits, unpadded base64url (43 characters).
func newClientID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

// clientHost keys rate limits on the peer address. Forwarded headers are not
// trusted, because the tunnel setup is not yet decided.
func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

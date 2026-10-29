package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Sentinels are checked with strings.Contains and never printed.
const protSentinel = "prot-sentinel-verifier-credential-9e1d"

const protPublic = "https://example.com"

// protVerifier returns the info or error chosen by the test, and counts calls.
type protVerifier struct {
	calls atomic.Int32
	info  *auth.TokenInfo
	err   error
}

func (v *protVerifier) verify(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	v.calls.Add(1)
	if token != "good-token" {
		return nil, v.err
	}
	return v.info, v.err
}

func protValid(scopes ...string) *auth.TokenInfo {
	return &auth.TokenInfo{Scopes: scopes, Expiration: time.Now().Add(time.Hour), UserID: "owner"}
}

func protHandler(t *testing.T, v *protVerifier) http.Handler {
	t.Helper()
	h, _, err := Protected(protPublic, v.verify)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func protCall(h http.Handler, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, protPublic+"/mcp", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func protRejected(t *testing.T, rec *httptest.ResponseRecorder, wantCode int) {
	t.Helper()
	if rec.Code != wantCode {
		t.Fatalf("status = %d, want %d", rec.Code, wantCode)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("rejection carries no WWW-Authenticate challenge")
	}
}

func TestProtectedExpiredTokenFailsClosed(t *testing.T) {
	v := &protVerifier{info: &auth.TokenInfo{Scopes: []string{"olist:read"}, Expiration: time.Now().Add(-time.Second)}}
	rec := protCall(protHandler(t, v), "Bearer good-token")
	protRejected(t, rec, http.StatusUnauthorized)
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("expired token body = %q", rec.Body.String())
	}
}

func TestProtectedMissingExpiryFailsClosed(t *testing.T) {
	v := &protVerifier{info: &auth.TokenInfo{Scopes: []string{"olist:read"}}}
	rec := protCall(protHandler(t, v), "Bearer good-token")
	protRejected(t, rec, http.StatusUnauthorized)
	if !strings.Contains(rec.Body.String(), "missing expiration") {
		t.Fatalf("missing expiry body = %q", rec.Body.String())
	}
}

func TestProtectedMissingReadScopeFailsClosed(t *testing.T) {
	v := &protVerifier{info: protValid("olist:write")}
	rec := protCall(protHandler(t, v), "Bearer good-token")
	protRejected(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "olist:read") {
		t.Fatal("insufficient-scope challenge does not name the required scope")
	}
}

func TestProtectedNoScopesFailsClosed(t *testing.T) {
	v := &protVerifier{info: protValid()}
	rec := protCall(protHandler(t, v), "Bearer good-token")
	protRejected(t, rec, http.StatusForbidden)
}

func TestProtectedInvalidTokenFailsClosed(t *testing.T) {
	v := &protVerifier{info: protValid("olist:read"), err: auth.ErrInvalidToken}
	rec := protCall(protHandler(t, v), "Bearer wrong-token")
	protRejected(t, rec, http.StatusUnauthorized)
}

func TestProtectedMissingOrMalformedHeaderFailsClosed(t *testing.T) {
	v := &protVerifier{info: protValid("olist:read")}
	h := protHandler(t, v)
	for _, header := range []string{"", "Basic good-token", "Bearer", "Bearer good-token extra", "good-token"} {
		rec := protCall(h, header)
		protRejected(t, rec, http.StatusUnauthorized)
	}
	if v.calls.Load() != 0 {
		t.Fatalf("verifier called %d times for malformed headers", v.calls.Load())
	}
}

// A verifier error must not leak its text. The wrapper maps every error to
// ErrInvalidToken, so the sentinel must not reach the response.
func TestProtectedVerifierErrorDoesNotLeak(t *testing.T) {
	cases := map[string]error{
		"plain error":   errors.New("provider said: " + protSentinel),
		"oauth error":   errors.Join(auth.ErrOAuth, errors.New(protSentinel)),
		"wrapped error": errors.Join(errors.New("db: "+protSentinel), auth.ErrInvalidToken),
	}
	for name, verr := range cases {
		t.Run(name, func(t *testing.T) {
			v := &protVerifier{info: protValid("olist:read"), err: verr}
			rec := protCall(protHandler(t, v), "Bearer good-token")
			if rec.Code == http.StatusOK {
				t.Fatal("verifier error accepted")
			}
			if strings.Contains(rec.Body.String(), protSentinel) || strings.Contains(rec.Header().Get("WWW-Authenticate"), protSentinel) {
				t.Fatal("verifier error text leaked to the client")
			}
		})
	}
}

// The safe wrapper turns every verifier error into 401. A nil TokenInfo with a
// nil error is passed through and the SDK answers 500; the request is still denied.
func TestProtectedNilInfoIsDenied(t *testing.T) {
	v := &protVerifier{info: nil, err: nil}
	rec := protCall(protHandler(t, v), "Bearer good-token")
	if rec.Code == http.StatusOK {
		t.Fatal("nil token info accepted")
	}
}

func TestProtectedMetadataFields(t *testing.T) {
	_, metadata, err := Protected(protPublic, (&protVerifier{}).verify)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	metadata.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, protPublic+"/.well-known/oauth-protected-resource/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`"resource":"https://example.com/mcp"`,
		`"authorization_servers":["https://example.com"]`,
		`"olist:read"`,
		`"olist:write"`,
		`"header"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metadata missing %s", want)
		}
	}
	if strings.Contains(body, "client_secret") {
		t.Fatal("metadata exposes unexpected fields")
	}
}

func TestProtectedChallengeNamesMetadataURL(t *testing.T) {
	v := &protVerifier{info: protValid("olist:read")}
	rec := protCall(protHandler(t, v), "")
	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(challenge, `resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("challenge = %q", challenge)
	}
}

func TestProtectedRejectsMalformedPublicOrigins(t *testing.T) {
	bad := []string{
		"",
		"http://example.com",
		"example.com",
		"https://",
		"https:///path",
		"https://user:pass@example.com",
		"https://example.com/mcp",
		"https://example.com/path/",
		"https://example.com?x=1",
		"https://example.com#frag",
		"ftp://example.com",
		"https://exa mple.com",
		"https://[::1",
		"//example.com",
	}
	for _, origin := range bad {
		if _, _, err := Protected(origin, (&protVerifier{}).verify); err == nil {
			t.Fatalf("origin %q accepted", origin)
		}
	}
	good := []string{"https://example.com", "https://example.com/", "https://example.com:8443"}
	for _, origin := range good {
		if _, _, err := Protected(origin, (&protVerifier{}).verify); err != nil {
			t.Fatalf("origin %q rejected: %v", origin, err)
		}
	}
}

func TestProtectedRejectsNilVerifier(t *testing.T) {
	if _, _, err := Protected(protPublic, nil); err == nil {
		t.Fatal("nil verifier accepted")
	}
}

// bearerTransport adds a fixed Authorization header to every request.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// A valid bearer must reach the MCP handler through the real SDK client.
func TestProtectedValidBearerReachesMCP(t *testing.T) {
	v := &protVerifier{info: protValid("olist:read")}
	h, _, err := Protected(protPublic, v.verify)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "prot-client", Version: "0.0.1"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: bearerTransport{base: http.DefaultTransport, token: "good-token"}},
	}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("authorized connect failed: %v", err)
	}
	defer session.Close()
	res, err := session.ListTools(context.Background(), nil)
	if err != nil || len(res.Tools) != 1 || res.Tools[0].Name != diagnosticTool {
		t.Fatalf("tools via authorized session = %+v, %v", res, err)
	}
	if v.calls.Load() == 0 {
		t.Fatal("verifier was not consulted")
	}
}

// The same client with a bad token must not reach the MCP handler.
func TestProtectedBadBearerRejectedByRealClient(t *testing.T) {
	v := &protVerifier{info: protValid("olist:read"), err: auth.ErrInvalidToken}
	h, _, err := Protected(protPublic, v.verify)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "prot-client", Version: "0.0.1"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: bearerTransport{base: http.DefaultTransport, token: "wrong-token"}, Timeout: 5 * time.Second},
		MaxRetries: -1,
	}
	session, err := client.Connect(context.Background(), transport, nil)
	if err == nil {
		session.Close()
		t.Fatal("unauthorized client connected")
	}
	if strings.Contains(err.Error(), protSentinel) {
		t.Fatal("client error leaks verifier text")
	}
}

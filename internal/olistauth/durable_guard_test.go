package olistauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
)

// Credential sentinels are compared with strings.Contains and never printed.
const (
	dgOldRefresh = "dg-sentinel-old-refresh-5a1e"
	dgNewRefresh = "dg-sentinel-new-refresh-9c33"
	dgNewAccess  = "dg-sentinel-new-access-0d7b"
	dgSecret     = "dg-sentinel-client-secret-e2f4"
)

const dgKeyByte = 9

func dgKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = dgKeyByte
	}
	return key
}

// dgProvider counts token requests and delegates each response to handler.
type dgProvider struct {
	calls atomic.Int32
	srv   *httptest.Server
}

func newDGProvider(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *dgProvider {
	t.Helper()
	p := &dgProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func dgConfig(tokenURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     "dg-client",
		ClientSecret: dgSecret,
		RedirectURL:  "https://example.com/oauth/olist/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.example/authorize",
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func dgRespond(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

// dgSuccess rotates the refresh token and returns a fresh access token.
func dgSuccess(w http.ResponseWriter, r *http.Request) {
	dgRespond(w, http.StatusOK, `{"access_token":"`+dgNewAccess+`","refresh_token":"`+dgNewRefresh+`","token_type":"Bearer","expires_in":3600}`)
}

// dgServerError is a transient failure that is not invalid_grant.
func dgServerError(w http.ResponseWriter, r *http.Request) {
	dgRespond(w, http.StatusInternalServerError, `{"error":"temporarily_unavailable"}`)
}

func dgInvalidGrant(w http.ResponseWriter, r *http.Request) {
	dgRespond(w, http.StatusBadRequest, `{"error":"invalid_grant"}`)
}

func dgOpen(t *testing.T, path string) *tokenstore.Store {
	t.Helper()
	s, err := tokenstore.Open(path, dgKey())
	if err != nil {
		t.Fatalf("tokenstore.Open: %v", err)
	}
	return s
}

// dgSeed stores an expired token so that the next AccessToken must refresh.
func dgSeed(t *testing.T, s *tokenstore.Store, account string) {
	t.Helper()
	err := s.Put(context.Background(), account, tokenstore.Token{
		AccessToken:  "dg-expired-access",
		RefreshToken: dgOldRefresh,
		Expiry:       time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func dgManager(t *testing.T, account string, provider *dgProvider, s TokenStore) *Manager {
	t.Helper()
	m, err := New(account, dgConfig(provider.srv.URL), s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func dgNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{dgOldRefresh, dgNewRefresh, dgNewAccess, dgSecret} {
		if strings.Contains(err.Error(), s) {
			t.Fatal("error message leaks a credential")
		}
	}
}

// A successful refresh clears the in-flight marker, and the new token is
// usable after a restart without contacting the provider again.
func TestSuccessfulRefreshClearsMarkerAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	provider := newDGProvider(t, dgSuccess)

	s := dgOpen(t, path)
	dgSeed(t, s, "a")
	got, err := dgManager(t, "a", provider, s).AccessToken(ctx)
	if err != nil || got != dgNewAccess {
		t.Fatalf("refresh failed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = dgOpen(t, path)
	defer s.Close()
	// The stored token must be readable directly, which fails while a marker exists.
	saved, err := s.Get(ctx, "a")
	if err != nil {
		t.Fatalf("marker survived a successful refresh: %v", err)
	}
	if saved.RefreshToken != dgNewRefresh {
		t.Fatal("rotated refresh token was not persisted")
	}
	got, err = dgManager(t, "a", provider, s).AccessToken(ctx)
	if err != nil || got != dgNewAccess {
		t.Fatalf("reopened account did not serve the stored token: %v", err)
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; want 1", n)
	}
}

// A provider error leaves the marker. The same process and a restarted one
// must both refuse to use the account without reauthorization.
func TestProviderErrorLeavesMarkerAndReopenRequiresReauth(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"transient 500": dgServerError,
		"invalid_grant": dgInvalidGrant,
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "control.db")
			provider := newDGProvider(t, handler)

			s := dgOpen(t, path)
			dgSeed(t, s, "a")
			m := dgManager(t, "a", provider, s)
			if _, err := m.AccessToken(ctx); err == nil {
				t.Fatal("provider error accepted")
			} else {
				dgNoLeak(t, err)
			}
			// Same process: the next call must fail closed without a provider call.
			if _, err := m.AccessToken(ctx); err == nil {
				t.Fatal("second call succeeded after a provider error")
			}
			if n := provider.calls.Load(); n != 1 {
				t.Fatalf("provider contacted %d times in one process; want 1", n)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			// Restarted process: the durable marker must still block refresh.
			s = dgOpen(t, path)
			defer s.Close()
			if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
				t.Fatal("restarted process used the account after a provider error")
			}
			if _, err := s.Get(ctx, "a"); err == nil {
				t.Fatal("stored token readable while the refresh marker is set")
			}
			if n := provider.calls.Load(); n != 1 {
				t.Fatalf("provider contacted %d times after restart; want 1", n)
			}
		})
	}
}

// A context canceled before the call must not start a refresh, and a later
// call with a live context must still work because nothing was marked.
func TestCanceledBeforeCallIsFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	provider := newDGProvider(t, dgSuccess)
	s := dgOpen(t, path)
	defer s.Close()
	dgSeed(t, s, "a")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := dgManager(t, "a", provider, s)
	if _, err := m.AccessToken(ctx); err == nil {
		t.Fatal("canceled call returned a token")
	}
	if n := provider.calls.Load(); n != 0 {
		t.Fatalf("provider contacted %d times with a canceled context", n)
	}
	if _, err := s.Get(context.Background(), "a"); err != nil {
		t.Fatalf("canceled call left a marker: %v", err)
	}
}

// A context canceled while the provider call is in flight may or may not have
// rotated the token. The marker written before the call must stay, so the
// account fails closed after the cancellation.
func TestCanceledInFlightRefreshIsFailClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	provider := newDGProvider(t, func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		// Hold the response until the client gives up or the test ends. The
		// server must not wait on the client alone: its connection may outlive
		// the canceled request.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Cleanups run last-in first-out, so this releases the handler before srv.Close.
	t.Cleanup(func() { close(release) })

	s := dgOpen(t, path)
	dgSeed(t, s, "a")
	callCtx, cancel := context.WithCancel(ctx)
	errc := make(chan error, 1)
	go func() {
		_, err := dgManager(t, "a", provider, s).AccessToken(callCtx)
		errc <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("provider call never started")
	}
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("canceled in-flight refresh returned a token")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = dgOpen(t, path)
	defer s.Close()
	if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
		t.Fatal("account usable after an in-flight refresh was canceled")
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; want 1", n)
	}
}

// Simulates a process that dies while the provider is answering: the marker
// was written before the request, and the connection is cut with no response.
func TestSimulatedCrashDuringRefreshIsFailClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	provider := newDGProvider(t, func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("response writer cannot hijack")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		// Drop the connection without writing any response, as a crash would.
		conn.(*net.TCPConn).Close()
	})

	s := dgOpen(t, path)
	dgSeed(t, s, "a")
	if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
		t.Fatal("refresh succeeded with no provider response")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = dgOpen(t, path)
	defer s.Close()
	if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
		t.Fatal("account usable after a crashed refresh")
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; want 1", n)
	}
}

// failingPut wraps the real store and fails every write, which models a
// persistence failure right after the provider rotated the refresh token.
type failingPut struct {
	inner *tokenstore.Store
}

func (f failingPut) Get(ctx context.Context, account string) (tokenstore.Token, error) {
	return f.inner.Get(ctx, account)
}

func (f failingPut) Put(context.Context, string, tokenstore.Token) error {
	return errors.New("simulated write failure")
}

// BeginRefresh is forwarded so the marker path runs as it does in production.
func (f failingPut) BeginRefresh(ctx context.Context, account string) error {
	return f.inner.BeginRefresh(ctx, account)
}

// A persistence failure after a rotation must fail closed, including after a
// restart. The marker is written by the real store, so the restarted process
// must refuse to use the old refresh token.
func TestPersistenceFailureThenRestartIsFailClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	provider := newDGProvider(t, dgSuccess)

	s := dgOpen(t, path)
	dgSeed(t, s, "a")
	if _, err := dgManager(t, "a", provider, failingPut{inner: s}).AccessToken(ctx); err == nil {
		t.Fatal("refresh reported success despite a failed write")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = dgOpen(t, path)
	defer s.Close()
	if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
		t.Fatal("restarted process reused the old refresh token")
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; want 1", n)
	}
}

// Markers are per account. A failed or interrupted account must not block
// another account, and the healthy account's token must survive a restart.
func TestSeparateAccountsRemainIndependent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	provider := newDGProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.FormValue("refresh_token") {
		case "dg-refresh-a":
			dgServerError(w, r)
		case "dg-refresh-b":
			dgRespond(w, http.StatusOK, `{"access_token":"dg-access-b-new","refresh_token":"dg-refresh-b-rotated","token_type":"Bearer","expires_in":3600}`)
		default:
			dgInvalidGrant(w, r)
		}
	})

	s := dgOpen(t, path)
	seed := func(account, refresh string) {
		err := s.Put(ctx, account, tokenstore.Token{AccessToken: "dg-expired", RefreshToken: refresh, Expiry: time.Now().Add(-time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
	}
	seed("a", "dg-refresh-a")
	seed("b", "dg-refresh-b")

	if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
		t.Fatal("account a refresh succeeded despite a provider error")
	}
	got, err := dgManager(t, "b", provider, s).AccessToken(ctx)
	if err != nil || got != "dg-access-b-new" {
		t.Fatalf("account b blocked by account a's marker: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = dgOpen(t, path)
	defer s.Close()
	if _, err := dgManager(t, "a", provider, s).AccessToken(ctx); err == nil {
		t.Fatal("account a usable after restart despite its marker")
	}
	if _, err := s.Get(ctx, "b"); err != nil {
		t.Fatalf("account b token lost or blocked after restart: %v", err)
	}
	got, err = dgManager(t, "b", provider, s).AccessToken(ctx)
	if err != nil || got != "dg-access-b-new" {
		t.Fatalf("account b not served after restart: %v", err)
	}
}

// Requirement check: the guard must hold even when the store is not the
// tokenstore type. Manager detects the marker API by type assertion, so a
// store without BeginRefresh skips the marker entirely. A crash after the
// provider rotates the refresh token would then leave the old token in place
// with nothing blocking a second use. This test is expected to fail today.
type plainStore struct {
	inner *tokenstore.Store
}

func (p plainStore) Get(ctx context.Context, account string) (tokenstore.Token, error) {
	return p.inner.Get(ctx, account)
}

func (p plainStore) Put(ctx context.Context, account string, tok tokenstore.Token) error {
	return errors.New("simulated write failure")
}

func TestGuardRequiresMarkerForAnyStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	provider := newDGProvider(t, dgSuccess)
	s := dgOpen(t, path)
	defer s.Close()
	dgSeed(t, s, "a")
	if _, err := dgManager(t, "a", provider, plainStore{inner: s}).AccessToken(ctx); err == nil {
		t.Fatal("unguarded store accepted")
	}
	if n := provider.calls.Load(); n != 0 {
		t.Fatalf("provider contacted %d times before guard check", n)
	}
}

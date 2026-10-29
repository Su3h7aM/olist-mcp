package olistauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
)

// Sentinel values are checked with strings.Contains and never printed, so a
// failing test cannot leak them into logs.
const (
	sentinelClientSecret = "sentinel-client-secret-7f3a"
	sentinelOldRefresh   = "sentinel-old-refresh-91bc"
	sentinelNewRefresh   = "sentinel-new-refresh-22de"
	sentinelNewAccess    = "sentinel-new-access-c04f"
	sentinelCode         = "sentinel-auth-code-5e18"
	sentinelOldAccess    = "sentinel-old-access-88aa"
)

// memStore is an in-memory TokenStore test double. It records writes and can
// be told to fail them.
type memStore struct {
	mu     sync.Mutex
	tokens map[string]tokenstore.Token
	putErr error
	puts   int
}

func newMemStore() *memStore {
	return &memStore{tokens: map[string]tokenstore.Token{}}
}

func (s *memStore) Get(_ context.Context, account string) (tokenstore.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[account]
	if !ok {
		return tokenstore.Token{}, errors.New("token not found")
	}
	return tok, nil
}

func (s *memStore) Put(_ context.Context, account string, tok tokenstore.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	if s.putErr != nil {
		return s.putErr
	}
	s.tokens[account] = tok
	return nil
}

func (s *memStore) snapshot(account string) (tokenstore.Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[account]
	return tok, ok
}

func (s *memStore) putCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

// fakeProvider is a token endpoint double. The handler decides each response.
type fakeProvider struct {
	calls atomic.Int32
	srv   *httptest.Server
}

func newFakeProvider(t *testing.T, handler http.HandlerFunc) *fakeProvider {
	t.Helper()
	p := &fakeProvider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func testOAuthConfig(tokenURL string) oauth2.Config {
	return oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: sentinelClientSecret,
		RedirectURL:  "https://example.com/oauth/olist/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.example/authorize",
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func successBody(access, refresh string) string {
	return `{"access_token":"` + access + `","refresh_token":"` + refresh + `","token_type":"Bearer","expires_in":3600}`
}

func expiredToken(refresh string) tokenstore.Token {
	return tokenstore.Token{AccessToken: sentinelOldAccess, RefreshToken: refresh, Expiry: time.Now().Add(-time.Hour)}
}

func mustManager(t *testing.T, account string, cfg oauth2.Config, store TokenStore) *Manager {
	t.Helper()
	m, err := New(account, cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func assertNoLeak(t *testing.T, err error, sentinels ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range sentinels {
		if strings.Contains(err.Error(), s) {
			t.Fatal("error message leaks a credential")
		}
	}
}

// A refused refresh must leave the stored token exactly as it was.
func TestRefreshFailureKeepsStoredToken(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, `{"error":"invalid_grant"}`)
	})
	store := newMemStore()
	store.tokens["a"] = expiredToken(sentinelOldRefresh)
	before := store.puts

	m := mustManager(t, "a", testOAuthConfig(provider.srv.URL), store)
	_, err := m.AccessToken(context.Background())
	if err == nil {
		t.Fatal("refresh rejected by provider was accepted")
	}
	assertNoLeak(t, err, sentinelOldRefresh, sentinelClientSecret)
	if store.puts != before {
		t.Fatal("a failed refresh wrote to the token store")
	}
	saved, ok := store.snapshot("a")
	if !ok || saved.RefreshToken != sentinelOldRefresh || saved.AccessToken != sentinelOldAccess {
		t.Fatal("stored token was replaced after a failed refresh")
	}
}

// Spec D3: a rejected refresh sets needs_reauth, so the manager must not
// contact the provider again. This test is expected to fail against the
// current implementation, which only sets needsReauth on persistence failure.
func TestRejectedRefreshRequiresReauthWithoutRetry(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, `{"error":"invalid_grant"}`)
	})
	store := newMemStore()
	store.tokens["a"] = expiredToken(sentinelOldRefresh)

	m := mustManager(t, "a", testOAuthConfig(provider.srv.URL), store)
	_, _ = m.AccessToken(context.Background())
	_, err := m.AccessToken(context.Background())
	if err == nil {
		t.Fatal("second call succeeded after a rejected refresh")
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; rejected refresh should set needs_reauth", n)
	}
}

// If the rotated refresh token cannot be saved, the manager must refuse all
// later refreshes in the same process instead of reusing the old token.
func TestPersistenceFailureBlocksSubsequentRefresh(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, successBody(sentinelNewAccess, sentinelNewRefresh))
	})
	store := newMemStore()
	store.tokens["a"] = expiredToken(sentinelOldRefresh)
	store.putErr = errors.New("disk full")

	m := mustManager(t, "a", testOAuthConfig(provider.srv.URL), store)
	tok, err := m.AccessToken(context.Background())
	if err == nil || tok != "" {
		t.Fatal("token returned despite persistence failure")
	}
	assertNoLeak(t, err, sentinelNewAccess, sentinelNewRefresh, sentinelOldRefresh)

	store.mu.Lock()
	store.putErr = nil // the store recovers; the manager must still refuse
	store.mu.Unlock()
	if _, err = m.AccessToken(context.Background()); err == nil {
		t.Fatal("manager refreshed again after a persistence failure")
	}
	if n := provider.calls.Load(); n != 1 {
		t.Fatalf("provider contacted %d times; want 1", n)
	}
	saved, _ := store.snapshot("a")
	if saved.RefreshToken != sentinelOldRefresh {
		t.Fatal("store changed although the write failed")
	}
}

// A canceled context must stop the refresh before any provider call or write.
func TestCanceledContextSendsNothing(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, successBody(sentinelNewAccess, sentinelNewRefresh))
	})
	store := newMemStore()
	store.tokens["a"] = expiredToken(sentinelOldRefresh)
	before := store.puts

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := mustManager(t, "a", testOAuthConfig(provider.srv.URL), store)
	_, err := m.AccessToken(ctx)
	if err == nil {
		t.Fatal("refresh succeeded with a canceled context")
	}
	if n := provider.calls.Load(); n != 0 {
		t.Fatalf("provider contacted %d times with a canceled context", n)
	}
	if store.puts != before {
		t.Fatal("canceled refresh wrote to the store")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err does not wrap context.Canceled: %v", err)
	}
}

// Two accounts refreshing at the same time must each receive their own token
// and each account's stored token must change only through its own manager.
func TestConcurrentRefreshIsolatedPerAccount(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.FormValue("refresh_token") {
		case "refresh-a":
			writeJSON(w, http.StatusOK, successBody("access-a-new", "refresh-a-rotated"))
		case "refresh-b":
			writeJSON(w, http.StatusOK, successBody("access-b-new", "refresh-b-rotated"))
		default:
			writeJSON(w, http.StatusBadRequest, `{"error":"invalid_grant"}`)
		}
	})
	store := newMemStore()
	store.tokens["a"] = expiredToken("refresh-a")
	store.tokens["b"] = expiredToken("refresh-b")
	cfg := testOAuthConfig(provider.srv.URL)
	ma := mustManager(t, "a", cfg, store)
	mb := mustManager(t, "b", cfg, store)

	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			got, err := ma.AccessToken(context.Background())
			if err == nil && got != "access-a-new" {
				err = errors.New("account a received another account's token")
			}
			errs <- err
		}()
		go func() {
			defer wg.Done()
			got, err := mb.AccessToken(context.Background())
			if err == nil && got != "access-b-new" {
				err = errors.New("account b received another account's token")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := provider.calls.Load(); n != 2 {
		t.Fatalf("provider contacted %d times; want one refresh per account", n)
	}
	a, _ := store.snapshot("a")
	b, _ := store.snapshot("b")
	if a.RefreshToken != "refresh-a-rotated" || b.RefreshToken != "refresh-b-rotated" {
		t.Fatal("rotated refresh tokens were stored under the wrong account")
	}
}

// Exchange failures of every kind must not persist anything.
func TestExchangeFailuresDoNotPersist(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"provider 400": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadRequest, `{"error":"invalid_grant","echo":"`+sentinelCode+`"}`)
		},
		"provider 500": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusInternalServerError, `{"error":"server"}`)
		},
		"missing refresh token": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, `{"access_token":"`+sentinelNewAccess+`","token_type":"Bearer","expires_in":3600}`)
		},
		"missing access token": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, `{"refresh_token":"`+sentinelNewRefresh+`","token_type":"Bearer","expires_in":3600}`)
		},
		"missing expiry": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, `{"access_token":"`+sentinelNewAccess+`","refresh_token":"`+sentinelNewRefresh+`","token_type":"Bearer"}`)
		},
		"not JSON": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, `<html>`)
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			provider := newFakeProvider(t, handler)
			store := newMemStore()
			err := Exchange(context.Background(), testOAuthConfig(provider.srv.URL), store, "a", sentinelCode)
			if err == nil {
				t.Fatal("exchange accepted a failing response")
			}
			assertNoLeak(t, err, sentinelCode, sentinelClientSecret, sentinelNewAccess, sentinelNewRefresh)
			if store.putCount() != 0 {
				t.Fatal("failed exchange persisted credentials")
			}
		})
	}
}

// A store failure after a good exchange must not leak the credentials it
// was trying to save.
func TestExchangePersistFailureHidesCredentials(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, successBody(sentinelNewAccess, sentinelNewRefresh))
	})
	store := newMemStore()
	store.putErr = errors.New("write failed")

	err := Exchange(context.Background(), testOAuthConfig(provider.srv.URL), store, "a", sentinelCode)
	if err == nil {
		t.Fatal("exchange reported success despite persistence failure")
	}
	assertNoLeak(t, err, sentinelNewAccess, sentinelNewRefresh, sentinelCode)
}

// A canceled context must stop the exchange before a provider call or write.
func TestExchangeCanceledContextSendsNothing(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, successBody(sentinelNewAccess, sentinelNewRefresh))
	})
	store := newMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Exchange(ctx, testOAuthConfig(provider.srv.URL), store, "a", sentinelCode); err == nil {
		t.Fatal("exchange succeeded with a canceled context")
	}
	if n := provider.calls.Load(); n != 0 {
		t.Fatalf("provider contacted %d times with a canceled context", n)
	}
	if store.putCount() != 0 {
		t.Fatal("canceled exchange persisted credentials")
	}
}

// Provider error bodies must not reach callers. Exchange wraps its error, but
// Manager.AccessToken returns the oauth2 error directly. When the body has no
// standard "error" field, oauth2 includes the raw body in the message. This
// test is expected to fail if a provider echoes the refresh token there.
func TestRefreshErrorDoesNotEchoRefreshToken(t *testing.T) {
	provider := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		// No standard "error" field, so oauth2 falls back to the raw body in its message.
		writeJSON(w, http.StatusBadRequest, `{"detail":"invalid grant","refresh_token":"`+sentinelOldRefresh+`"}`)
	})
	store := newMemStore()
	store.tokens["a"] = expiredToken(sentinelOldRefresh)

	m := mustManager(t, "a", testOAuthConfig(provider.srv.URL), store)
	_, err := m.AccessToken(context.Background())
	if err == nil {
		t.Fatal("refresh rejected by provider was accepted")
	}
	assertNoLeak(t, err, sentinelOldRefresh, sentinelClientSecret)
}

package admin

import (
	"context"
	"github.com/openbot/olist-mcp/internal/oauthstate"
	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testStore struct{ account string }

func (s *testStore) Get(context.Context, string) (tokenstore.Token, error) {
	return tokenstore.Token{}, nil
}
func (s *testStore) Put(_ context.Context, a string, _ tokenstore.Token) error {
	s.account = a
	return nil
}
func TestConnectBoundStateAndReplay(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"a","refresh_token":"r","expires_in":3600}`))
	}))
	defer provider.Close()
	registry, _ := oauthstate.New(time.Minute, 10)
	store := &testStore{}
	cfg := oauth2.Config{ClientID: "c", ClientSecret: "s", RedirectURL: "https://example.com/callback", Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: provider.URL, AuthStyle: oauth2.AuthStyleInParams}}
	h, err := New(func(r *http.Request) (string, error) { return r.Header.Get("owner"), nil }, func(a string) (oauth2.Config, bool) { return cfg, a == "account-a" }, registry, store)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/start", strings.NewReader("account=account-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("owner", "owner-a")
	rec := httptest.NewRecorder()
	h.Start(rec, req)
	if rec.Code != 303 {
		t.Fatalf("start: %d", rec.Code)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	state := u.Query().Get("state")
	call := func(owner string) int {
		r := httptest.NewRequest(http.MethodGet, "/callback?state="+url.QueryEscape(state)+"&code=ok", nil)
		r.Header.Set("owner", owner)
		w := httptest.NewRecorder()
		h.Callback(w, r)
		return w.Code
	}
	if call("other") != 400 {
		t.Fatal("wrong owner accepted")
	}
	if call("owner-a") != 200 || store.account != "account-a" {
		t.Fatal("valid callback failed")
	}
	if call("owner-a") != 400 {
		t.Fatal("replay accepted")
	}
}

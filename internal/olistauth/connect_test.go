package olistauth

import (
	"context"
	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

func TestConnectExchange(t *testing.T) {
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "code" {
			t.Error("missing code")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer endpoint.Close()
	config := oauth2.Config{ClientID: "client", ClientSecret: "secret", RedirectURL: "https://example.com/oauth/olist/callback", Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example/authorize", TokenURL: endpoint.URL, AuthStyle: oauth2.AuthStyleInParams}}
	raw, err := AuthorizationURL(config, "random-state")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Query().Get("state") != "random-state" {
		t.Fatal("state missing")
	}
	db, err := tokenstore.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = Exchange(context.Background(), config, db, "a", "code"); err != nil {
		t.Fatal(err)
	}
	tok, err := db.Get(context.Background(), "a")
	if err != nil || tok.RefreshToken != "refresh" {
		t.Fatalf("credentials missing: %v", err)
	}
}

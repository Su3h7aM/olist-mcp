package olistauth

import (
	"context"
	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshSerializedAndPersisted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"new","refresh_token":"rotated","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()
	db, err := tokenstore.Open(filepath.Join(t.TempDir(), "control.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err = db.Put(ctx, "a", tokenstore.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	m, err := New("a", oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: srv.URL, AuthStyle: oauth2.AuthStyleInParams}}, db)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			got, err := m.AccessToken(ctx)
			if err != nil || got != "new" {
				t.Errorf("refresh failed: %v", err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d", calls.Load())
	}
	saved, err := db.Get(ctx, "a")
	if err != nil || saved.RefreshToken != "rotated" {
		t.Fatalf("token not saved: %v", err)
	}
}

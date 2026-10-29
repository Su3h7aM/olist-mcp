package mcpserver

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openbot/olist-mcp/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestListRecordsEnforcesGrant(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, a := range []string{"a", "b"} {
		if err = db.PutAccount(ctx, a, a); err != nil {
			t.Fatal(err)
		}
		if err = db.Put(ctx, store.Record{AccountID: a, Resource: "produtos", RemoteID: "1", Payload: []byte(`{"id":1}`), ObservedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	verifier := func(context.Context, string, *http.Request) (*auth.TokenInfo, error) {
		return &auth.TokenInfo{UserID: "owner", Expiration: time.Now().Add(time.Minute), Scopes: []string{"olist:read"}, Extra: map[string]any{"accounts": []string{"a"}}}, nil
	}
	wrapped, _, err := ProtectedMirror("https://example.com", verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer example")
		wrapped.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, tc := range []struct {
		account string
		denied  bool
	}{{"a", false}, {"b", true}} {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_records", Arguments: map[string]any{"account": tc.account, "resource": "produtos", "limit": 10, "offset": 0}})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError != tc.denied {
			t.Fatalf("account %s denied %v", tc.account, res.IsError)
		}
	}
}

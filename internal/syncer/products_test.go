package syncer

import (
	"context"
	"encoding/json"
	"github.com/openbot/olist-mcp/internal/olist"
	"github.com/openbot/olist-mcp/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestProductsCopiesDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/produtos":
			w.Write([]byte(`{"itens":[{"id":1}],"paginacao":{"limit":100,"offset":0,"total":1}}`))
		case "/produtos/1":
			w.Write([]byte(`{"id":1,"sku":"A"}`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	api, err := olist.NewClient(srv.URL, func(context.Context) (string, error) { return "token", nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.PutAccount(ctx, "a", "A"); err != nil {
		t.Fatal(err)
	}
	p, err := Products(ctx, api, db, "a")
	if err != nil || p.Records != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	r, err := db.Get(ctx, "a", "produtos", "1")
	if err != nil || !json.Valid(r.Payload) || string(r.Payload) != `{"id":1,"sku":"A"}` {
		t.Fatalf("%s %v", r.Payload, err)
	}
}
func TestProductsRejectsInvalidPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"itens":[],"paginacao":{"limit":100,"offset":0,"total":1}}`))
	}))
	defer srv.Close()
	api, _ := olist.NewClient(srv.URL, func(context.Context) (string, error) { return "token", nil })
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = Products(ctx, api, db, "a"); err == nil {
		t.Fatal("expected error")
	}
}

package olist

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public-api/v3/produtos" || r.URL.Query().Get("limit") != "10" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("unexpected request: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"itens":[]}`))
	}))
	defer server.Close()
	c, err := NewClient(server.URL+"/public-api/v3", func(context.Context) (string, error) { return "secret", nil })
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Get(context.Background(), "/produtos", url.Values{"limit": {"10"}})
	if err != nil || string(b) != `{"itens":[]}` {
		t.Fatalf("%s %v", b, err)
	}
	for _, path := range []string{"//evil", "/../x", "/x?secret=1"} {
		if _, err = c.Get(context.Background(), path, nil); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}
func TestRateLimitAndNoRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, target.URL, http.StatusFound)
			return
		}
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(429)
	}))
	defer server.Close()
	c, _ := NewClient(server.URL, func(context.Context) (string, error) { return "secret", nil })
	_, err := c.Get(context.Background(), "/limit", nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != 429 || he.RetryAfter != "15" {
		t.Fatalf("%v", err)
	}
	_, err = c.Get(context.Background(), "/redirect", nil)
	if !errors.As(err, &he) || he.StatusCode != 302 {
		t.Fatalf("%v", err)
	}
}

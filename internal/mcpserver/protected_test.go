package mcpserver

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProtectedRequiresBearerAndProvidesMetadata(t *testing.T) {
	verify := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		if token != "valid" {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{Scopes: []string{"olist:read"}, Expiration: time.Now().Add(time.Minute), UserID: "owner"}, nil
	}
	h, metadata, err := Protected("https://example.com", verify)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://example.com/mcp", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("status %d", w.Code)
	}
	w = httptest.NewRecorder()
	metadata.ServeHTTP(w, httptest.NewRequest("GET", "https://example.com/.well-known/oauth-protected-resource/mcp", nil))
	var v map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &v); err != nil || v["resource"] != "https://example.com/mcp" {
		t.Fatalf("metadata invalid: %v", err)
	}
	r.Header.Set("Authorization", "Bearer invalid")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("invalid token: %d", w.Code)
	}
}
func TestProtectedRejectsInvalidConfiguration(t *testing.T) {
	if _, _, err := Protected("http://example.com", nil); err == nil {
		t.Fatal("invalid configuration accepted")
	}
}

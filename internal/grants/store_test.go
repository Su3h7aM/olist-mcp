package grants

import (
	"context"
	"database/sql"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/auth"
	_ "modernc.org/sqlite"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGrantVerification(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := Open(ctx, db, "https://example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 40)
	g := Grant{Subject: "client-1", Audience: "https://example.com/mcp", Accounts: []string{"a"}, Scopes: []string{"olist:read"}, Expires: time.Now().Add(time.Hour)}
	if err = s.Put(ctx, token, g); err != nil {
		t.Fatal(err)
	}
	info, err := s.Verify(ctx, token, nil)
	if err != nil || info.UserID != "client-1" || len(info.Extra["accounts"].([]string)) != 1 {
		t.Fatal("valid grant rejected")
	}
	if err = s.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Verify(ctx, token, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatal("revoked token accepted")
	}
	wrong, _ := Open(ctx, db, "https://other.example/mcp")
	if _, err = wrong.Verify(ctx, token, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatal("wrong audience accepted")
	}
}

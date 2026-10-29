package grants

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// Tokens and their encodings are compared with bytes.Contains and never printed.
const (
	gsAudience = "https://example.com/mcp"
	gsOther    = "https://other.example/mcp"
)

func gsToken(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func gsGrant(subject string, accounts ...string) Grant {
	return Grant{
		Subject:  subject,
		Audience: gsAudience,
		Accounts: accounts,
		Scopes:   []string{"olist:read"},
		Expires:  time.Now().Add(time.Hour),
	}
}

// gsDB opens a real SQLite file at path. WAL mode is enabled so that the
// -wal sidecar exists and can be inspected.
func gsDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func gsStore(t *testing.T, path, audience string) (*Store, *sql.DB) {
	t.Helper()
	db := gsDB(t, path)
	s, err := Open(context.Background(), db, audience)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return s, db
}

func gsRequireInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("verify returned %v; want auth.ErrInvalidToken", err)
	}
}

func TestRawTokenAbsentFromDatabaseAndWAL(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "control.db")
	s, db := gsStore(t, path, gsAudience)

	token := gsToken(t)
	if err := s.Put(ctx, token, gsGrant("client-1", "a", "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, token, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte(token))
	encodings := [][]byte{
		[]byte(token),
		[]byte(base64.StdEncoding.EncodeToString([]byte(token))),
		[]byte(base64.RawStdEncoding.EncodeToString([]byte(token))),
	}
	check := func(stage string) {
		t.Helper()
		for _, name := range []string{path, path + "-wal"} {
			raw, err := os.ReadFile(name)
			if err != nil {
				continue
			}
			for _, enc := range encodings {
				if bytes.Contains(raw, enc) {
					t.Fatalf("%s: raw token found in %s", stage, filepath.Base(name))
				}
			}
			if name == path && stage == "open" && !bytes.Contains(raw, hash[:]) && !hashInWAL(path+"-wal", hash[:]) {
				t.Fatalf("%s: token hash not found, so the check could not have worked", stage)
			}
		}
	}
	check("open")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	check("closed")
}

func hashInWAL(walPath string, needle []byte) bool {
	raw, err := os.ReadFile(walPath)
	return err == nil && bytes.Contains(raw, needle)
}

func TestWrongAudienceRejectedBeforeRevocation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	issuer, _ := gsStore(t, path, gsAudience)
	token := gsToken(t)
	if err := issuer.Put(ctx, token, gsGrant("client-1", "a")); err != nil {
		t.Fatal(err)
	}

	// A store for another resource shares the database. It must refuse the token.
	other, _ := gsStore(t, path, gsOther)
	if _, err := other.Verify(ctx, token, nil); err == nil {
		t.Fatal("token for one audience accepted by another resource")
	} else {
		gsRequireInvalid(t, err)
	}
	if err := other.Put(ctx, gsToken(t), gsGrant("client-2", "a")); err == nil {
		t.Fatal("grant with a foreign audience stored")
	}
	// The correct audience still works, so the rejection was about audience alone.
	if _, err := issuer.Verify(ctx, token, nil); err != nil {
		t.Fatalf("correct audience rejected: %v", err)
	}
}

func TestExpiredGrantFailsClosed(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	token := gsToken(t)
	g := gsGrant("client-1", "a")
	g.Expires = time.Now().Add(300 * time.Millisecond)
	if err := s.Put(ctx, token, g); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, token, nil); err != nil {
		t.Fatalf("live grant rejected: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	_, err := s.Verify(ctx, token, nil)
	gsRequireInvalid(t, err)
}

func TestPastExpiryRejectedAtPut(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	g := gsGrant("client-1", "a")
	g.Expires = time.Now().Add(-time.Minute)
	if err := s.Put(ctx, gsToken(t), g); err == nil {
		t.Fatal("already-expired grant stored")
	}
}

func TestMalformedStoredGrantsFailClosed(t *testing.T) {
	ctx := context.Background()
	s, db := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	token := gsToken(t)
	if err := s.Put(ctx, token, gsGrant("client-1", "a")); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	cases := map[string]map[string]any{
		"accounts not JSON":    {"accounts": "a,b"},
		"accounts empty array": {"accounts": "[]"},
		"accounts null":        {"accounts": "null"},
		"accounts object":      {"accounts": `{"a":1}`},
		"scopes not JSON":      {"scopes": "olist:read"},
		"scopes empty array":   {"scopes": "[]"},
		"scopes object":        {"scopes": `{"read":true}`},
		"subject empty":        {"subject": ""},
		"expires garbage":      {"expires": "tomorrow"},
		"expires empty":        {"expires": ""},
		"expires past":         {"expires": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)},
		"revoked flag other":   {"revoked": 2},
		"audience changed":     {"audience": gsOther},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			// Reset the row, then apply exactly one malformed field.
			if _, err := db.ExecContext(ctx, `UPDATE mcp_grants SET accounts=?, scopes=?, subject=?, expires=?, revoked=0, audience=? WHERE token_hash=?`,
				`["a"]`, `["olist:read"]`, "client-1", future, gsAudience, hash[:]); err != nil {
				t.Fatal(err)
			}
			for col, val := range change {
				if _, err := db.ExecContext(ctx, `UPDATE mcp_grants SET `+col+`=? WHERE token_hash=?`, val, hash[:]); err != nil {
					t.Fatal(err)
				}
			}
			_, err := s.Verify(ctx, token, nil)
			gsRequireInvalid(t, err)
		})
	}
	// The unmodified row still verifies, so each failure above came from its one bad field.
	if _, err := db.ExecContext(ctx, `UPDATE mcp_grants SET accounts=?, scopes=?, subject=?, expires=?, revoked=0, audience=? WHERE token_hash=?`,
		`["a"]`, `["olist:read"]`, "client-1", future, gsAudience, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, token, nil); err != nil {
		t.Fatalf("baseline row no longer verifies: %v", err)
	}
}

func TestEmptyEntryInStoredListRejected(t *testing.T) {
	ctx := context.Background()
	s, db := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	token := gsToken(t)
	if err := s.Put(ctx, token, gsGrant("client-1", "a")); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	if _, err := db.ExecContext(ctx, `UPDATE mcp_grants SET accounts=? WHERE token_hash=?`, `[""]`, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, token, nil); err == nil {
		t.Fatal("row with empty account accepted")
	}
}

func TestAccountsAndSubjectsIsolated(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	t1, t2 := gsToken(t), gsToken(t)
	if err := s.Put(ctx, t1, gsGrant("subject-1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, t2, gsGrant("subject-2", "b", "c")); err != nil {
		t.Fatal(err)
	}

	i1, err := s.Verify(ctx, t1, nil)
	if err != nil || i1.UserID != "subject-1" || !equalStrings(i1.Extra["accounts"].([]string), []string{"a"}) {
		t.Fatalf("subject-1 info = %+v, %v", i1, err)
	}
	i2, err := s.Verify(ctx, t2, nil)
	if err != nil || i2.UserID != "subject-2" || !equalStrings(i2.Extra["accounts"].([]string), []string{"b", "c"}) {
		t.Fatalf("subject-2 info = %+v, %v", i2, err)
	}

	// Revoking one subject must not affect another.
	if err := s.Revoke(ctx, t1); err != nil {
		t.Fatal(err)
	}
	_, err = s.Verify(ctx, t1, nil)
	gsRequireInvalid(t, err)
	if _, err := s.Verify(ctx, t2, nil); err != nil {
		t.Fatalf("revoking subject-1 affected subject-2: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDuplicateTokenHashRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	token := gsToken(t)
	if err := s.Put(ctx, token, gsGrant("client-1", "a")); err != nil {
		t.Fatal(err)
	}
	// A second grant for the same token must not overwrite the first.
	if err := s.Put(ctx, token, gsGrant("client-2", "b", "c")); err == nil {
		t.Fatal("duplicate token hash accepted")
	}
	info, err := s.Verify(ctx, token, nil)
	if err != nil || info.UserID != "client-1" || !equalStrings(info.Extra["accounts"].([]string), []string{"a"}) {
		t.Fatalf("original grant changed by duplicate insert: %+v, %v", info, err)
	}

	// A revoked token must not be resurrected by inserting it again.
	if err := s.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, token, gsGrant("client-3", "a")); err == nil {
		t.Fatal("revoked token re-issued by Put")
	}
	_, err = s.Verify(ctx, token, nil)
	gsRequireInvalid(t, err)
}

func TestRevokedStaysRevokedAfterReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, db := gsStore(t, path, gsAudience)
	token := gsToken(t)
	if err := s.Put(ctx, token, gsGrant("client-1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, _ := gsStore(t, path, gsAudience)
	_, err := reopened.Verify(ctx, token, nil)
	gsRequireInvalid(t, err)
}

func TestShortTokensRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	short := make([]byte, 31)
	if _, err := rand.Read(short); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(short)[:31]
	if err := s.Put(ctx, token, gsGrant("client-1", "a")); err == nil {
		t.Fatal("31-character token stored")
	}
	_, err := s.Verify(ctx, token, nil)
	gsRequireInvalid(t, err)
}

func TestUnknownTokenRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	_, err := s.Verify(ctx, gsToken(t), nil)
	gsRequireInvalid(t, err)
}

// Revoking a token that was never issued is a silent no-op. This test pins
// that behavior so a change is visible.
func TestRevokeUnknownTokenIsNoop(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	if err := s.Revoke(ctx, gsToken(t)); err != nil {
		t.Fatalf("revoking an unknown token returned %v", err)
	}
}

// Verify is called while other goroutines revoke. A verify that starts after
// Revoke has returned must fail. Successful verifies before that point are fine.
func TestConcurrentVerifyAndRevoke(t *testing.T) {
	ctx := context.Background()
	s, _ := gsStore(t, filepath.Join(t.TempDir(), "control.db"), gsAudience)
	token := gsToken(t)
	if err := s.Put(ctx, token, gsGrant("client-1", "a")); err != nil {
		t.Fatal(err)
	}

	var revoked atomic.Bool
	var wg sync.WaitGroup
	violations := make(chan string, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				wasRevoked := revoked.Load()
				_, err := s.Verify(ctx, token, nil)
				if wasRevoked && err == nil {
					violations <- "verify succeeded after revocation completed"
					return
				}
				if err != nil && !errors.Is(err, auth.ErrInvalidToken) {
					violations <- "verify returned a non-invalid-token error"
					return
				}
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)
	if err := s.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	wg.Wait()
	close(violations)
	for v := range violations {
		t.Fatal(v)
	}
	_, err := s.Verify(ctx, token, nil)
	gsRequireInvalid(t, err)
}

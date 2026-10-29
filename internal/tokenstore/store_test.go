package tokenstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedTokensAndAccountBinding(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	key := bytes.Repeat([]byte{7}, 32)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	want := Token{"access-sensitive", "refresh-sensitive", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err = s.Put(ctx, "a", want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "a")
	if err != nil || got != want {
		t.Fatalf("token round trip failed: %v", err)
	}
	if _, err = s.db.Exec(`INSERT INTO tokens SELECT 'b',ciphertext FROM tokens WHERE account_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, "b"); err == nil {
		t.Fatal("row swap accepted")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("access-sensitive")) || bytes.Contains(raw, []byte("refresh-sensitive")) {
		t.Fatal("plaintext in database")
	}
	s, err = Open(path, bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Get(ctx, "a"); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestInterruptedRefreshRequiresReauthorizationAfterReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	key := bytes.Repeat([]byte{9}, 32)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(ctx, "a", Token{"a", "r", time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err = s.BeginRefresh(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Get(ctx, "a"); err == nil {
		t.Fatal("interrupted refresh was not detected")
	}
	if err = s.Put(ctx, "a", Token{"new", "new-r", time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(ctx, "a"); err != nil {
		t.Fatal(err)
	}
}

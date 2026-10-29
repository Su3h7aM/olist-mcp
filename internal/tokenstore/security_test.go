package tokenstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Secret values are checked with bytes.Contains or compared, never printed.
const (
	secretAccess  = "secret-access-token-value-41d2"
	secretRefresh = "secret-refresh-token-value-b07e"
)

func testKey(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, 32)
}

func sampleToken(tag string) Token {
	return Token{
		AccessToken:  secretAccess + "-" + tag,
		RefreshToken: secretRefresh + "-" + tag,
		Expiry:       time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
	}
}

func openSecure(t *testing.T, path string, key []byte) *Store {
	t.Helper()
	s, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenRejectsInvalidKeyLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := Open(path, make([]byte, n)); err == nil {
			t.Fatalf("key of %d bytes accepted", n)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("database file created despite invalid key")
	}
}

func TestOpenRejectsNonAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	for _, p := range []string{"control.db", "./control.db", "sub/../control.db"} {
		if _, err := Open(p, testKey(1)); err == nil {
			t.Fatalf("relative path %q accepted", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "control.db")); err == nil {
		t.Fatal("relative path created a database")
	}
}

func TestOpenCreatesPrivateDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	s := openSecure(t, path, testKey(1))
	if err := s.Put(context.Background(), "a", sampleToken("x")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("database permissions = %o, want 600", perm)
	}
	// SQLite may create -wal and -shm sidecars; they hold the same ciphertext.
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		side, err := os.Stat(path + suffix)
		if err != nil {
			continue
		}
		if perm := side.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("sidecar %s permissions = %o, want no group or other access", suffix, perm)
		}
	}
}

func TestOpenRejectsGroupOrWorldReadableDatabase(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.db")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, testKey(1)); err == nil {
				t.Fatalf("database with mode %o accepted", mode)
			}
		})
	}
}

func TestOpenRejectsDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, testKey(1)); err == nil {
		t.Fatal("directory accepted as database")
	}
}

func TestWrongKeyCannotDecryptAnyAccount(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"a", "b"} {
		if err := s.Put(ctx, a, sampleToken(a)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	wrong := openSecure(t, path, testKey(2))
	for _, a := range []string{"a", "b"} {
		tok, err := wrong.Get(ctx, a)
		if err == nil {
			t.Fatalf("account %s decrypted with the wrong key", a)
		}
		if tok.AccessToken != "" || tok.RefreshToken != "" {
			t.Fatal("token fields populated after failed decryption")
		}
		if strings.Contains(err.Error(), secretAccess) || strings.Contains(err.Error(), secretRefresh) {
			t.Fatal("decryption error leaks token material")
		}
	}
}

func TestModifiedCiphertextIsRejected(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))
	if err := s.Put(ctx, "a", sampleToken("a")); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := s.db.QueryRowContext(ctx, `SELECT ciphertext FROM tokens WHERE account_id='a'`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), sealed...)

	// Flip every bit of nonce, ciphertext and tag in turn; each must fail.
	for i := range original {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), original...)
			mutated[i] ^= 1 << bit
			if _, err := s.db.ExecContext(ctx, `UPDATE tokens SET ciphertext=? WHERE account_id='a'`, mutated); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, "a"); err == nil {
				t.Fatalf("bit flip at byte %d bit %d accepted", i, bit)
			}
		}
	}
	// Restore and confirm the untouched row still decrypts.
	if _, err := s.db.ExecContext(ctx, `UPDATE tokens SET ciphertext=? WHERE account_id='a'`, original); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a"); err != nil {
		t.Fatalf("restored ciphertext rejected: %v", err)
	}
}

func TestTruncatedCiphertextIsRejected(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))
	if err := s.Put(ctx, "a", sampleToken("a")); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := s.db.QueryRowContext(ctx, `SELECT ciphertext FROM tokens WHERE account_id='a'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 11, 12, 13} {
		if _, err := s.db.ExecContext(ctx, `UPDATE tokens SET ciphertext=? WHERE account_id='a'`, original[:n]); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "a"); err == nil {
			t.Fatalf("ciphertext truncated to %d bytes accepted", n)
		}
	}
}

func TestRowSwapAcrossAccountsIsRejected(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))
	for _, a := range []string{"a", "b"} {
		if err := s.Put(ctx, a, sampleToken(a)); err != nil {
			t.Fatal(err)
		}
	}
	// Overwrite b's ciphertext with a's, the way an attacker with DB write access would.
	var sealedA []byte
	if err := s.db.QueryRowContext(ctx, `SELECT ciphertext FROM tokens WHERE account_id='a'`).Scan(&sealedA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE tokens SET ciphertext=? WHERE account_id='b'`, sealedA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "b"); err == nil {
		t.Fatal("account b decrypted account a's ciphertext")
	}
	// Account a is unaffected and still readable.
	got, err := s.Get(ctx, "a")
	if err != nil || got.AccessToken != sampleToken("a").AccessToken {
		t.Fatalf("account a changed by swap: %v", err)
	}
}

func TestPutDoesNotStorePlaintext(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s := openSecure(t, path, testKey(1))
	if err := s.Put(ctx, "a", sampleToken("a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + "-wal"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(secretAccess)) || bytes.Contains(raw, []byte(secretRefresh)) {
			t.Fatalf("plaintext token found in %s", filepath.Base(p))
		}
	}
}

func TestConcurrentAccountWritesStayIsolated(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))

	const accounts, rounds = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, accounts*rounds)
	for i := 0; i < accounts; i++ {
		account := fmt.Sprintf("acc%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				tok := sampleToken(fmt.Sprintf("%s-%d", account, r))
				if err := s.Put(ctx, account, tok); err != nil {
					errs <- err
					return
				}
				got, err := s.Get(ctx, account)
				if err != nil {
					errs <- err
					return
				}
				// Each account must only ever see its own tokens.
				if !strings.HasPrefix(got.AccessToken, secretAccess+"-"+account+"-") {
					errs <- fmt.Errorf("account %s read another account's token", account)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for i := 0; i < accounts; i++ {
		account := fmt.Sprintf("acc%d", i)
		got, err := s.Get(ctx, account)
		if err != nil {
			t.Fatalf("account %s: %v", account, err)
		}
		want := sampleToken(fmt.Sprintf("%s-%d", account, rounds-1)).AccessToken
		if got.AccessToken != want {
			t.Fatalf("account %s final token is not its last write", account)
		}
	}
}

func TestConcurrentSameAccountWritesLeaveDecryptableRow(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < 20; r++ {
				if err := s.Put(ctx, "a", sampleToken(fmt.Sprintf("w%d", w))); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	got, err := s.Get(ctx, "a")
	if err != nil {
		t.Fatalf("row unreadable after concurrent writes: %v", err)
	}
	if !strings.HasPrefix(got.AccessToken, secretAccess+"-w") {
		t.Fatal("row does not hold a complete token written by one writer")
	}
}

func TestReopenPersistsTokensAndUpdates(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	key := testKey(3)

	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	first := sampleToken("first")
	if err := s.Put(ctx, "a", first); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "b", sampleToken("b")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openSecure(t, path, key)
	got, err := s.Get(ctx, "a")
	if err != nil || got != first {
		t.Fatalf("token not persisted across reopen: %v", err)
	}
	// A rotated token written after reopen must replace the old one durably.
	rotated := sampleToken("rotated")
	if err := s.Put(ctx, "a", rotated); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openSecure(t, path, key)
	got, err = s.Get(ctx, "a")
	if err != nil || got != rotated {
		t.Fatalf("rotated token not persisted: %v", err)
	}
	if _, err := s.Get(ctx, "b"); err != nil {
		t.Fatalf("other account lost on reopen: %v", err)
	}
}

func TestGetUnknownAccountAndEmptyAccount(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))
	if _, err := s.Get(ctx, "missing"); err == nil {
		t.Fatal("unknown account returned a token")
	}
	if _, err := s.Get(ctx, ""); err == nil {
		t.Fatal("empty account accepted")
	}
	if err := s.Put(ctx, "", sampleToken("x")); err == nil {
		t.Fatal("empty account accepted for write")
	}
}

func TestPutRejectsIncompleteToken(t *testing.T) {
	ctx := context.Background()
	s := openSecure(t, filepath.Join(t.TempDir(), "control.db"), testKey(1))
	cases := map[string]Token{
		"no access":  {RefreshToken: secretRefresh},
		"no refresh": {AccessToken: secretAccess},
	}
	for name, tok := range cases {
		if err := s.Put(ctx, "a", tok); err == nil {
			t.Fatalf("%s: incomplete token stored", name)
		}
	}
	if _, err := s.Get(ctx, "a"); err == nil {
		t.Fatal("rejected token left a row behind")
	}
}

// Package tokenstore persists encrypted Olist credentials separately from mirror data.
package tokenstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}
type Store struct {
	db   *sql.DB
	aead cipher.AEAD
	mu   sync.Mutex
}

// Open creates a separate control database; key must be a stable 256-bit secret
// stored outside the database. The parent directory must already exist.
func Open(path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("token encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("control database path must be absolute")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		err = errors.New("control database must be a private regular file")
	}
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS tokens (account_id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, aead: aead}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Put(ctx context.Context, account string, token Token) error {
	if account == "" || token.AccessToken == "" || token.RefreshToken == "" {
		return errors.New("account and tokens are required")
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	// Bind ciphertext to its account, so rows cannot be swapped across accounts.
	sealed := s.aead.Seal(nonce, nonce, data, []byte(account))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.ExecContext(ctx, `INSERT INTO tokens(account_id,ciphertext) VALUES(?,?) ON CONFLICT(account_id) DO UPDATE SET ciphertext=excluded.ciphertext`, account, sealed)
	return err
}
func (s *Store) Get(ctx context.Context, account string) (Token, error) {
	var out Token
	if account == "" {
		return out, errors.New("account required")
	}
	var sealed []byte
	if err := s.db.QueryRowContext(ctx, `SELECT ciphertext FROM tokens WHERE account_id=?`, account).Scan(&sealed); err != nil {
		return out, err
	}
	if len(sealed) < s.aead.NonceSize() {
		return out, errors.New("invalid encrypted token")
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(account))
	if err != nil {
		return out, errors.New("cannot decrypt token")
	}
	if err = json.Unmarshal(plain, &out); err != nil {
		return Token{}, fmt.Errorf("invalid token data: %w", err)
	}
	return out, nil
}

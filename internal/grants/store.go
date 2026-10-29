// Package grants persists opaque MCP access grants. Token issuance and OAuth
// protocol flows are handled elsewhere; the store never stores raw tokens.
package grants

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/modelcontextprotocol/go-sdk/auth"
	_ "modernc.org/sqlite"
	"net/http"
	"time"
)

type Store struct {
	db       *sql.DB
	audience string
}
type Grant struct {
	Subject  string
	Audience string
	Accounts []string
	Scopes   []string
	Expires  time.Time
}

func Open(ctx context.Context, db *sql.DB, audience string) (*Store, error) {
	if db == nil || audience == "" {
		return nil, errors.New("database and audience required")
	}
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS mcp_grants (token_hash BLOB PRIMARY KEY, subject TEXT NOT NULL, audience TEXT NOT NULL, accounts TEXT NOT NULL, scopes TEXT NOT NULL, expires TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)`)
	if err != nil {
		return nil, err
	}
	return &Store{db, audience}, nil
}

// Put stores an already-issued high-entropy opaque token as a one-way hash.
func (s *Store) Put(ctx context.Context, token string, g Grant) error {
	if len(token) < 32 || g.Subject == "" || g.Audience != s.audience || len(g.Accounts) == 0 || len(g.Scopes) == 0 || !g.Expires.After(time.Now()) {
		return errors.New("invalid grant")
	}
	for _, a := range g.Accounts {
		if a == "" {
			return errors.New("invalid account")
		}
	}
	for _, scope := range g.Scopes {
		if scope == "" {
			return errors.New("invalid scope")
		}
	}
	accounts, err := json.Marshal(g.Accounts)
	if err != nil {
		return err
	}
	scopes, err := json.Marshal(g.Scopes)
	if err != nil {
		return err
	}
	hash := sha256.Sum256([]byte(token))
	_, err = s.db.ExecContext(ctx, `INSERT INTO mcp_grants(token_hash,subject,audience,accounts,scopes,expires) VALUES(?,?,?,?,?,?)`, hash[:], g.Subject, g.Audience, string(accounts), string(scopes), g.Expires.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) Revoke(ctx context.Context, token string) error {
	h := sha256.Sum256([]byte(token))
	_, err := s.db.ExecContext(ctx, `UPDATE mcp_grants SET revoked=1 WHERE token_hash=?`, h[:])
	return err
}

// Verify is compatible with the SDK middleware and fails closed for malformed,
// expired, revoked, or wrong-audience tokens.
func (s *Store) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if len(token) < 32 {
		return nil, auth.ErrInvalidToken
	}
	h := sha256.Sum256([]byte(token))
	var subject, audience, accounts, scopes, expires string
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT subject,audience,accounts,scopes,expires,revoked FROM mcp_grants WHERE token_hash=?`, h[:]).Scan(&subject, &audience, &accounts, &scopes, &expires, &revoked)
	if err != nil || revoked != 0 || audience != s.audience || subject == "" {
		return nil, auth.ErrInvalidToken
	}
	expiry, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !expiry.After(time.Now()) {
		return nil, auth.ErrInvalidToken
	}
	var aa, ss []string
	if json.Unmarshal([]byte(accounts), &aa) != nil || json.Unmarshal([]byte(scopes), &ss) != nil || len(aa) == 0 || len(ss) == 0 {
		return nil, auth.ErrInvalidToken
	}
	for _, value := range append(aa, ss...) {
		if value == "" {
			return nil, auth.ErrInvalidToken
		}
	}
	return &auth.TokenInfo{UserID: subject, Expiration: expiry, Scopes: ss, Extra: map[string]any{"accounts": aa}}, nil
}

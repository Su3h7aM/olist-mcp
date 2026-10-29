// Package clientregistry stores OAuth clients that may request MCP access.
//
// This is storage only. A client is unapproved when created, and nothing in
// this package approves it automatically. The registry holds no secrets and no
// tokens. It lives in its own SQLite file, separate from the mirror and from
// the token store.
package clientregistry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound  = errors.New("client not found")
	ErrDuplicate = errors.New("client already registered")
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

const (
	maxRedirects  = 16
	maxRedirectLn = 2048
)

// Client is a registered OAuth client. RedirectURIs is matched exactly.
type Client struct {
	ID           string
	RedirectURIs []string
	CreatedAt    time.Time
	Approved     bool
}

// Registry is safe for concurrent use. A single connection serializes all
// statements, so every check-and-write runs as one transaction.
type Registry struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens or creates the registry database at path. path must be absolute.
// The file is created with mode 0600 if it does not exist.
func Open(ctx context.Context, path string) (*Registry, error) {
	return openWithClock(ctx, path, time.Now)
}

func openWithClock(ctx context.Context, path string, now func() time.Time) (*Registry, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("registry database path must be absolute")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	schema := `CREATE TABLE IF NOT EXISTS oauth_clients (
		client_id TEXT PRIMARY KEY,
		redirect_uris TEXT NOT NULL,
		created_at TEXT NOT NULL,
		approved INTEGER NOT NULL DEFAULT 0 CHECK (approved IN (0, 1))
	)`
	if _, err = db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Registry{db: db, now: now}, nil
}

// Close releases the database.
func (r *Registry) Close() error { return r.db.Close() }

// Count returns the number of registered clients, including pending clients.
func (r *Registry) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&count)
	return count, err
}

// Create registers a client that is not yet approved. The client ID must be
// 1 to 128 characters of ASCII letters, digits, dot, underscore or hyphen. The
// redirect list must be non-empty, and each entry must be an absolute URI with
// no fragment: https, or http on a loopback host. Duplicate entries are rejected.
func (r *Registry) Create(ctx context.Context, id string, redirectURIs []string) (Client, error) {
	if !idPattern.MatchString(id) {
		return Client{}, errors.New("client ID must be 1 to 128 ASCII letters, digits, dot, underscore or hyphen")
	}
	if err := validateRedirects(redirectURIs); err != nil {
		return Client{}, err
	}
	encoded, err := json.Marshal(redirectURIs)
	if err != nil {
		return Client{}, err
	}
	created := r.now().UTC()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Client{}, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM oauth_clients WHERE client_id=?`, id).Scan(&exists); err != nil {
		return Client{}, err
	}
	if exists != 0 {
		return Client{}, ErrDuplicate
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO oauth_clients(client_id,redirect_uris,created_at,approved) VALUES(?,?,?,0)`,
		id, string(encoded), created.Format(time.RFC3339Nano)); err != nil {
		return Client{}, err
	}
	if err = tx.Commit(); err != nil {
		return Client{}, err
	}
	return Client{ID: id, RedirectURIs: append([]string(nil), redirectURIs...), CreatedAt: created}, nil
}

// Get returns the client with the given ID, or ErrNotFound.
func (r *Registry) Get(ctx context.Context, id string) (Client, error) {
	if id == "" {
		return Client{}, ErrNotFound
	}
	var c Client
	var encoded, created string
	var approved int
	err := r.db.QueryRowContext(ctx, `SELECT client_id,redirect_uris,created_at,approved FROM oauth_clients WHERE client_id=?`, id).
		Scan(&c.ID, &encoded, &created, &approved)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	if err = json.Unmarshal([]byte(encoded), &c.RedirectURIs); err != nil {
		return Client{}, fmt.Errorf("stored redirect list is invalid: %w", err)
	}
	c.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return Client{}, fmt.Errorf("stored creation time is invalid: %w", err)
	}
	c.Approved = approved == 1
	return c, nil
}

// Approve marks a client as approved. Approving an approved client is a no-op.
// It returns ErrNotFound when the client does not exist.
func (r *Registry) Approve(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE oauth_clients SET approved=1 WHERE client_id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func validateRedirects(uris []string) error {
	if len(uris) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	if len(uris) > maxRedirects {
		return fmt.Errorf("at most %d redirect URIs are allowed", maxRedirects)
	}
	seen := make(map[string]bool, len(uris))
	for _, raw := range uris {
		if raw == "" || len(raw) > maxRedirectLn {
			return errors.New("redirect URI is empty or too long")
		}
		if seen[raw] {
			return errors.New("duplicate redirect URI")
		}
		seen[raw] = true
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil {
			return errors.New("redirect URI must be an absolute URI without fragment or user information")
		}
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && isLoopback(u.Hostname()):
		default:
			return errors.New("redirect URI must use https, or http on a loopback host")
		}
	}
	return nil
}

func isLoopback(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// Package store implements the account-scoped local mirror.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbot/olist-mcp/migrations"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }
type Record struct {
	AccountID  string
	Resource   string
	RemoteID   string
	Payload    json.RawMessage
	ObservedAt time.Time
}

func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One physical connection ensures foreign keys and serializes writes.
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	if _, err = db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fail(err)
	}
	if _, err = db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return fail(err)
	}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version > 1 {
		return fail(fmt.Errorf("unsupported database version %d", version))
	}
	if version == 0 {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return fail(e)
		}
		if _, e = tx.ExecContext(ctx, migrations.Initial); e == nil {
			_, e = tx.ExecContext(ctx, "PRAGMA user_version=1")
		}
		if e != nil {
			tx.Rollback()
			return fail(e)
		}
		if e = tx.Commit(); e != nil {
			return fail(e)
		}
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) PutAccount(ctx context.Context, id, name string) error {
	if id == "" || name == "" {
		return fmt.Errorf("account id and name are required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO accounts(id,display_name) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name`, id, name)
	return err
}
func (s *Store) Put(ctx context.Context, r Record) error {
	if r.AccountID == "" || r.Resource == "" || r.RemoteID == "" || !json.Valid(r.Payload) || r.ObservedAt.IsZero() {
		return fmt.Errorf("invalid record")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO records(account_id,resource,remote_id,payload,observed_at) VALUES(?,?,?,?,?) ON CONFLICT(account_id,resource,remote_id) DO UPDATE SET payload=excluded.payload, observed_at=excluded.observed_at, deleted_at=NULL`, r.AccountID, r.Resource, r.RemoteID, string(r.Payload), r.ObservedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) Get(ctx context.Context, account, resource, id string) (Record, error) {
	var r Record
	var payload, observed string
	err := s.db.QueryRowContext(ctx, `SELECT account_id,resource,remote_id,payload,observed_at FROM records WHERE account_id=? AND resource=? AND remote_id=? AND deleted_at IS NULL`, account, resource, id).Scan(&r.AccountID, &r.Resource, &r.RemoteID, &payload, &observed)
	if err != nil {
		return r, err
	}
	r.Payload = json.RawMessage(payload)
	r.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
	return r, err
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Status is the sync state stored for one account and resource. The values
// match the CHECK constraint in migrations/001_mirror.sql.
type Status string

const (
	StatusPending       Status = "pending"
	StatusPartial       Status = "partial"
	StatusComplete      Status = "complete"
	StatusError         Status = "error"
	StatusNotApplicable Status = "not_applicable"
)

var validStatuses = map[Status]bool{
	StatusPending: true, StatusPartial: true, StatusComplete: true,
	StatusError: true, StatusNotApplicable: true,
}

// ErrNoCoverage is returned when no coverage row exists for an account and resource.
var ErrNoCoverage = errors.New("no sync coverage recorded")

// Coverage describes how far one account's resource has been mirrored.
type Coverage struct {
	AccountID string
	Resource  string
	SyncClass string
	Status    Status
	// LastSuccessAt is the end of the last complete run. Zero means never.
	LastSuccessAt time.Time
	// Cursor is an opaque resume position. Empty means none.
	Cursor string
}

// UpsertCoverage writes the coverage row for an account and resource. The
// account must already exist; the foreign key enforces this.
//
// Only a complete status can advance LastSuccessAt, and it must be set when
// the status is complete. For any other status the stored LastSuccessAt is
// kept, so a partial or failed run never looks like a successful one.
func (s *Store) UpsertCoverage(ctx context.Context, c Coverage) error {
	if err := validateCoverage(c); err != nil {
		return err
	}
	var lastSuccess any
	if c.Status == StatusComplete {
		lastSuccess = c.LastSuccessAt.UTC().Format(time.RFC3339Nano)
	}
	var cursor any
	if c.Cursor != "" {
		cursor = c.Cursor
	}
	// The store has one connection, so this statement is serialized with other writes.
	_, err := s.db.ExecContext(ctx, `INSERT INTO sync_coverage(account_id,resource,sync_class,status,last_success_at,cursor)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(account_id,resource) DO UPDATE SET sync_class=excluded.sync_class, status=excluded.status,
		last_success_at=CASE WHEN excluded.status='complete' THEN excluded.last_success_at ELSE sync_coverage.last_success_at END,
		cursor=excluded.cursor`,
		c.AccountID, c.Resource, c.SyncClass, string(c.Status), lastSuccess, cursor)
	return err
}

// GetCoverage returns the coverage row for an account and resource. It returns
// ErrNoCoverage when none exists.
func (s *Store) GetCoverage(ctx context.Context, account, resource string) (Coverage, error) {
	if strings.TrimSpace(account) == "" || strings.TrimSpace(resource) == "" {
		return Coverage{}, errors.New("account and resource are required")
	}
	var c Coverage
	var status string
	var lastSuccess, cursor sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT account_id,resource,sync_class,status,last_success_at,cursor
		FROM sync_coverage WHERE account_id=? AND resource=?`, account, resource).
		Scan(&c.AccountID, &c.Resource, &c.SyncClass, &status, &lastSuccess, &cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return Coverage{}, ErrNoCoverage
	}
	if err != nil {
		return Coverage{}, err
	}
	c.Status = Status(status)
	if lastSuccess.Valid {
		c.LastSuccessAt, err = time.Parse(time.RFC3339Nano, lastSuccess.String)
		if err != nil {
			return Coverage{}, fmt.Errorf("invalid stored last success time: %w", err)
		}
	}
	c.Cursor = cursor.String
	return c, nil
}

func validateCoverage(c Coverage) error {
	switch {
	case strings.TrimSpace(c.AccountID) == "":
		return errors.New("account is required")
	case strings.TrimSpace(c.Resource) == "":
		return errors.New("resource is required")
	case strings.TrimSpace(c.SyncClass) == "":
		return errors.New("sync class is required")
	case !validStatuses[c.Status]:
		return fmt.Errorf("invalid sync status %q", c.Status)
	case c.Status == StatusComplete && c.LastSuccessAt.IsZero():
		return errors.New("complete coverage requires a last success time")
	}
	return nil
}

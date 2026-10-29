package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutUpsertSameIDStaysInAccount(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), "mirror.db"))
	defer s.Close()

	for _, a := range []string{"a", "b"} {
		if err := s.PutAccount(ctx, a, a); err != nil {
			t.Fatal(err)
		}
	}
	first := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	second := time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC)
	for _, r := range []Record{
		{"a", "produtos", "1", json.RawMessage(`{"nome":"A v1"}`), first},
		{"b", "produtos", "1", json.RawMessage(`{"nome":"B v1"}`), first},
	} {
		if err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	// Same account and ID: must update in place, not add a row or touch account b.
	if err := s.Put(ctx, Record{"a", "produtos", "1", json.RawMessage(`{"nome":"A v2"}`), second}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "a", "produtos", "1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Payload) != `{"nome":"A v2"}` {
		t.Fatalf("account a payload = %s, want updated value", got.Payload)
	}
	if !got.ObservedAt.Equal(second) {
		t.Fatalf("account a observed_at = %v, want %v", got.ObservedAt, second)
	}

	other, err := s.Get(ctx, "b", "produtos", "1")
	if err != nil {
		t.Fatal(err)
	}
	if string(other.Payload) != `{"nome":"B v1"}` || !other.ObservedAt.Equal(first) {
		t.Fatalf("account b changed after upsert in a: payload=%s observed_at=%v", other.Payload, other.ObservedAt)
	}

	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM records WHERE resource='produtos' AND remote_id='1'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("rows for remote id 1 = %d, want 2 (one per account)", rows)
	}
}

func TestPutUpsertRevivesDeletedRecord(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), "mirror.db"))
	defer s.Close()

	if err := s.PutAccount(ctx, "a", "a"); err != nil {
		t.Fatal(err)
	}
	rec := Record{"a", "produtos", "1", json.RawMessage(`{}`), time.Now()}
	if err := s.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE records SET deleted_at='2026-10-03T00:00:00Z' WHERE account_id='a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a", "produtos", "1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("deleted record readable via Get: %v", err)
	}

	if err := s.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "a", "produtos", "1"); err != nil {
		t.Fatalf("upsert did not clear deleted_at: %v", err)
	}
}

func TestPutRejectsInvalidRecords(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), "mirror.db"))
	defer s.Close()

	if err := s.PutAccount(ctx, "a", "a"); err != nil {
		t.Fatal(err)
	}
	valid := func() Record {
		return Record{"a", "produtos", "1", json.RawMessage(`{"ok":true}`), time.Now()}
	}

	cases := map[string]func(r *Record){
		"empty account id": func(r *Record) { r.AccountID = "" },
		"empty resource":   func(r *Record) { r.Resource = "" },
		"empty remote id":  func(r *Record) { r.RemoteID = "" },
		"zero observed at": func(r *Record) { r.ObservedAt = time.Time{} },
		"nil payload":      func(r *Record) { r.Payload = nil },
		"empty payload":    func(r *Record) { r.Payload = json.RawMessage(``) },
		"truncated json":   func(r *Record) { r.Payload = json.RawMessage(`{"nome":`) },
		"bare word":        func(r *Record) { r.Payload = json.RawMessage(`abc`) },
		"trailing garbage": func(r *Record) { r.Payload = json.RawMessage(`{} {}`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := valid()
			mutate(&r)
			if err := s.Put(ctx, r); err == nil {
				t.Fatal("Put accepted invalid record")
			}
		})
	}

	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM records`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("rejected records were stored: %d rows", rows)
	}
}

func TestDataSurvivesReopenAfterUpsert(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mirror.db")
	observed := time.Date(2026, 10, 5, 8, 0, 0, 123456789, time.UTC)

	s := openTestStore(t, path)
	if err := s.PutAccount(ctx, "a", "Conta A"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, Record{"a", "produtos", "1", json.RawMessage(`{"v":1}`), time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, Record{"a", "produtos", "1", json.RawMessage(`{"v":2}`), observed}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openTestStore(t, path)
	defer s.Close()
	got, err := s.Get(ctx, "a", "produtos", "1")
	if err != nil {
		t.Fatalf("record missing after reopen: %v", err)
	}
	if string(got.Payload) != `{"v":2}` {
		t.Fatalf("payload after reopen = %s, want upserted value", got.Payload)
	}
	if !got.ObservedAt.Equal(observed) {
		t.Fatalf("observed_at after reopen = %v, want %v", got.ObservedAt, observed)
	}

	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT display_name FROM accounts WHERE id='a'`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "Conta A" {
		t.Fatalf("account name after reopen = %q", name)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("user_version after reopen = %d, want 1", version)
	}
}

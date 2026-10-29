package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreAccountIsolationAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mirror.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"a", "b"} {
		if err = s.PutAccount(ctx, a, a); err != nil {
			t.Fatal(err)
		}
		if err = s.Put(ctx, Record{a, "produtos", "1", []byte(`{"account":"` + a + `"}`), time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.Get(ctx, "b", "produtos", "1")
	if err != nil || string(r.Payload) != `{"account":"b"}` {
		t.Fatalf("%s %v", r.Payload, err)
	}
	_, err = s.Get(ctx, "c", "produtos", "1")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected: %v", err)
	}
	if err = s.Put(ctx, Record{"missing", "produtos", "2", []byte(`{}`), time.Now()}); err == nil {
		t.Fatal("expected foreign key error")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.Get(ctx, "a", "produtos", "1"); err != nil {
		t.Fatal(err)
	}
}

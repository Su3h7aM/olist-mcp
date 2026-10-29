package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestListIsScopedAndBounded(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, a := range []string{"a", "b"} {
		if err = s.PutAccount(ctx, a, a); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"1", "2"} {
			if err = s.Put(ctx, Record{a, "produtos", id, []byte(`{}`), time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	r, err := s.List(ctx, "a", "produtos", 1, 1)
	if err != nil || len(r) != 1 || r[0].AccountID != "a" || r[0].RemoteID != "2" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err = s.List(ctx, "a", "produtos", 1001, 0); err == nil {
		t.Fatal("accepted excessive limit")
	}
	r, err = s.List(ctx, "c", "produtos", 10, 0)
	if err != nil || len(r) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

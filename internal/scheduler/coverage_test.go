package scheduler

import (
	"context"
	"errors"
	"github.com/openbot/olist-mcp/internal/store"
	"path/filepath"
	"testing"
)

func TestTrackedJobRecordsFailureAndSuccess(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.PutAccount(ctx, "a", "A"); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("sync failed")
	job, err := TrackedJob("a", "produtos", "full-refresh", db, func(context.Context) error { return failure })
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(job.Run(ctx), failure) {
		t.Fatal("failure lost")
	}
	row, err := db.GetCoverage(ctx, "a", "produtos")
	if err != nil || row.Status != store.StatusError || !row.LastSuccessAt.IsZero() {
		t.Fatalf("%+v %v", row, err)
	}
	job, _ = TrackedJob("a", "produtos", "full-refresh", db, func(context.Context) error { return nil })
	if err = job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	row, err = db.GetCoverage(ctx, "a", "produtos")
	if err != nil || row.Status != store.StatusComplete || row.LastSuccessAt.IsZero() {
		t.Fatalf("%+v %v", row, err)
	}
}

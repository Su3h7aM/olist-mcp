package scheduler

import (
	"context"
	"errors"
	"time"

	"github.com/openbot/olist-mcp/internal/store"
)

type CoverageStore interface {
	UpsertCoverage(context.Context, store.Coverage) error
}

// TrackedJob records partial before running and complete only after a clean
// return. On failure, it retains the last successful time and records error.
func TrackedJob(account, resource, class string, db CoverageStore, run func(context.Context) error) (Job, error) {
	if account == "" || resource == "" || class == "" || db == nil || run == nil {
		return Job{}, errors.New("account, resource, class, store and job are required")
	}
	return Job{Name: resource, Run: func(ctx context.Context) error {
		row := store.Coverage{AccountID: account, Resource: resource, SyncClass: class, Status: store.StatusPartial}
		if err := db.UpsertCoverage(ctx, row); err != nil {
			return err
		}
		runErr := run(ctx)
		// Preserve the outcome on shutdown, but do not wait indefinitely for SQLite.
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if runErr != nil {
			row.Status = store.StatusError
		} else {
			row.Status = store.StatusComplete
			row.LastSuccessAt = time.Now().UTC()
		}
		return errors.Join(runErr, db.UpsertCoverage(saveCtx, row))
	}}, nil
}

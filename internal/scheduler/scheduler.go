// Package scheduler runs one account's mirror jobs sequentially.
package scheduler

import (
	"context"
	"errors"
	"time"
)

type Job struct {
	Name string
	Run  func(context.Context) error
}
type Result struct {
	Name       string
	StartedAt  time.Time
	FinishedAt time.Time
	Err        error
}
type Reporter func(Result)

// Run executes each configured job once per cycle, with no overlapping cycles.
// Individual failures are reported and do not prevent unrelated jobs running.
// The interval starts after a cycle finishes, avoiding unbounded retries.
func Run(ctx context.Context, interval time.Duration, jobs []Job, report Reporter) error {
	if interval <= 0 || len(jobs) == 0 || report == nil {
		return errors.New("positive interval, jobs and reporter required")
	}
	for _, j := range jobs {
		if j.Name == "" || j.Run == nil {
			return errors.New("each job requires a name and function")
		}
	}
	for {
		for _, job := range jobs {
			if err := ctx.Err(); err != nil {
				return err
			}
			start := time.Now().UTC()
			err := job.Run(ctx)
			report(Result{Name: job.Name, StartedAt: start, FinishedAt: time.Now().UTC(), Err: err})
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

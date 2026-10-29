package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunReportsFailuresAndContinues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var names []string
	problem := errors.New("failed")
	jobs := []Job{{"first", func(context.Context) error { return problem }}, {"second", func(context.Context) error { return nil }}}
	err := Run(ctx, time.Hour, jobs, func(r Result) {
		names = append(names, r.Name)
		if r.Name == "first" && !errors.Is(r.Err, problem) {
			t.Error("failure not reported")
		}
		if r.FinishedAt.Before(r.StartedAt) {
			t.Error("invalid times")
		}
		if r.Name == "second" {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) || len(names) != 2 {
		t.Fatalf("names %v err %v", names, err)
	}
}
func TestInvalidConfiguration(t *testing.T) {
	if err := Run(context.Background(), 0, nil, nil); err == nil {
		t.Fatal("invalid configuration accepted")
	}
}

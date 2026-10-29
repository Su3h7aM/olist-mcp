// Package ratelimit provides a local sliding-window read budget for one
// Olist account.
//
// Each Limiter belongs to exactly one account; callers create one per
// account. The limiter performs no network calls and keeps no goroutines.
// State lives in memory only, so a restart begins with an empty window.
// Olist's quota is shared with other apps on the same account, which this
// limiter cannot see, so it bounds only this process's reads.
package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const window = time.Minute

// Limiter enforces at most readsPerMinute reads in any 60-second window.
// Background reads may use only readsPerMinute minus the reserved share;
// on-demand reads may use the full budget.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	reserve int
	clock   clock
	reads   []time.Time                       // grant times inside the current window, ascending
	onGrant func(at time.Time, onDemand bool) // test hook; nil in production
}

// New creates a limiter for one account. The reserved share is
// reservedPercent of readsPerMinute, rounded up, so the background budget
// is never larger than the configured percentage allows.
func New(readsPerMinute int, reservedPercent int) (*Limiter, error) {
	return newLimiter(readsPerMinute, reservedPercent, realClock{})
}

func newLimiter(readsPerMinute, reservedPercent int, c clock) (*Limiter, error) {
	if readsPerMinute <= 0 {
		return nil, fmt.Errorf("readsPerMinute must be positive, got %d", readsPerMinute)
	}
	if reservedPercent < 0 || reservedPercent > 100 {
		return nil, fmt.Errorf("reservedPercent must be between 0 and 100, got %d", reservedPercent)
	}
	reserve := (readsPerMinute*reservedPercent + 99) / 100
	if readsPerMinute-reserve < 1 {
		return nil, fmt.Errorf("reservedPercent %d leaves no background capacity for %d reads per minute", reservedPercent, readsPerMinute)
	}
	return &Limiter{limit: readsPerMinute, reserve: reserve, clock: c}, nil
}

// Wait blocks until a read may proceed under the budget, then records it.
// Background reads (onDemand false) wait while the window holds the
// reserved share. It returns ctx.Err() if ctx ends first; a cancelled wait
// consumes no budget.
func (l *Limiter) Wait(ctx context.Context, onDemand bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for {
		l.mu.Lock()
		now := l.clock.now()
		l.prune(now)
		capacity := l.limit
		if !onDemand {
			capacity -= l.reserve
		}
		if len(l.reads) < capacity {
			l.reads = append(l.reads, now)
			if l.onGrant != nil {
				l.onGrant(now, onDemand)
			}
			l.mu.Unlock()
			return nil
		}
		// Full at this threshold: a slot opens once the grant at index
		// len-capacity leaves the window.
		wait := l.reads[len(l.reads)-capacity].Add(window).Sub(now)
		l.mu.Unlock()

		if err := l.clock.wait(ctx, wait); err != nil {
			return err
		}
	}
}

// prune drops grants at or before now-window. Caller must hold l.mu.
func (l *Limiter) prune(now time.Time) {
	cutoff := now.Add(-window)
	i := 0
	for i < len(l.reads) && !l.reads[i].After(cutoff) {
		i++
	}
	if i > 0 {
		l.reads = append(l.reads[:0], l.reads[i:]...)
	}
}

type clock interface {
	now() time.Time
	wait(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) now() time.Time { return time.Now() }

func (realClock) wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

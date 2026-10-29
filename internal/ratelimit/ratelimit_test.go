package ratelimit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock moves time forward only when Wait sleeps, so tests never
// wait for a real minute.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	waits []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	c.t = c.t.Add(d)
	return nil
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) waitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waits)
}

func mustLimiter(t *testing.T, reads, reserved int, c clock) *Limiter {
	t.Helper()
	l, err := newLimiter(reads, reserved, c)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNewValidatesParameters(t *testing.T) {
	invalid := []struct{ reads, reserved int }{
		{0, 0},
		{-1, 0},
		{30, -1},
		{30, 101},
		{1, 100},
		{1, 99}, // ceil(0.99) = 1 reserved leaves no background capacity
	}
	for _, c := range invalid {
		if _, err := New(c.reads, c.reserved); err == nil {
			t.Errorf("New(%d, %d) accepted invalid parameters", c.reads, c.reserved)
		}
	}
	valid := []struct{ reads, reserved int }{
		{30, 0},
		{30, 20},
		{1, 0},
		{140, 99}, // reserve 139, one background slot left
	}
	for _, c := range valid {
		if _, err := New(c.reads, c.reserved); err != nil {
			t.Errorf("New(%d, %d): %v", c.reads, c.reserved, err)
		}
	}
}

func TestWindowNeverExceedsLimit(t *testing.T) {
	clock := newFakeClock()
	l := mustLimiter(t, 3, 0, clock)
	ctx := context.Background()

	// Grants at 0s, 20s and 40s fill the window.
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx, true); err != nil {
			t.Fatal(err)
		}
		clock.advance(20 * time.Second)
	}
	// At 60s the first grant (at 0s) has just left the window; the fourth
	// read may proceed immediately.
	if err := l.Wait(ctx, true); err != nil {
		t.Fatal(err)
	}
	if clock.waitCount() != 0 {
		t.Fatalf("waited %d times before window was full", clock.waitCount())
	}
	// Window now holds grants at 20s, 40s and 60s; the next read has to
	// wait until the grant at 20s expires, i.e. 20s more.
	if err := l.Wait(ctx, true); err != nil {
		t.Fatal(err)
	}
	if len(clock.waits) != 1 || clock.waits[0] != 20*time.Second {
		t.Fatalf("waits = %v, want [20s]", clock.waits)
	}
}

func TestWaitBlocksUntilSlotFrees(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	l := mustLimiter(t, 5, 0, clock)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := l.Wait(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Wait(ctx, true); err != nil {
		t.Fatal(err)
	}
	if got := clock.now().Sub(start); got != time.Minute {
		t.Fatalf("sixth read at +%v, want +1m", got)
	}
}

func TestBackgroundRespectsReserve(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	// 30% of 10 rounds up to 3 reserved, leaving 7 for background.
	l := mustLimiter(t, 10, 30, clock)
	ctx := context.Background()

	for i := 0; i < 7; i++ {
		if err := l.Wait(ctx, false); err != nil {
			t.Fatal(err)
		}
	}
	if clock.waitCount() != 0 {
		t.Fatalf("background waited while under its share: %v", clock.waits)
	}

	// On-demand reads use the reserved share without waiting.
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	if clock.waitCount() != 0 {
		t.Fatalf("on-demand waited while reserve was available: %v", clock.waits)
	}

	// The window is now full for both kinds; the eighth background read
	// must wait for the first grant to expire.
	if err := l.Wait(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := clock.now().Sub(start); got != time.Minute {
		t.Fatalf("background read at +%v, want +1m", got)
	}
}

func TestOnDemandCanUseWholeBudget(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	l := mustLimiter(t, 10, 30, clock)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := l.Wait(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	if clock.waitCount() != 0 {
		t.Fatalf("on-demand waited before budget was used: %v", clock.waits)
	}
	// Background is blocked by the full window, not by its own share.
	if err := l.Wait(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := clock.now().Sub(start); got != time.Minute {
		t.Fatalf("background read at +%v, want +1m", got)
	}
}

func TestInstancesAreIsolated(t *testing.T) {
	clock := newFakeClock()
	a := mustLimiter(t, 2, 0, clock)
	b := mustLimiter(t, 2, 0, clock)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := a.Wait(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	// A is exhausted; B must still grant without waiting.
	before := clock.waitCount()
	for i := 0; i < 2; i++ {
		if err := b.Wait(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	if clock.waitCount() != before {
		t.Fatal("account B waited because account A used its budget")
	}
}

func TestCancelledContextConsumesNoBudget(t *testing.T) {
	clock := newFakeClock()
	l := mustLimiter(t, 1, 0, clock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait with cancelled ctx = %v, want context.Canceled", err)
	}
	if len(l.reads) != 0 {
		t.Fatalf("cancelled wait recorded %d reads", len(l.reads))
	}
	if err := l.Wait(context.Background(), true); err != nil {
		t.Fatal(err)
	}
}

func TestCancelDuringWaitReturnsPromptly(t *testing.T) {
	// Real clock: a second read must wait a full minute, so cancellation
	// has to end it long before that.
	l, err := New(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Wait(context.Background(), true); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	began := time.Now()
	err = l.Wait(ctx, true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(began); elapsed > 5*time.Second {
		t.Fatalf("cancelled wait took %v", elapsed)
	}
	if len(l.reads) != 1 {
		t.Fatalf("cancelled wait changed budget: %d reads recorded", len(l.reads))
	}
}

func TestConcurrentWaitsRespectWindowAndReserve(t *testing.T) {
	clock := newFakeClock()
	const limit, reserve = 20, 5 // 25% of 20; background capacity 15
	l := mustLimiter(t, limit, 25, clock)

	type grant struct {
		at       time.Time
		onDemand bool
	}
	var mu sync.Mutex
	var grants []grant
	l.onGrant = func(at time.Time, onDemand bool) {
		mu.Lock()
		defer mu.Unlock()
		grants = append(grants, grant{at, onDemand})
	}

	const workers = 300
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(onDemand bool) {
			defer wg.Done()
			errs <- l.Wait(context.Background(), onDemand)
		}(i%3 == 0)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(grants) != workers {
		t.Fatalf("granted %d reads, want %d", len(grants), workers)
	}

	// Each grant must see at most the allowed count in the 60s ending at it.
	for i, g := range grants {
		inWindow, bgInWindow := 0, 0
		for _, o := range grants[:i+1] {
			if g.at.Sub(o.at) < time.Minute {
				inWindow++
				if !o.onDemand {
					bgInWindow++
				}
			}
		}
		if inWindow > limit {
			t.Fatalf("grant %d: %d reads in 60s, limit %d", i, inWindow, limit)
		}
		if !g.onDemand && inWindow > limit-reserve {
			t.Fatalf("grant %d: background read used reserved share (%d in window)", i, inWindow)
		}
	}
}

package oauthstate

import (
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is advanced explicitly by tests; it is safe for concurrent reads.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestRegistry(t *testing.T, ttl time.Duration, capacity int) (*Registry, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)}
	r, err := newRegistry(ttl, capacity, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	return r, clock
}

func TestNewRejectsInvalidParameters(t *testing.T) {
	cases := []struct {
		name     string
		ttl      time.Duration
		capacity int
	}{
		{"zero ttl", 0, 10},
		{"negative ttl", -time.Second, 10},
		{"zero capacity", time.Minute, 0},
		{"negative capacity", time.Minute, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.ttl, tc.capacity); err == nil {
				t.Fatal("invalid parameters accepted")
			}
		})
	}
	if _, err := New(time.Minute, 10); err != nil {
		t.Fatal(err)
	}
}

func TestIssueRejectsEmptyOwnerOrAccount(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	if _, err := r.Issue("", "acc"); err == nil {
		t.Fatal("empty owner accepted")
	}
	if _, err := r.Issue("owner", ""); err == nil {
		t.Fatal("empty account accepted")
	}
	if r.Len() != 0 {
		t.Fatal("rejected issue stored an entry")
	}
}

func TestStateFormatAndUniqueness(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 5000)
	seen := make(map[string]bool, 2000)
	for i := 0; i < 2000; i++ {
		state, err := r.Issue("owner", "acc")
		if err != nil {
			t.Fatal(err)
		}
		if seen[state] {
			t.Fatal("duplicate state issued")
		}
		seen[state] = true
		raw, err := base64.RawURLEncoding.DecodeString(state)
		if err != nil {
			t.Fatalf("state is not unpadded URL-safe base64: %v", err)
		}
		if len(raw) != stateBytes {
			t.Fatalf("state decodes to %d bytes, want %d", len(raw), stateBytes)
		}
		if strings.ContainsAny(state, "+/=") {
			t.Fatal("state contains characters that are not URL-safe")
		}
	}
}

func TestConsumeReturnsBoundAccount(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	state, err := r.Issue("owner-1", "acc-7")
	if err != nil {
		t.Fatal(err)
	}
	account, err := r.Consume(state, "owner-1")
	if err != nil || account != "acc-7" {
		t.Fatalf("Consume = %q, %v; want acc-7", account, err)
	}
}

func TestReplayIsRejected(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	state, _ := r.Issue("owner", "acc")
	if _, err := r.Consume(state, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Consume(state, "owner"); err == nil {
		t.Fatal("state consumed twice")
	}
}

func TestWrongOwnerDoesNotConsume(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	state, _ := r.Issue("owner", "acc")

	if _, err := r.Consume(state, "intruder"); err == nil {
		t.Fatal("wrong owner consumed the state")
	}
	// The rightful owner can still use it afterwards.
	account, err := r.Consume(state, "owner")
	if err != nil || account != "acc" {
		t.Fatalf("rightful owner rejected after wrong-owner attempt: %v", err)
	}
}

func TestOwnerComparisonIsExact(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	state, _ := r.Issue("Owner", "acc")
	for _, wrong := range []string{"owner", "Owner ", "Owner\x00", "Owne"} {
		if _, err := r.Consume(state, wrong); err == nil {
			t.Fatalf("owner %q matched", wrong)
		}
	}
	if _, err := r.Consume(state, "Owner"); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownAndEmptyStatesRejected(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	if _, err := r.Consume("not-issued", "owner"); err == nil {
		t.Fatal("unknown state accepted")
	}
	if _, err := r.Consume("", "owner"); err == nil {
		t.Fatal("empty state accepted")
	}
	state, _ := r.Issue("owner", "acc")
	if _, err := r.Consume(state, ""); err == nil {
		t.Fatal("empty owner accepted")
	}
}

func TestStateExpiresAtTTL(t *testing.T) {
	ttl := 10 * time.Minute
	r, clock := newTestRegistry(t, ttl, 10)
	state, _ := r.Issue("owner", "acc")

	clock.advance(ttl - time.Nanosecond)
	if _, err := r.Consume(state, "owner"); err != nil {
		t.Fatalf("state rejected one nanosecond before expiry: %v", err)
	}

	expired, _ := r.Issue("owner", "acc")
	clock.advance(ttl)
	if _, err := r.Consume(expired, "owner"); err == nil {
		t.Fatal("state accepted at its expiry time")
	}
}

func TestExpiredStateIsRemovedOnConsume(t *testing.T) {
	ttl := time.Minute
	r, clock := newTestRegistry(t, ttl, 10)
	state, _ := r.Issue("owner", "acc")
	clock.advance(ttl)
	if _, err := r.Consume(state, "owner"); err == nil {
		t.Fatal("expired state accepted")
	}
	if r.Len() != 0 {
		t.Fatalf("expired state left in registry: %d entries", r.Len())
	}
}

func TestCapacityRejectsWhenFullOfLiveStates(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 3)
	states := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		s, err := r.Issue("owner", "acc")
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, s)
	}
	if _, err := r.Issue("owner", "acc"); err == nil {
		t.Fatal("issued beyond capacity")
	}
	// Live states are never evicted to make room.
	for _, s := range states {
		if _, err := r.Consume(s, "owner"); err != nil {
			t.Fatalf("live state evicted: %v", err)
		}
	}
}

func TestConsumingFreesCapacity(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 1)
	state, _ := r.Issue("owner", "acc")
	if _, err := r.Issue("owner", "acc"); err == nil {
		t.Fatal("second issue accepted at capacity")
	}
	if _, err := r.Consume(state, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Issue("owner", "acc"); err != nil {
		t.Fatalf("capacity not freed after consume: %v", err)
	}
}

func TestExpiredEntriesCleanedOnIssue(t *testing.T) {
	ttl := time.Minute
	r, clock := newTestRegistry(t, ttl, 2)
	if _, err := r.Issue("owner", "acc"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Issue("owner", "acc"); err != nil {
		t.Fatal(err)
	}
	clock.advance(ttl)
	// Both earlier states have expired, so the registry must accept new ones
	// and drop the old entries rather than count them against capacity.
	if _, err := r.Issue("owner", "acc"); err != nil {
		t.Fatalf("expired states still counted against capacity: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("registry holds %d entries, want 1 after cleanup", r.Len())
	}
}

func TestConcurrentConsumeSucceedsOnce(t *testing.T) {
	r, _ := newTestRegistry(t, time.Minute, 10)
	state, _ := r.Issue("owner", "acc")

	const workers = 200
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if account, err := r.Consume(state, "owner"); err == nil {
				if account != "acc" {
					t.Error("winner received the wrong account")
				}
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := wins.Load(); n != 1 {
		t.Fatalf("%d goroutines consumed the state; want exactly 1", n)
	}
}

func TestConcurrentIssueRespectsCapacity(t *testing.T) {
	const capacity = 25
	r, _ := newTestRegistry(t, time.Minute, capacity)

	var granted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Issue("owner", "acc"); err == nil {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := granted.Load(); n != capacity {
		t.Fatalf("granted %d states; want exactly capacity %d", n, capacity)
	}
	if r.Len() != capacity {
		t.Fatalf("registry holds %d entries; want %d", r.Len(), capacity)
	}
}

func TestErrorsDoNotContainState(t *testing.T) {
	r, clock := newTestRegistry(t, time.Minute, 10)
	state, _ := r.Issue("owner", "acc")

	checks := []func() error{
		func() error { _, err := r.Consume(state, "intruder"); return err },
	}
	for _, check := range checks {
		if err := check(); err != nil && strings.Contains(err.Error(), state) {
			t.Fatal("error message contains the OAuth state")
		}
	}
	clock.advance(time.Minute)
	if _, err := r.Consume(state, "owner"); err == nil || strings.Contains(err.Error(), state) {
		t.Fatalf("expired-state error missing or leaks state: %v", err)
	}
}

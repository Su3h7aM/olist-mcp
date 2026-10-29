package owner

import (
	"sync"
	"time"
)

// maxTrackedClients bounds per-client state. Clients beyond it are still counted
// by the global limit, so the table cannot be used to exhaust memory.
const maxTrackedClients = 4096

type bucket struct {
	failures    []time.Time
	lockedUntil time.Time
}

// throttle limits failed logins per client and globally. Once a limit is hit,
// logins are refused for the lockout period, even with the correct password.
type throttle struct {
	mu          sync.Mutex
	clientLimit int
	globalLimit int
	window      time.Duration
	lockout     time.Duration
	clients     map[string]*bucket
	global      bucket
}

func newThrottle(clientLimit, globalLimit int, window, lockout time.Duration) *throttle {
	return &throttle{
		clientLimit: clientLimit,
		globalLimit: globalLimit,
		window:      window,
		lockout:     lockout,
		clients:     make(map[string]*bucket),
	}
}

// allow reports whether a login may be attempted now. When it may not, retry
// is how long the caller must wait.
func (t *throttle) allow(client string, now time.Time) (ok bool, retry time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := t.global.lockedUntil.Sub(now); d > 0 {
		return false, d
	}
	if b, found := t.clients[client]; found {
		if d := b.lockedUntil.Sub(now); d > 0 {
			return false, d
		}
	}
	return true, 0
}

// failure records one failed login for client and globally.
func (t *throttle) failure(client string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record(&t.global, t.globalLimit, now)
	b, found := t.clients[client]
	if !found {
		if len(t.clients) >= maxTrackedClients {
			return
		}
		b = &bucket{}
		t.clients[client] = b
	}
	t.record(b, t.clientLimit, now)
}

// success clears the client's failure history. The global history is kept, so
// a correct password cannot reset a global lockout.
func (t *throttle) success(client string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.clients, client)
}

func (t *throttle) record(b *bucket, limit int, now time.Time) {
	cutoff := now.Add(-t.window)
	kept := b.failures[:0]
	for _, at := range b.failures {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	b.failures = append(kept, now)
	if len(b.failures) >= limit {
		b.lockedUntil = now.Add(t.lockout)
		b.failures = nil
	}
}

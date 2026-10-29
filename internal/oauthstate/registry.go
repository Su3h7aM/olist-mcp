// Package oauthstate issues and consumes single-use OAuth state values.
//
// A state is bound to the owner that started the flow and the Olist account
// it connects. Consume succeeds once, for the bound owner, before the state
// expires. Entries live in memory only; a restart invalidates them all.
package oauthstate

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const stateBytes = 32

type entry struct {
	ownerID   string
	accountID string
	expires   time.Time
}

// Registry is safe for concurrent use. It holds at most capacity live entries.
type Registry struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	now      func() time.Time
	entries  map[string]entry
}

// New returns a registry whose states expire after ttl and that holds at most
// capacity unconsumed states.
func New(ttl time.Duration, capacity int) (*Registry, error) {
	return newRegistry(ttl, capacity, time.Now)
}

func newRegistry(ttl time.Duration, capacity int, now func() time.Time) (*Registry, error) {
	if ttl <= 0 {
		return nil, errors.New("state TTL must be positive")
	}
	if capacity <= 0 {
		return nil, errors.New("state capacity must be positive")
	}
	return &Registry{ttl: ttl, capacity: capacity, now: now, entries: make(map[string]entry)}, nil
}

// Issue creates a new random state bound to ownerID and accountID. It returns
// an error when the registry is full of live states; it never evicts a live
// state to make room.
func (r *Registry) Issue(ownerID, accountID string) (string, error) {
	if ownerID == "" || accountID == "" {
		return "", errors.New("owner and account are required")
	}
	buf := make([]byte, stateBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("cannot generate OAuth state")
	}
	state := base64.RawURLEncoding.EncodeToString(buf)

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.purgeLocked(now)
	if len(r.entries) >= r.capacity {
		return "", errors.New("too many pending OAuth authorizations")
	}
	r.entries[state] = entry{ownerID: ownerID, accountID: accountID, expires: now.Add(r.ttl)}
	return state, nil
}

// Consume returns the account bound to state and removes the state, so it
// cannot be used again. A wrong owner is rejected and leaves the state in place
// for the rightful owner. An expired state is removed and rejected.
func (r *Registry) Consume(state, ownerID string) (string, error) {
	if state == "" || ownerID == "" {
		return "", errors.New("state and owner are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	e, ok := r.entries[state]
	if !ok {
		return "", errors.New("invalid or already used OAuth state")
	}
	if !now.Before(e.expires) {
		delete(r.entries, state)
		return "", errors.New("OAuth state expired")
	}
	if subtle.ConstantTimeCompare([]byte(e.ownerID), []byte(ownerID)) != 1 {
		return "", errors.New("OAuth state does not belong to this owner")
	}
	delete(r.entries, state)
	return e.accountID, nil
}

// Len reports the number of stored entries, including expired ones not yet
// purged. It is intended for tests and diagnostics.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// purgeLocked removes every expired entry. The caller must hold r.mu.
func (r *Registry) purgeLocked(now time.Time) {
	for state, e := range r.entries {
		if !now.Before(e.expires) {
			delete(r.entries, state)
		}
	}
}

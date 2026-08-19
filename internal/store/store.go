// Package store holds the compiled snapshot the RLS server reads on every check,
// and keeps it in step with the objects in the cache.
//
// The store is written by the updater on every event and read by the gRPC server
// on every request, so it is a whole-value swap behind an atomic pointer: readers
// never take a lock and never observe a half-built snapshot. Applying a rule
// change is therefore atomic per request — no request sees the old rules of one
// domain next to the new extraction of another.
package store

import (
	"sync/atomic"

	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// Store holds the current snapshot.
type Store struct {
	current atomic.Pointer[policy.Snapshot]
}

// New returns a Store holding an empty snapshot, so a reader that runs before the
// first rebuild sees "no domain is known" rather than a nil dereference.
func New() *Store {
	s := &Store{}
	s.current.Store(policy.Empty())
	return s
}

// Load returns the current snapshot. The result must be treated as read-only.
func (s *Store) Load() *policy.Snapshot {
	return s.current.Load()
}

// Replace swaps in a new snapshot.
func (s *Store) Replace(snapshot *policy.Snapshot) {
	if snapshot == nil {
		snapshot = policy.Empty()
	}
	s.current.Store(snapshot)
}

// HasDomain reports whether any policy is bound to the domain. A false here on a
// live request means the domain in the filter config of the gateway matches no
// policy.
func (s *Store) HasDomain(domain string) bool {
	return s.Load().Domain(domain) != nil
}

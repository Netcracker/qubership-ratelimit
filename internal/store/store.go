// Package store holds the rule set the RLS server reads on every check.
//
// The store is written by the updater on every RateLimitPolicy event and read
// by the gRPC server on every request, so it is a whole-value swap behind an
// atomic pointer: readers never take a lock and never observe a half-built map.
package store

import (
	"sync/atomic"

	engine "github.com/netcracker/qubership-ratelimit/engine"
)

// RuleSet is an immutable snapshot of the domains that have a policy bound to
// them: one ready-to-serve decision engine per domain. Engines are themselves
// immutable, so a rule change means new engines — checks in flight finish on
// the engine they started with, and none ever observes half-updated rules.
type RuleSet struct {
	engines map[string]*engine.Engine
}

// NewRuleSet builds a RuleSet over ready engines keyed by domain.
func NewRuleSet(engines map[string]*engine.Engine) *RuleSet {
	if engines == nil {
		engines = map[string]*engine.Engine{}
	}
	return &RuleSet{engines: engines}
}

// Engine returns the domain's engine, or nil when no policy is bound to the
// domain — the "unknown rate limit domain" case the server reports.
func (r *RuleSet) Engine(domain string) *engine.Engine {
	return r.engines[domain]
}

// Has reports whether a policy is bound to the domain.
func (r *RuleSet) Has(domain string) bool {
	return r.engines[domain] != nil
}

// Len reports how many domains carry an engine.
func (r *RuleSet) Len() int { return len(r.engines) }

// Store holds the current RuleSet.
type Store struct {
	current atomic.Pointer[RuleSet]
}

// New returns a Store holding an empty rule set, so readers that run before the
// first rebuild see "no domain is known" rather than a nil dereference.
func New() *Store {
	s := &Store{}
	s.current.Store(NewRuleSet(nil))
	return s
}

// Load returns the current snapshot. The result must be treated as read-only.
func (s *Store) Load() *RuleSet {
	return s.current.Load()
}

// Replace swaps in a new snapshot.
func (s *Store) Replace(rs *RuleSet) {
	if rs == nil {
		rs = NewRuleSet(nil)
	}
	s.current.Store(rs)
}

// Engine returns the current engine of the domain in one atomic load, or nil
// for an unbound domain.
func (s *Store) Engine(domain string) *engine.Engine {
	return s.Load().Engine(domain)
}

// HasDomain reports whether any policy is bound to the domain. A false here on a
// live request means the domain in the gateway's filter config does not match any
// policy.
func (s *Store) HasDomain(domain string) bool {
	return s.Load().Has(domain)
}

// Package store holds the rule set the RLS server reads on every check.
//
// The store is written by the updater on every RateLimitPolicy event and read
// by the gRPC server on every request, so it is a whole-value swap behind an
// atomic pointer: readers never take a lock and never observe a half-built map.
package store

import (
	"sync/atomic"
)

// RuleSet is an immutable snapshot of the domains that have a policy bound to
// them.
type RuleSet struct {
	Domains map[string]struct{}
}

// NewRuleSet builds a RuleSet from the domains in effect. Duplicates collapse,
// which is what makes two policies naming one domain a single entry.
func NewRuleSet(domains []string) *RuleSet {
	out := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		out[domain] = struct{}{}
	}
	return &RuleSet{Domains: out}
}

// Has reports whether a policy is bound to the domain.
func (r *RuleSet) Has(domain string) bool {
	_, ok := r.Domains[domain]
	return ok
}

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

// HasDomain reports whether any policy is bound to the domain. A false here on a
// live request means the domain in the gateway's filter config does not match any
// policy.
func (s *Store) HasDomain(domain string) bool {
	return s.Load().Has(domain)
}

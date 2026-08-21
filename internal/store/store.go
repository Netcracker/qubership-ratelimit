// Package store holds the rule set the RLS server reads on every check.
//
// The store is written by the updater on every RateLimitPolicy event and read
// by the gRPC server on every request, so it is a whole-value swap behind an
// atomic pointer: readers never take a lock and never observe a half-built map.
package store

import (
	"maps"
	"sort"
	"sync/atomic"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
)

// Domain is one domain in both of the forms the process needs it: the engine
// the decision path runs, and the snapshot it was built from.
//
// They travel together because the management API reports what is being
// enforced, not what was last compiled. Holding the snapshot in a second value
// would let the two drift for a moment after a rebuild, and the endpoint that
// resets counters derives its keys from the snapshot — it must describe the
// same rules the engine is deciding with.
type Domain struct {
	Engine   *engine.Engine
	Snapshot *compile.Snapshot
}

// RuleSet is an immutable snapshot of the domains that have a policy bound to
// them: one ready-to-serve decision engine per domain. Engines are themselves
// immutable, so a rule change means new engines — checks in flight finish on
// the engine they started with, and none ever observes half-updated rules.
type RuleSet struct {
	domains map[string]Domain
}

// NewRuleSet builds a RuleSet over ready domains. The map is cloned, not
// aliased: the snapshot must stay immutable even when the caller keeps writing
// to its map after Replace.
func NewRuleSet(domains map[string]Domain) *RuleSet {
	domains = maps.Clone(domains)
	if domains == nil {
		domains = map[string]Domain{}
	}
	return &RuleSet{domains: domains}
}

// Engine returns the domain's engine, or nil when no policy is bound to the
// domain — the "unknown rate limit domain" case the server reports.
func (r *RuleSet) Engine(domain string) *engine.Engine {
	return r.domains[domain].Engine
}

// Snapshot returns the compiled form of the domain the engine is deciding
// with, or nil for an unbound domain. It is read-only.
func (r *RuleSet) Snapshot(domain string) *compile.Snapshot {
	return r.domains[domain].Snapshot
}

// Domains lists the bound domains in name order, so a management response and
// the log line of a rebuild agree on ordering.
func (r *RuleSet) Domains() []string {
	out := make([]string, 0, len(r.domains))
	for domain := range r.domains {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

// Has reports whether a policy is bound to the domain.
func (r *RuleSet) Has(domain string) bool {
	return r.domains[domain].Engine != nil
}

// Len reports how many domains carry an engine.
func (r *RuleSet) Len() int { return len(r.domains) }

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

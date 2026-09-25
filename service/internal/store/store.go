// Package store holds the rule set the RLS server reads on every check.
//
// The store is written on every apply by the configuration reader and read by
// the gRPC server on every request, so it is a whole-value swap behind an
// atomic pointer: readers never take a lock and never observe a half-built
// map. It knows nothing of where the rules come from.
package store

import (
	"maps"
	"sort"
	"sync/atomic"
	"time"

	"github.com/netcracker/qubership-ratelimit/api/applied"
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

	// Version identifies the enforced set the pair above represents. It is
	// hashed once, when the domain is built, because every management response
	// quotes it and every pinned reset compares it.
	Version string

	// Generation and UID are the policy object the domain was applied from,
	// and AppliedAt is when. They ride with the engine rather than beside it
	// so that one load of the set yields the rules and the generation they
	// came from together: the applied report and the snapshot endpoint read
	// them off the same set, and a request that lands inside an apply sees
	// either configuration whole, never one's rules with the other's
	// generation.
	Generation int64
	UID        string
	AppliedAt  time.Time
}

// RuleSet is an immutable snapshot of the domains that have a policy bound to
// them: one ready-to-serve decision engine per domain. Engines are themselves
// immutable, so a rule change means new engines — checks in flight finish on
// the engine they started with, and none ever observes half-updated rules.
type RuleSet struct {
	domains map[string]Domain

	// swappedAt is when this set became the current one. It is set by
	// Replace, on the set itself, so that a reader of the set gets the time
	// of the swap it observed rather than the time of a later one.
	swappedAt time.Time

	// refusal is the reading this replica would not apply while this set
	// stayed current, nil when the last reading was applied. It rides on
	// the set for the same reason the applied facts do: the operator's
	// probe reads the generations and the refusal in one report, and a
	// refusal beside a set it does not belong to is judged as a replica
	// that refuses the manifest it just applied.
	refusal *applied.Refusal
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

// Domain returns the whole of one bound domain: the engine, the snapshot,
// the version, and the object it was applied from. ok is false for an
// unbound domain.
func (r *RuleSet) Domain(domain string) (d Domain, ok bool) {
	d, ok = r.domains[domain]
	return d, ok
}

// SwappedAt is when this set became the current one; the zero time for a
// set that never was, such as the empty one a Store starts with.
func (r *RuleSet) SwappedAt() time.Time {
	return r.swappedAt
}

// Refusal is the reading this replica would not apply while the set stayed
// current, nil when the last reading was applied.
func (r *RuleSet) Refusal() *applied.Refusal {
	return r.refusal
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

// Version returns the enforced-set version of the domain, or an empty string
// for an unbound one.
func (r *RuleSet) Version(domain string) string {
	return r.domains[domain].Version
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

// Store holds the current RuleSet: one atomic pointer, and every fact a
// reader pairs with the rules on the set behind it.
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

// Replace swaps in a new snapshot, stamped with the time of the swap and
// carrying no refusal: a set that was applied is the answer to the reading
// before it.
func (s *Store) Replace(rs *RuleSet) {
	if rs == nil {
		rs = NewRuleSet(nil)
	}
	rs.swappedAt = time.Now()
	rs.refusal = nil
	s.current.Store(rs)
}

// Refuse publishes a refusal on the current set: the same domains and the
// same swap time, since the rules did not change, with the refusal beside
// them in the one object a reader loads. The caller serializes it against
// Replace, as the applier does under its mutex; two writers racing here
// could publish a refusal on a set that was just retired.
func (s *Store) Refuse(refusal *applied.Refusal) {
	current := s.Load()
	refused := &RuleSet{domains: current.domains, swappedAt: current.swappedAt, refusal: refusal}
	s.current.Store(refused)
}

// SwappedAt is when this replica last swapped its rule set, or the zero time
// before the first one lands. Replicas swap independently, so this is a
// per-replica fact and the one the management API reports: comparing it
// across pods is how a rollout skew becomes visible.
func (s *Store) SwappedAt() time.Time {
	return s.Load().SwappedAt()
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

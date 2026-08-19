// Package policy validates the custom resources of a namespace and compiles the
// valid ones into one immutable snapshot per rebuild.
//
// Policies are units of ownership and review rather than units of evaluation:
// every event recompiles the whole domain, and after compilation there are no
// policies left, only one flat set of blocks. Compilation is a pure function of
// the set of objects and the last-good state: the order the objects arrived in,
// their recreation, and their timestamps change nothing. Order carries meaning in
// exactly one place — the rule list of a FirstMatch block, which is the lines of
// one file.
//
// What the compiler decides is validity, not verdicts. A generation with one
// blocking problem is invalid as a whole, an invalid generation falls back to the
// last-good one, and a mapping that would stop running rules is vetoed.
package policy

import (
	"sort"
	"time"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/route"
)

// KeyKind is the shape of the value set behind a descriptor key. It decides
// which operators apply and whether the key can serve as a counter axis.
type KeyKind uint8

const (
	// KeyScalar is a one-element set.
	KeyScalar KeyKind = iota

	// KeyArray is a set of elements.
	KeyArray
)

// Snapshot is the compiled state of every domain in the namespace.
type Snapshot struct {
	domains map[string]*Domain
}

// Domain returns the compiled domain, or nil when nothing is bound to it.
//
// A nil result on a live request means the domain in the filter config of the
// gateway matches no policy. Such a request passes: a domain nobody wrote rules
// for is not an error. The cost of that choice is that a typo in a domain
// silently turns limits off, which is why the unknown-domain path is logged on
// every check.
func (s *Snapshot) Domain(name string) *Domain {
	return s.domains[name]
}

// Names returns the compiled domain names, sorted.
func (s *Snapshot) Names() []string {
	names := make([]string, 0, len(s.domains))
	for name := range s.domains {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Domain is the compiled rule set of one traffic source.
type Domain struct {
	// Name is the domain string both sides agreed on.
	Name string

	// Keys is the effective key set: the built-in keys plus the mapped ones.
	// Route captures are per block and are not in here.
	Keys map[string]KeyKind

	// Blocks are the blocks of every policy of the domain, concatenated. They
	// always add up, so the order between them changes nothing.
	Blocks []*Block
}

// EffectiveKeys returns the key names of the domain, sorted, for publication in
// the status of the mapping.
func (d *Domain) EffectiveKeys() []string {
	keys := make([]string, 0, len(d.Keys))
	for key := range d.Keys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Block is a target plus the rules counting the traffic it selects.
type Block struct {
	// Policy and Name are the first two thirds of the counter key. The
	// namespace of a block name is its policy, so two policies naming one block
	// are independent additive blocks rather than a conflict.
	Policy string
	Name   string

	// Mode selects how the rules combine. It has no effect across blocks.
	Mode v1alpha1.BlockMode

	// Routes is an OR-list. An empty list means the block sees the whole domain.
	Routes []Route

	// Rules are the counters of the block.
	Rules []*Rule
}

// Route is one compiled route of a block.
type Route struct {
	// Matcher matches the request path.
	Matcher *route.Matcher

	// Methods accepts a request whose method is a member. An empty map accepts
	// any method.
	Methods map[string]struct{}
}

// Match returns the first route that accepts the request, together with the
// segments it captured. A block without routes accepts everything and captures
// nothing.
func (b *Block) Match(path, method string) (*route.Matcher, map[string]string, bool) {
	if len(b.Routes) == 0 {
		return nil, nil, true
	}
	for i := range b.Routes {
		candidate := &b.Routes[i]
		if len(candidate.Methods) > 0 {
			if _, ok := candidate.Methods[method]; !ok {
				continue
			}
		}
		if captures, ok := candidate.Matcher.Match(path); ok {
			return candidate.Matcher, captures, true
		}
	}
	return nil, nil, false
}

// Rule is one counter of a block.
type Rule struct {
	// Name is the last third of the counter key.
	Name string

	// Predicates is a conjunction. An empty list matches every request the
	// block sees.
	Predicates []Predicate

	// Counters are the axes of the bucket. An empty list gives the rule one
	// shared bucket.
	Counters []string

	// Rates are the windows of the rule. Each is an independent bucket.
	Rates []Rate

	// Behavior selects what the rule does with the verdict.
	Behavior v1alpha1.RuleBehavior

	// Replaces names the rules of the block this rule silences.
	Replaces map[string]struct{}

	// Dead marks a rule that references something the domain does not produce.
	// One such rule already invalidates its whole generation, so a rule carrying
	// this flag never reaches a snapshot; it is defense in depth for the day an
	// evaluator is added, so that a typo gives a rule that matches nothing rather
	// than one that traps traffic.
	Dead bool
}

// Predicate is one compiled condition on the identity of the caller.
type Predicate struct {
	// Key names the descriptor key the predicate reads.
	Key string

	// Operator is the predicate over the value set of the key.
	Operator v1alpha1.PredicateOperator

	// Value is the operand of Equals and Contains.
	Value string

	// Set is the operand of In and the resolved membership of InGroup. Both are
	// intersection tests, so the group list is flattened at compile time and the
	// request path is a map lookup.
	Set map[string]struct{}

	// Fold reports that values are lower-cased before the set is consulted. It
	// is set for InGroup, whose members are normalized the same way, so the case
	// a token happens to carry does not decide membership.
	Fold bool
}

// Rate is one compiled window.
type Rate struct {
	// Requests is the quota of the window.
	Requests int64

	// Burst is the bucket depth of a GCRA window, in requests.
	Burst int64

	// Period is the length of the window.
	Period time.Duration

	// Algorithm selects the counting rule.
	Algorithm v1alpha1.Algorithm
}

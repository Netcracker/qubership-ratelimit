package compile

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// domainName mirrors the schema's domain pattern. Compile enforces it itself:
// an empty domain would otherwise reach the key builder at request time and
// meet its empty-hash-tag panic on the data path.
var domainName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Reason names why a rule or an object cannot take effect. The first five
// mirror the resource status contract; the last two are engine-level umbrellas
// for what schema validation rejects upstream — they surface only when a
// caller bypassed it, because a library cannot assume anyone validated.
type Reason string

const (
	ReasonUnresolvedKeyReference   Reason = "UnresolvedKeyReference"
	ReasonUnresolvedGroupReference Reason = "UnresolvedGroupReference"
	ReasonIncompatibleOperator     Reason = "IncompatibleOperator"
	ReasonInvalidCounterAxis       Reason = "InvalidCounterAxis"
	ReasonCaptureShadowsMappedKey  Reason = "CaptureShadowsMappedKey"

	// ReasonInvalidSpec covers structural violations the CRD's CEL rules
	// catch before an object ever reaches the controller.
	ReasonInvalidSpec Reason = "InvalidSpec"

	// ReasonInvalidWindow covers window math the schema cannot see: GCRA
	// resolution and bucket-depth bounds live in algo.Check only.
	ReasonInvalidWindow Reason = "InvalidWindow"

	// ReasonDecisionBudgetExceeded covers a policy whose worst-case request
	// would collect more than model.MaxDecisionBucketsPerPolicy buckets — a
	// cross-field product the schema cannot see.
	ReasonDecisionBudgetExceeded Reason = "DecisionBudgetExceeded"

	// ReasonDomainBudgetExceeded reports a domain over its reference bounds:
	// the worst-case decision above what the runtime backstop admits, or a
	// block count above the target-scan budget. Informational and
	// domain-level — no single policy is at fault, so none is excluded; the
	// operator's admission gate is what keeps live domains inside, and this
	// record is its diagnostics and the alarm signal for embedders running
	// without it.
	ReasonDomainBudgetExceeded Reason = "DomainBudgetExceeded"
)

// Problem is one finding. A policy with at least one blocking problem is
// invalid as a whole: none of its rules enters the snapshot, because partial
// enforcement would hand cascade traffic to the wrong rules. An empty Policy
// field marks a mapping-level problem.
type Problem struct {
	Policy   string
	Block    string
	Rule     string
	Reason   Reason
	Message  string
	Blocking bool
}

// Snapshot is the compiled domain: a flat block set with every default
// resolved, every group baked into its conditions, and every window past
// algo.Check. It is immutable; the engine swaps whole snapshots atomically.
type Snapshot struct {
	Domain string

	// EffectiveKeys is the domain-global key set — built-ins plus mapping
	// keys — sorted. Block captures extend it per block, not here.
	EffectiveKeys []string

	// Blocks are ordered by policy name, then by authored position: the one
	// ordering that is a pure function of the object set.
	Blocks []Block

	// Extraction drives identity: built-in client first unless overridden,
	// then mapped keys in authored order.
	Extraction []KeyExtraction

	// DecisionBuckets is the worst case one request can collect across the
	// domain — the number the domain budget record compares against
	// model.MaxDomainDecisionBuckets — and PolicyBuckets breaks it down by
	// policy. Both are facts for an embedder's capacity metrics; the formula
	// itself stays in this package.
	DecisionBuckets int
	PolicyBuckets   map[string]int
}

// Block is a compiled limits entry, carrying its policy for counter identity.
type Block struct {
	Policy string
	Name   string
	Mode   model.Mode
	Routes []Route

	// Captures are the template placeholder names of this block's routes:
	// block-scoped descriptor keys, sorted.
	Captures []string

	Rules []Rule
}

// Route is a compiled route matcher.
type Route struct {
	Type  model.PathType
	Value string

	// Segments precompile a Template route; nil otherwise.
	Segments []Segment

	// Methods is empty for "any method".
	Methods map[string]struct{}
}

// Segment is one path segment of a template: a literal, or a capture name.
type Segment struct {
	Literal string
	Capture string
}

// Rule is a compiled rule with resolved behavior and windows.
type Rule struct {
	Name     string
	Behavior model.Behavior
	When     []Condition
	Counters []string
	Rates    []Rate
	Replaces []string
}

// Condition is a compiled when predicate. Values carries the In set, or the
// resolved client set of an InGroup — group indirection ends at compile time.
type Condition struct {
	Key      string
	Operator model.Operator
	Value    string
	Values   map[string]struct{}
}

// Rate is one window, resolved and checked. Prefix is the constant part of
// every bucket key of this rate — everything up to the axis values — built
// once here so the request path only appends escaped axes.
type Rate struct {
	Algorithm algo.Algorithm
	Window    algo.Window
	Prefix    string
}

// KeyExtraction drives one descriptor key's extraction, claim paths already
// split into segments.
type KeyExtraction struct {
	Key       string
	Path      []string
	Type      model.ValueType
	Normalize model.Normalize
	Fallbacks [][]string
}

// Compile turns one domain's objects into a snapshot plus every problem
// found. It is a pure function of the set: apply order, recreation, and
// timestamps cannot reach the result, so equal inputs give byte-equal
// snapshots on every replica. A nil mapping is the normal built-ins-only
// state. Policies with blocking problems are excluded whole; their problems
// are still reported, as are informational ones of included policies.
func Compile(domain string, policies []model.Policy, mapping *model.Mapping) (*Snapshot, []Problem) {
	if len(domain) > 63 || !domainName.MatchString(domain) {
		return &Snapshot{Domain: domain}, []Problem{{
			Reason:   ReasonInvalidSpec,
			Message:  fmt.Sprintf("domain %q does not match %s or exceeds 63 characters", domain, domainName),
			Blocking: true,
		}}
	}

	var problems []Problem

	env, mappingProblems := compileMapping(domain, mapping)
	problems = append(problems, mappingProblems...)

	sorted := make([]model.Policy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	// A duplicated policy name would collide the counter identities of two
	// objects; every bearer of the name is excluded, loudly.
	names := map[string]int{}
	for _, p := range sorted {
		names[p.Name]++
	}

	snap := &Snapshot{
		Domain:        domain,
		EffectiveKeys: env.effectiveKeys(),
		Extraction:    env.extraction,
	}
	for _, p := range sorted {
		if names[p.Name] > 1 {
			problems = append(problems, Problem{
				Policy:   p.Name,
				Reason:   ReasonInvalidSpec,
				Message:  "policy name is declared more than once in the domain",
				Blocking: true,
			})
			continue
		}
		blocks, policyProblems := compilePolicy(domain, p, env)
		problems = append(problems, policyProblems...)
		if blocking(policyProblems) {
			continue
		}
		snap.Blocks = append(snap.Blocks, blocks...)
	}

	snap.DecisionBuckets = decisionBuckets(snap.Blocks)
	snap.PolicyBuckets = policyBuckets(snap.Blocks)

	if n := snap.DecisionBuckets; n > model.MaxDomainDecisionBuckets {
		problems = append(problems, Problem{
			Reason: ReasonDomainBudgetExceeded,
			Message: fmt.Sprintf(
				"one request can collect up to %d buckets across the domain, over the runtime backstop of %d:"+
					" overlapping requests will be refused",
				n, model.MaxDomainDecisionBuckets),
		})
	}
	if n := len(snap.Blocks); n > model.MaxDomainBlocks {
		problems = append(problems, Problem{
			Reason: ReasonDomainBudgetExceeded,
			Message: fmt.Sprintf(
				"the domain compiles %d blocks, over the reference bound of %d for the target scan",
				n, model.MaxDomainBlocks),
		})
	}
	return snap, problems
}

func blocking(problems []Problem) bool {
	for _, p := range problems {
		if p.Blocking {
			return true
		}
	}
	return false
}

package compile

import (
	"fmt"
	"regexp"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// domainName mirrors the schema's domain pattern. Compile enforces it itself:
// an empty domain would otherwise reach the key builder at request time and
// meet its empty-hash-tag panic on the data path.
var domainName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Reason names why a generation cannot take effect. All but the last are
// blocking, and one blocking entry invalidates the generation whole.
type Reason string

const (
	ReasonUnresolvedKeyReference   Reason = "UnresolvedKeyReference"
	ReasonUnresolvedGroupReference Reason = "UnresolvedGroupReference"
	ReasonUnresolvedReplacedRules  Reason = "UnresolvedReplacedRules"
	ReasonIncompatibleOperator     Reason = "IncompatibleOperator"
	ReasonInvalidCounterAxis       Reason = "InvalidCounterAxis"

	// ReasonInvalidSpec covers a structural defect the schema cannot see:
	// predicate arity, a Bypass without replacedRules under All, a repeated
	// placeholder, an unknown field or enum value of a newer schema.
	ReasonInvalidSpec Reason = "InvalidSpec"

	// ReasonInvalidWindow covers window math the schema cannot see: GCRA
	// resolution and bucket-depth bounds live in algo.Check only.
	ReasonInvalidWindow Reason = "InvalidWindow"

	// ReasonDomainBudgetExceeded covers a worst-case decision above
	// model.MaxDomainDecisionBuckets. It is blocking: last-good keeps serving
	// rather than a generation whose widest paths the runtime backstop would
	// refuse outright.
	ReasonDomainBudgetExceeded Reason = "DomainBudgetExceeded"

	// ReasonCaptureShadowsMappedKey is informational: within its block the
	// capture wins, and the author is told which key it displaced.
	ReasonCaptureShadowsMappedKey Reason = "CaptureShadowsMappedKey"
)

// Problem is one finding. A generation with at least one blocking problem is
// invalid as a whole: none of its rules enters the snapshot, because partial
// enforcement would hand cascade traffic to the wrong rules.
type Problem struct {
	Block    string
	Rule     string
	Reason   Reason
	Message  string
	Blocking bool
}

// Snapshot is the compiled domain: a flat block set with every default
// resolved, every group baked into its predicates, and every window past
// algo.Check. It is immutable; the engine swaps whole snapshots atomically.
type Snapshot struct {
	Namespace string
	Domain    string

	// EffectiveKeys is the domain-global key set — built-ins plus mapping
	// keys — sorted. Block captures extend it per block, not here.
	EffectiveKeys []string

	// Blocks are in authored order, which is the order a FirstMatch cascade
	// reads. They are empty when the generation is invalid: a snapshot never
	// carries part of one.
	Blocks []Block

	// Extraction drives identity: built-in client first unless overridden,
	// then mapped keys in authored order.
	Extraction []KeyExtraction

	// DecisionBuckets is the worst case one request can collect across the
	// domain — the number compared against model.MaxDomainDecisionBuckets. It
	// is a fact for an embedder's capacity metrics; the formula stays here.
	DecisionBuckets int
}

// Block is a compiled limits entry.
type Block struct {
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
	Name          string
	Behavior      model.Behavior
	Matches       []Predicate
	Counters      []string
	Rates         []Rate
	ReplacedRules []string
}

// Predicate is a compiled matches entry. Values carries the In set, or the
// resolved client set of an InGroup — group indirection ends at compile time.
type Predicate struct {
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
	Key           string
	Path          []string
	Type          model.ValueType
	Normalization model.Normalize
	Fallbacks     [][]string
}

// Compile turns one domain's policy into a snapshot plus every problem found.
// It is a pure function of the spec: apply order, recreation, and timestamps
// cannot reach the result, so an equal spec gives byte-equal snapshots on
// every replica.
//
// A nil policy is the empty domain — no object, or none whose generation
// compiles — and yields the built-in key set with no blocks. Compilation is
// all-or-nothing: a blocking problem leaves the snapshot without blocks, so no
// caller can enforce half a generation by accident.
func Compile(namespace, domain string, p *model.Policy) (*Snapshot, []Problem) {
	if namespace == "" {
		return &Snapshot{Domain: domain}, []Problem{{
			Reason:   ReasonInvalidSpec,
			Message:  "the component's own namespace is empty; it is a segment of every counter key",
			Blocking: true,
		}}
	}
	if len(domain) > 63 || !domainName.MatchString(domain) {
		return &Snapshot{Namespace: namespace, Domain: domain}, []Problem{{
			Reason:   ReasonInvalidSpec,
			Message:  fmt.Sprintf("domain %q does not match %s or exceeds 63 characters", domain, domainName),
			Blocking: true,
		}}
	}

	env, problems := compileEnvironment(domain, p)
	snap := &Snapshot{
		Namespace:     namespace,
		Domain:        domain,
		EffectiveKeys: env.effectiveKeys(),
		Extraction:    env.extraction,
	}
	if p == nil {
		return snap, problems
	}

	blocks, blockProblems := compileBlocks(namespace, domain, *p, env)
	problems = append(problems, blockProblems...)

	if n := decisionBuckets(blocks); n > model.MaxDomainDecisionBuckets {
		problems = append(problems, Problem{
			Reason: ReasonDomainBudgetExceeded,
			Message: fmt.Sprintf(
				"one request can collect up to %d buckets across the domain; the budget is %d",
				n, model.MaxDomainDecisionBuckets),
			Blocking: true,
		})
	}
	if blocking(problems) {
		return snap, problems
	}

	snap.Blocks = blocks
	snap.DecisionBuckets = decisionBuckets(blocks)
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

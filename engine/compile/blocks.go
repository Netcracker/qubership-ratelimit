package compile

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/algo"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// httpMethods is the closed method set the schema admits: the eight methods of
// RFC 9110 plus PATCH.
var httpMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "DELETE": {}, "PATCH": {},
	"HEAD": {}, "OPTIONS": {}, "CONNECT": {}, "TRACE": {},
}

// blockCompiler carries one generation's compilation state so the helpers stay
// small and the problem plumbing stays in one place.
type blockCompiler struct {
	namespace string
	domain    string
	env       *environment
	problems  []Problem
}

// compileBlocks validates and builds the blocks of one policy.
func compileBlocks(namespace, domain string, p model.Policy, env *environment) ([]Block, []Problem) {
	c := &blockCompiler{namespace: namespace, domain: domain, env: env}

	if len(p.Blocks) == 0 {
		c.fail("", "", ReasonInvalidSpec, "a policy without blocks")
	}

	blocks := make([]Block, 0, len(p.Blocks))
	seen := map[string]struct{}{}
	for _, b := range p.Blocks {
		if _, dup := seen[b.Name]; dup {
			c.fail(b.Name, "", ReasonInvalidSpec, "block %q is declared twice", b.Name)
			continue
		}
		seen[b.Name] = struct{}{}
		blocks = append(blocks, c.compileBlock(b))
	}
	return blocks, c.problems
}

// decisionBuckets is the worst case one request can collect from these blocks:
// every block targeted at once, All summing every counting rule, FirstMatch
// settling on its widest counting rule after every shadow rule — shadows count
// without ending the cascade. Bypass rules carry no rates, and replacedRules
// suppression cannot be assumed statically.
//
// It sums blocks with disjoint targets too, so it is deliberately pessimistic:
// no request can exceed a bound this formula respects.
func decisionBuckets(blocks []Block) int {
	total := 0
	for _, b := range blocks {
		total += blockDecisionBuckets(b)
	}
	return total
}

// blockDecisionBuckets is one block's contribution to the worst case.
func blockDecisionBuckets(b Block) int {
	always, widest := 0, 0
	for _, r := range b.Rules {
		switch {
		case b.Mode != model.ModeFirstMatch:
			always += len(r.Rates)
		case r.Behavior == model.BehaviorShadow:
			always += len(r.Rates)
		default:
			widest = max(widest, len(r.Rates))
		}
	}
	return always + widest
}

func (c *blockCompiler) fail(block, rule string, reason Reason, format string, args ...any) {
	c.problems = append(c.problems, Problem{
		Block:    block,
		Rule:     rule,
		Reason:   reason,
		Message:  fmt.Sprintf(format, args...),
		Blocking: reason != ReasonCaptureShadowsMappedKey,
	})
}

func (c *blockCompiler) compileBlock(b model.Block) Block {
	out := Block{Name: b.Name, Mode: b.Mode}
	if out.Mode == "" {
		out.Mode = model.ModeAll
	}
	if out.Mode != model.ModeAll && out.Mode != model.ModeFirstMatch {
		c.fail(b.Name, "", ReasonInvalidSpec, "unknown mode %q", b.Mode)
	}

	out.Routes, out.Captures = c.compileRoutes(b)

	// blockKeys is the per-block effective set: domain keys plus captures.
	blockKeys := make(map[string]bool, len(c.env.keys)+len(out.Captures))
	maps.Copy(blockKeys, c.env.keys)
	for _, capture := range out.Captures {
		blockKeys[capture] = false
	}

	if len(b.Rules) == 0 {
		c.fail(b.Name, "", ReasonInvalidSpec, "a block without rules")
	}
	names := map[string]struct{}{}
	for _, r := range b.Rules {
		if _, dup := names[r.Name]; dup {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "rule %q is declared twice", r.Name)
			continue
		}
		names[r.Name] = struct{}{}
		out.Rules = append(out.Rules, c.compileRule(b, r, blockKeys))
	}
	c.checkReplacedRules(b, out.Mode, names)
	return out
}

func (c *blockCompiler) checkReplacedRules(b model.Block, mode model.Mode, names map[string]struct{}) {
	for _, r := range b.Rules {
		if len(r.ReplacedRules) == 0 {
			continue
		}
		if mode == model.ModeFirstMatch {
			c.fail(b.Name, r.Name, ReasonInvalidSpec,
				"replacedRules is not available under FirstMatch, where the order of the rules already decides")
			continue
		}
		for _, target := range r.ReplacedRules {
			if _, ok := names[target]; !ok || target == r.Name {
				c.fail(b.Name, r.Name, ReasonUnresolvedReplacedRules,
					"replacedRules names %q, which is not another rule of this block", target)
			}
		}
	}
}

func (c *blockCompiler) compileRule(b model.Block, r model.Rule, blockKeys map[string]bool) Rule {
	// Cloned, not aliased: the snapshot must stay immutable even when the
	// caller mutates the model after Compile.
	out := Rule{Name: r.Name, Behavior: r.Behavior,
		Counters: slices.Clone(r.Counters), ReplacedRules: slices.Clone(r.ReplacedRules)}
	if out.Behavior == "" {
		out.Behavior = model.BehaviorEnforce
	}
	switch out.Behavior {
	case model.BehaviorEnforce, model.BehaviorShadow, model.BehaviorBypass:
	default:
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "unknown behavior %q", r.Behavior)
	}
	// Under All, a bypass is a targeted exemption: without replacedRules it
	// would be a silent no-op, and this model keeps authoring mistakes loud.
	if out.Behavior == model.BehaviorBypass && b.Mode != model.ModeFirstMatch && len(r.ReplacedRules) == 0 {
		c.fail(b.Name, r.Name, ReasonInvalidSpec,
			"a Bypass rule under All names the rules it exempts from in replacedRules")
	}

	c.compileMatches(b, r, blockKeys, &out)
	c.compileCounters(b, r, blockKeys)
	out.Rates = c.compileRates(b, r, out.Behavior)
	return out
}

func (c *blockCompiler) compileMatches(b model.Block, r model.Rule, blockKeys map[string]bool, out *Rule) {
	for _, p := range r.Matches {
		if compiled, ok := c.compilePredicate(b, r, p, blockKeys); ok {
			out.Matches = append(out.Matches, compiled)
		}
	}
}

// compilePredicate validates one predicate against the block's key set and
// bakes group and In sets into it.
func (c *blockCompiler) compilePredicate(
	b model.Block, r model.Rule, p model.Predicate, blockKeys map[string]bool,
) (Predicate, bool) {
	compiled := Predicate{Key: p.Key, Operator: p.Operator, Value: p.Value}

	if p.Key == model.KeyPath || p.Key == model.KeyMethod || p.Key == model.KeyToken {
		c.fail(b.Name, r.Name, ReasonInvalidSpec,
			"matches key %q belongs to the target, not to matches", p.Key)
		return Predicate{}, false
	}
	isArray, known := blockKeys[p.Key]
	if !known {
		c.fail(b.Name, r.Name, ReasonUnresolvedKeyReference,
			"key %q is not in the effective set of the domain", p.Key)
		return Predicate{}, false
	}
	if !c.operatorArity(b, r, p) {
		return Predicate{}, false
	}

	switch p.Operator {
	case model.OperatorEquals:
		if isArray {
			c.fail(b.Name, r.Name, ReasonIncompatibleOperator,
				"Equals cannot apply to the array-valued key %q", p.Key)
		}
	case model.OperatorIn:
		compiled.Values = toSet(p.Values)
	case model.OperatorInGroup:
		clients, ok := c.env.groups[p.Value]
		if !ok {
			c.fail(b.Name, r.Name, ReasonUnresolvedGroupReference,
				"InGroup names %q, which no group declares", p.Value)
			return Predicate{}, false
		}
		compiled.Values = toSet(clients)
	case model.OperatorContains, model.OperatorExists, model.OperatorDoesNotExist:
	}
	return compiled, true
}

// operatorArity rejects a predicate whose parameters do not fit its operator:
// a foreign parameter means part of the author's intent would be silently
// dropped, and this model keeps authoring mistakes loud.
func (c *blockCompiler) operatorArity(b model.Block, r model.Rule, p model.Predicate) bool {
	bad := func(format string, args ...any) bool {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, format, args...)
		return false
	}
	switch p.Operator {
	case model.OperatorEquals, model.OperatorContains, model.OperatorInGroup:
		if p.Value == "" || len(p.Values) > 0 {
			return bad("%s takes value and nothing else", p.Operator)
		}
	case model.OperatorIn:
		if len(p.Values) == 0 || p.Value != "" {
			return bad("In takes a non-empty values list and nothing else")
		}
	case model.OperatorExists, model.OperatorDoesNotExist:
		if p.Value != "" || len(p.Values) > 0 {
			return bad("%s takes no parameters", p.Operator)
		}
	default:
		return bad("unknown operator %q", p.Operator)
	}
	return true
}

func (c *blockCompiler) compileCounters(b model.Block, r model.Rule, blockKeys map[string]bool) {
	for _, axis := range r.Counters {
		isArray, known := blockKeys[axis]
		if !known {
			c.fail(b.Name, r.Name, ReasonUnresolvedKeyReference,
				"counter axis %q is not in the effective set of the domain", axis)
			continue
		}
		if isArray {
			c.fail(b.Name, r.Name, ReasonInvalidCounterAxis,
				"the array-valued key %q cannot be a counter axis", axis)
		}
	}
}

func (c *blockCompiler) compileRates(b model.Block, r model.Rule, behavior model.Behavior) []Rate {
	if !c.ratesCompilable(b, r, behavior) {
		return nil
	}

	out := make([]Rate, 0, len(r.Rates))
	ident := key.Ident{Namespace: c.namespace, Domain: c.domain, Block: b.Name, Rule: r.Name}
	periods := map[time.Duration]struct{}{}
	for _, rate := range r.Rates {
		if _, dup := periods[rate.Period]; dup {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "two rates entries share the period %s", rate.Period)
			continue
		}
		periods[rate.Period] = struct{}{}

		if compiled, ok := c.compileRate(b, r, rate, ident); ok {
			out = append(out, compiled)
		}
	}
	return out
}

// ratesCompilable reports whether the rule's rates array is worth walking. A
// Bypass rule legitimately has none; the other answers are rejections, and each
// reports itself before returning.
func (c *blockCompiler) ratesCompilable(b model.Block, r model.Rule, behavior model.Behavior) bool {
	if behavior == model.BehaviorBypass {
		if len(r.Rates) > 0 {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "a Bypass rule carries no rates")
		}
		return false
	}
	if len(r.Rates) == 0 {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "a counting rule carries at least one rates entry")
		return false
	}
	return true
}

// compileRate resolves one rates entry to its algorithm and checked window.
// The bool is false when the entry was rejected, which it has already
// reported.
func (c *blockCompiler) compileRate(
	b model.Block,
	r model.Rule,
	rate model.Rate,
	ident key.Ident,
) (Rate, bool) {
	name := rate.Algorithm
	if name == "" {
		name = "GCRA"
	}
	a, ok := algo.ByName(name)
	if !ok {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "unknown algorithm %q; known: %v", rate.Algorithm, algo.Names())
		return Rate{}, false
	}

	w := algo.Window{Requests: rate.Requests, Period: rate.Period, Burst: rate.Burst}
	if a.ID() == algo.GCRAID && w.Burst == 0 {
		w.Burst = w.Requests // the documented default: a full bucket
	}
	if err := algo.Check(a, w); err != nil {
		c.fail(b.Name, r.Name, ReasonInvalidWindow, "window %s/%s: %v", name, rate.Period, err)
		return Rate{}, false
	}
	return Rate{Algorithm: a, Window: w, Prefix: key.RatePrefix(ident, a, w)}, true
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

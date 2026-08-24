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

// httpMethods is the closed method set the schema admits.
var httpMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "DELETE": {}, "PATCH": {},
	"HEAD": {}, "OPTIONS": {}, "CONNECT": {}, "TRACE": {},
}

// policyCompiler carries one policy's compilation state so the helpers stay
// small and the problem plumbing stays in one place.
type policyCompiler struct {
	domain   string
	policy   model.Policy
	env      *environment
	groups   map[string][]string // private over shared, shadowing resolved
	problems []Problem
}

// compilePolicy validates and builds one policy's blocks. Any blocking
// problem invalidates the whole policy; the caller drops the blocks then.
func compilePolicy(domain string, p model.Policy, env *environment) ([]Block, []Problem) {
	c := &policyCompiler{domain: domain, policy: p, env: env}
	c.resolveGroups()

	if p.Domain != domain {
		c.fail("", "", ReasonInvalidSpec, "policy domain %q does not belong to domain %q", p.Domain, domain)
	}
	if len(p.Blocks) == 0 {
		c.fail("", "", ReasonInvalidSpec, "a policy without blocks")
	}
	if len(p.Blocks) > model.MaxBlocksPerPolicy {
		c.fail("", "", ReasonInvalidSpec, "blocks exceed the limit of %d", model.MaxBlocksPerPolicy)
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
	if n := decisionBuckets(blocks); n > model.MaxDecisionBucketsPerPolicy {
		c.fail("", "", ReasonDecisionBudgetExceeded,
			"one request can collect up to %d buckets from this policy; the budget is %d",
			n, model.MaxDecisionBucketsPerPolicy)
	}
	return blocks, c.problems
}

// decisionBuckets is the worst case one request can collect from these
// blocks: every block targeted at once, All summing every counting rule,
// FirstMatch settling on its widest counting rule after every shadow rule —
// shadows count without ending the cascade. Bypass rules carry no rates and
// replaces suppression cannot be assumed statically.
func decisionBuckets(blocks []Block) int {
	total := 0
	for _, b := range blocks {
		total += blockDecisionBuckets(b)
	}
	return total
}

// blockDecisionBuckets is one block's contribution to the worst case: All
// sums every counting rule, FirstMatch settles on its widest counting rule
// after every shadow rule.
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

// policyBuckets breaks decisionBuckets down by policy. The formula is
// per-block additive, so a policy's worst case is the sum over its own
// blocks.
func policyBuckets(blocks []Block) map[string]int {
	if len(blocks) == 0 {
		return nil
	}
	out := make(map[string]int, 4)
	for _, b := range blocks {
		out[b.Policy] += blockDecisionBuckets(b)
	}
	return out
}

func (c *policyCompiler) fail(block, rule string, reason Reason, format string, args ...any) {
	c.problems = append(c.problems, Problem{
		Policy:   c.policy.Name,
		Block:    block,
		Rule:     rule,
		Reason:   reason,
		Message:  fmt.Sprintf(format, args...),
		Blocking: reason != ReasonCaptureShadowsMappedKey,
	})
}

// resolveGroups lays private groups over shared ones: a local name shadows,
// deterministically and per policy.
func (c *policyCompiler) resolveGroups() {
	c.groups = make(map[string][]string, len(c.env.sharedGroups)+len(c.policy.Groups))
	maps.Copy(c.groups, c.env.sharedGroups)
	private := map[string][]string{}
	c.problems = append(c.problems, compileGroups(c.policy.Groups, private, c.policy.Name)...)
	maps.Copy(c.groups, private)
}

func (c *policyCompiler) compileBlock(b model.Block) Block {
	out := Block{Policy: c.policy.Name, Name: b.Name, Mode: b.Mode}
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
	if len(b.Rules) > model.MaxRulesPerBlock {
		c.fail(b.Name, "", ReasonInvalidSpec, "rules exceed the limit of %d", model.MaxRulesPerBlock)
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
	c.checkReplaces(b, out.Mode, names)
	return out
}

func (c *policyCompiler) checkReplaces(b model.Block, mode model.Mode, names map[string]struct{}) {
	for _, r := range b.Rules {
		if len(r.Replaces) == 0 {
			continue
		}
		if mode == model.ModeFirstMatch {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "replaces is not available under FirstMatch")
			continue
		}
		if len(r.Replaces) > model.MaxReplacesPerRule {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "replaces exceed the limit of %d", model.MaxReplacesPerRule)
		}
		for _, target := range r.Replaces {
			if _, ok := names[target]; !ok || target == r.Name {
				c.fail(b.Name, r.Name, ReasonInvalidSpec, "replaces names %q, which is not another rule of this block", target)
			}
		}
	}
}

func (c *policyCompiler) compileRule(b model.Block, r model.Rule, blockKeys map[string]bool) Rule {
	// Cloned, not aliased: the snapshot must stay immutable even when the
	// caller mutates the model after Compile.
	out := Rule{Name: r.Name, Behavior: r.Behavior,
		Counters: slices.Clone(r.Counters), Replaces: slices.Clone(r.Replaces)}
	if out.Behavior == "" {
		out.Behavior = model.BehaviorEnforce
	}
	switch out.Behavior {
	case model.BehaviorEnforce, model.BehaviorShadow, model.BehaviorBypass:
	default:
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "unknown behavior %q", r.Behavior)
	}
	// Under All, a bypass is a targeted exemption: without replaces it would
	// be a silent no-op, and this model keeps authoring mistakes loud.
	if out.Behavior == model.BehaviorBypass && b.Mode != model.ModeFirstMatch && len(r.Replaces) == 0 {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "a Bypass rule under All names the rules it exempts from in replaces")
	}

	c.compileConditions(b, r, blockKeys, &out)
	c.compileCounters(b, r, blockKeys)
	out.Rates = c.compileRates(b, r, out.Behavior)
	return out
}

func (c *policyCompiler) compileConditions(b model.Block, r model.Rule, blockKeys map[string]bool, out *Rule) {
	if len(r.When) > model.MaxConditionsPerRule {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "when exceeds the limit of %d", model.MaxConditionsPerRule)
	}
	for _, cond := range r.When {
		if compiled, ok := c.compileCondition(b, r, cond, blockKeys); ok {
			out.When = append(out.When, compiled)
		}
	}
}

// compileCondition validates one predicate against the block's key set and
// bakes group and In sets into it.
func (c *policyCompiler) compileCondition(
	b model.Block, r model.Rule, cond model.Condition, blockKeys map[string]bool,
) (Condition, bool) {
	compiled := Condition{Key: cond.Key, Operator: cond.Operator, Value: cond.Value}

	if cond.Key == model.KeyPath || cond.Key == model.KeyMethod {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "when key %q belongs to the target, not to when", cond.Key)
		return Condition{}, false
	}
	isArray, known := blockKeys[cond.Key]
	if !known {
		c.fail(b.Name, r.Name, ReasonUnresolvedKeyReference,
			"key %q is not in the effective set of the domain", cond.Key)
		return Condition{}, false
	}
	if !c.operatorArity(b, r, cond) {
		return Condition{}, false
	}

	switch cond.Operator {
	case model.OperatorEquals:
		if isArray {
			c.fail(b.Name, r.Name, ReasonIncompatibleOperator,
				"Equals cannot apply to the array-valued key %q", cond.Key)
		}
	case model.OperatorIn:
		compiled.Values = toSet(cond.Values)
	case model.OperatorInGroup:
		clients, ok := c.groups[cond.Value]
		if !ok {
			c.fail(b.Name, r.Name, ReasonUnresolvedGroupReference,
				"InGroup names %q, which no group declares", cond.Value)
			return Condition{}, false
		}
		compiled.Values = toSet(clients)
	case model.OperatorContains, model.OperatorExists, model.OperatorNotExists:
	}
	return compiled, true
}

// operatorArity rejects a condition whose parameters do not fit its operator:
// a foreign parameter means part of the author's intent would be silently
// dropped, and this model keeps authoring mistakes loud.
func (c *policyCompiler) operatorArity(b model.Block, r model.Rule, cond model.Condition) bool {
	bad := func(format string, args ...any) bool {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, format, args...)
		return false
	}
	switch cond.Operator {
	case model.OperatorEquals, model.OperatorContains, model.OperatorInGroup:
		if cond.Value == "" || len(cond.Values) > 0 {
			return bad("%s takes value and nothing else", cond.Operator)
		}
	case model.OperatorIn:
		if len(cond.Values) == 0 || cond.Value != "" {
			return bad("In takes a non-empty values list and nothing else")
		}
	case model.OperatorExists, model.OperatorNotExists:
		if cond.Value != "" || len(cond.Values) > 0 {
			return bad("%s takes no parameters", cond.Operator)
		}
	default:
		return bad("unknown operator %q", cond.Operator)
	}
	return true
}

func (c *policyCompiler) compileCounters(b model.Block, r model.Rule, blockKeys map[string]bool) {
	if len(r.Counters) > model.MaxCountersPerRule {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "counters exceed the limit of %d", model.MaxCountersPerRule)
	}
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

func (c *policyCompiler) compileRates(b model.Block, r model.Rule, behavior model.Behavior) []Rate {
	if behavior == model.BehaviorBypass {
		if len(r.Rates) > 0 {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "a Bypass rule carries no rates")
		}
		return nil
	}
	if len(r.Rates) == 0 {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "a counting rule carries at least one rates entry")
		return nil
	}
	if len(r.Rates) > model.MaxRatesPerRule {
		c.fail(b.Name, r.Name, ReasonInvalidSpec, "rates exceed the limit of %d", model.MaxRatesPerRule)
		return nil
	}

	out := make([]Rate, 0, len(r.Rates))
	ident := key.Ident{Domain: c.domain, Policy: c.policy.Name, Block: b.Name, Rule: r.Name}
	periods := map[time.Duration]struct{}{}
	for _, rate := range r.Rates {
		if _, dup := periods[rate.Period]; dup {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "two rates entries share the period %s", rate.Period)
			continue
		}
		periods[rate.Period] = struct{}{}

		name := rate.Algorithm
		if name == "" {
			name = "GCRA"
		}
		a, ok := algo.ByName(name)
		if !ok {
			c.fail(b.Name, r.Name, ReasonInvalidSpec, "unknown algorithm %q; known: %v", rate.Algorithm, algo.Names())
			continue
		}

		w := algo.Window{Requests: rate.Requests, Period: rate.Period, Burst: rate.Burst}
		if a.ID() == algo.GCRAID && w.Burst == 0 {
			w.Burst = w.Requests // the documented default: a full bucket
		}
		if err := algo.Check(a, w); err != nil {
			c.fail(b.Name, r.Name, ReasonInvalidWindow, "window %s/%s: %v", name, rate.Period, err)
			continue
		}
		out = append(out, Rate{Algorithm: a, Window: w, Prefix: key.RatePrefix(ident, a, w)})
	}
	return out
}

func toSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		out[v] = struct{}{}
	}
	return out
}

package policy

import (
	"encoding/json"
	"fmt"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// MaxResolvedSize bounds the serialized size of a resolved policy: 1.5 MiB
// (1572864 bytes), the largest object etcd accepts. A preset can therefore
// produce nothing that one object could not hold written out, and the payload
// bound of the service keeps resting on the object size.
const MaxResolvedSize = 1536 * 1024

// RuleRef addresses one rule of a policy by the names of its block and of the
// rule, the address a RuleProblem carries.
type RuleRef struct {
	Block string
	Rule  string
}

// Resolved is a policy spec with its presets written out.
type Resolved struct {
	// Spec is the resolved spec: every rule that took a preset is the merge
	// of the two, mode, behavior, and algorithm carry the compiler's defaults
	// where every layer left them out, and presets and preset are gone. It
	// is what the engine compiles, what the ConfigMap carries, and what
	// last-good holds.
	Spec v1.RateLimitPolicySpec

	// Presets names, for every rule that took a preset, the preset it took,
	// so that a problem the compiler reports at the rule can name it.
	Presets map[RuleRef]string

	// EstimatedSize is the estimate the size bound was checked against, in
	// bytes: the serialized size of the spec as written with the defaults
	// written in, plus the size of each preset, with its defaults written
	// in, once per rule that takes it. It is at least the serialized size of
	// Spec, because a field a rule replaces is counted in both layers.
	EstimatedSize int
}

// Resolve writes the presets of a spec into the rules that take them. A spec
// that uses no preset resolves to itself with the defaults written in.
//
// Every problem is blocking, and a spec with one resolves to nothing: a
// preset a rule names that spec.presets.rules does not hold
// (UnresolvedPresetReference), a resolved policy estimated above
// [MaxResolvedSize] (ResolvedPolicyTooLarge), a preset declared twice or
// without a name, and a preset body that names a preset (InvalidSpec). The
// estimate, [Resolved.EstimatedSize], is made before any preset is written
// into a rule and never falls below the resolved size, so it can refuse a
// policy whose resolved size is below the bound.
func Resolve(spec *v1.RateLimitPolicySpec) (*Resolved, []v1.RuleProblem) {
	r := &resolver{presets: map[string]*v1.Rule{}}
	r.declarePresets(spec)
	uses := r.checkReferences(spec)
	estimated := r.checkSize(spec, uses)
	if len(r.problems) > 0 {
		return nil, r.problems
	}

	out := &Resolved{Spec: *spec.DeepCopy(), Presets: map[RuleRef]string{}, EstimatedSize: estimated}
	out.Spec.Presets = nil
	for b := range out.Spec.Limits {
		block := &out.Spec.Limits[b]
		for i := range block.Rules {
			rule := &block.Rules[i]
			if rule.Preset != "" {
				out.Presets[RuleRef{Block: block.Name, Rule: rule.Name}] = rule.Preset
				*rule = mergeRule(rule, r.presets[rule.Preset])
			}
		}
		applyBlockDefaults(block)
	}
	return out, nil
}

// resolver collects the presets of one spec and the problems found on the
// way, so the checks stay small and report through one place.
type resolver struct {
	presets  map[string]*v1.Rule
	problems []v1.RuleProblem
}

func (r *resolver) fail(block, rule, reason, format string, args ...any) {
	r.problems = append(r.problems, v1.RuleProblem{
		Block:   block,
		Rule:    rule,
		Reason:  reason,
		Message: fmt.Sprintf(format, args...),
	})
}

// declarePresets indexes the rule presets by name and checks the shape of
// each, whether a rule takes it or not. A problem of a preset has no block
// and no rule to be addressed to, so the message names the preset.
func (r *resolver) declarePresets(spec *v1.RateLimitPolicySpec) {
	if spec.Presets == nil {
		return
	}
	for i := range spec.Presets.Rules {
		preset := &spec.Presets.Rules[i]
		if preset.Name == "" {
			r.fail("", "", v1.ProblemInvalidSpec, "a rule preset without a name")
			continue
		}
		if _, dup := r.presets[preset.Name]; dup {
			r.fail("", "", v1.ProblemInvalidSpec, "rule preset %q is declared twice", preset.Name)
			continue
		}
		if preset.Preset != "" {
			// Reported, and indexed all the same: a rule that takes the
			// preset is then told about the chain, not that the preset is
			// not declared.
			r.fail("", "", v1.ProblemInvalidSpec,
				"rule preset %q names preset %q; a preset body carries no preset of its own", preset.Name, preset.Preset)
		}
		r.presets[preset.Name] = preset
	}
}

// checkReferences reports every rule whose preset is not declared, and counts
// how many rules take each preset for the size estimate.
func (r *resolver) checkReferences(spec *v1.RateLimitPolicySpec) map[string]int {
	uses := map[string]int{}
	for _, block := range spec.Limits {
		for _, rule := range block.Rules {
			if rule.Preset == "" {
				continue
			}
			if _, ok := r.presets[rule.Preset]; !ok {
				r.fail(block.Name, rule.Name, v1.ProblemUnresolvedPresetReference,
					"preset %q is not declared under spec.presets.rules", rule.Preset)
				continue
			}
			uses[rule.Preset]++
		}
	}
	return uses
}

// checkSize refuses a policy whose resolved form is estimated above
// [MaxResolvedSize] and returns the estimate: the serialized size of the
// spec as written with the defaults written in, plus each preset's size,
// with its defaults written in, once per rule that takes it. The defaults
// are counted on both sides because the resolved rule carries them where
// every layer left the field out, and a field present in both is counted
// twice, so the estimate never falls below the resolved size.
func (r *resolver) checkSize(spec *v1.RateLimitPolicySpec, uses map[string]int) int {
	written := spec.DeepCopy()
	for b := range written.Limits {
		applyBlockDefaults(&written.Limits[b])
	}
	total := serializedSize(written)
	for name, n := range uses {
		preset := r.presets[name].DeepCopy()
		applyRuleDefaults(preset)
		total += n * serializedSize(preset)
	}
	if total > MaxResolvedSize {
		r.fail("", "", v1.ProblemResolvedPolicyTooLarge,
			"the resolved policy is estimated at %d bytes serialized, over the limit of %d bytes (1.5 MiB)",
			total, MaxResolvedSize)
	}
	return total
}

// serializedSize is the length of v as JSON. The spec types marshal without
// error, so a failure is a programming error.
func serializedSize(v any) int {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal a RateLimitPolicy spec: %v", err))
	}
	return len(raw)
}

// mergeRule is the rule of the point of use over its preset: a copy of the
// preset with every field the rule wrote on top, whole. A list the rule
// wrote empty is a value and replaces the preset's list; a list it left out
// is nil and keeps it. The result carries the rule's own name and no preset.
func mergeRule(use, preset *v1.Rule) v1.Rule {
	written := use.DeepCopy()
	out := preset.DeepCopy()
	out.Name = written.Name
	out.Preset = ""
	if written.Matches != nil {
		out.Matches = written.Matches
	}
	if written.Counters != nil {
		out.Counters = written.Counters
	}
	if written.Rates != nil {
		out.Rates = written.Rates
	}
	if written.Behavior != "" {
		out.Behavior = written.Behavior
	}
	if written.ReplacedRules != nil {
		out.ReplacedRules = written.ReplacedRules
	}
	return *out
}

// applyBlockDefaults writes the compiler's defaults into a resolved block and
// its rules, once, after the last layer: an absent mode is All.
func applyBlockDefaults(block *v1.LimitBlock) {
	if block.Mode == "" {
		block.Mode = v1.BlockModeAll
	}
	for i := range block.Rules {
		applyRuleDefaults(&block.Rules[i])
	}
}

// applyRuleDefaults writes the compiler's defaults into a resolved rule: an
// absent behavior is Enforce and an absent algorithm is GCRA.
func applyRuleDefaults(rule *v1.Rule) {
	if rule.Behavior == "" {
		rule.Behavior = v1.RuleBehaviorEnforce
	}
	for i := range rule.Rates {
		if rule.Rates[i].Algorithm == "" {
			rule.Rates[i].Algorithm = v1.AlgorithmGCRA
		}
	}
}

package policy

import (
	"encoding/json"
	"fmt"
	"slices"

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
	// Spec is the resolved spec: every block that took a preset is the merge
	// of the two, every rule that took a preset likewise, mode, behavior,
	// and algorithm carry the compiler's defaults where every layer left
	// them out, and presets, preset, before, and drop are gone. It is what
	// the engine compiles, what the ConfigMap carries, and what last-good
	// holds.
	Spec v1.RateLimitPolicySpec

	// Presets names, for every rule that took a rule preset, the preset it
	// took, so that a problem the compiler reports at the rule can name it.
	// A rule a block took from its block preset is listed under the block's
	// own name.
	Presets map[RuleRef]string

	// BlockPresets names, for every block that took a block preset, the
	// preset it took, so that a problem the compiler reports in the block
	// can name it.
	BlockPresets map[string]string

	// EstimatedSize is the estimate the size bound was checked against, in
	// bytes: the serialized size of the spec as written with the defaults
	// written in, plus the size of each preset, with its defaults written
	// in, once per rule or block that takes it, less the rules that drop
	// names. It is at least the serialized size of Spec, because a field a
	// layer replaces is counted in both layers.
	EstimatedSize int
}

// Resolve writes the presets of a spec into the blocks and rules that take
// them. A spec that uses no preset resolves to itself with the defaults
// written in.
//
// Every problem is blocking, and a spec with one resolves to nothing. A
// preset a rule or a block names that spec.presets does not hold, a before
// that names a rule neither in the block's preset nor written earlier in the
// list, and a drop that names a rule the block's preset does not hold are
// UnresolvedPresetReference. A resolved policy estimated above
// [MaxResolvedSize] is ResolvedPolicyTooLarge. A preset declared twice or
// without a name, a preset body that names a preset or carries before or
// drop, before or drop in a block without a preset, drop beside any field
// other than name, before on a rule the block's preset holds, and preset on
// a rule that overrides a rule of the block's preset by name are
// InvalidSpec. The estimate, [Resolved.EstimatedSize], is made before any
// preset is written into a block or a rule and never falls below the
// resolved size, so it can refuse a policy whose resolved size is below the
// bound.
func Resolve(spec *v1.RateLimitPolicySpec) (*Resolved, []v1.RuleProblem) {
	r := &resolver{rulePresets: map[string]*v1.Rule{}, blockPresets: map[string]*v1.LimitBlock{}}
	r.declareRulePresets(spec)
	r.declareBlockPresets(spec)
	uses := r.checkReferences(spec)
	estimated := r.checkSize(spec, uses)
	if len(r.problems) > 0 {
		return nil, r.problems
	}

	out := &Resolved{
		Spec:          *spec.DeepCopy(),
		Presets:       map[RuleRef]string{},
		BlockPresets:  map[string]string{},
		EstimatedSize: estimated,
	}
	out.Spec.Presets = nil
	for b := range out.Spec.Limits {
		block := &out.Spec.Limits[b]
		if block.Preset != "" {
			out.BlockPresets[block.Name] = block.Preset
			*block = mergeBlock(block, r.blockPresets[block.Preset])
		}
		for i := range block.Rules {
			rule := &block.Rules[i]
			if rule.Preset != "" {
				out.Presets[RuleRef{Block: block.Name, Rule: rule.Name}] = rule.Preset
				*rule = mergeRule(rule, r.rulePresets[rule.Preset])
			}
		}
		applyBlockDefaults(block)
	}
	return out, nil
}

// resolver collects the presets of one spec and the problems found on the
// way, so the checks stay small and report through one place.
type resolver struct {
	rulePresets  map[string]*v1.Rule
	blockPresets map[string]*v1.LimitBlock
	problems     []v1.RuleProblem
}

func (r *resolver) fail(block, rule, reason, format string, args ...any) {
	r.problems = append(r.problems, v1.RuleProblem{
		Block:   block,
		Rule:    rule,
		Reason:  reason,
		Message: fmt.Sprintf(format, args...),
	})
}

// declareRulePresets indexes the rule presets by name and checks the shape
// of each, whether a rule takes it or not. A problem of a preset has no block
// and no rule to be addressed to, so the message names the preset.
func (r *resolver) declareRulePresets(spec *v1.RateLimitPolicySpec) {
	if spec.Presets == nil {
		return
	}
	for i := range spec.Presets.Rules {
		preset := &spec.Presets.Rules[i]
		if preset.Name == "" {
			r.fail("", "", v1.ProblemInvalidSpec, "a rule preset without a name")
			continue
		}
		if _, dup := r.rulePresets[preset.Name]; dup {
			r.fail("", "", v1.ProblemInvalidSpec, "rule preset %q is declared twice", preset.Name)
			continue
		}
		// Reported, and indexed all the same: a rule that takes the preset
		// is then told about the chain, not that the preset is not
		// declared.
		if preset.Preset != "" {
			r.fail("", "", v1.ProblemInvalidSpec,
				"rule preset %q names preset %q; a preset body carries no preset of its own", preset.Name, preset.Preset)
		}
		if preset.Before != "" || preset.Drop {
			r.fail("", "", v1.ProblemInvalidSpec,
				"rule preset %q carries before or drop, which a rule of a block that takes a block preset carries", preset.Name)
		}
		r.rulePresets[preset.Name] = preset
	}
}

// declareBlockPresets indexes the block presets by name and checks the shape
// of each, whether a block takes it or not: a body carries no preset, and
// its rules carry no before or drop. A rule preset its rules name is a
// reference, checked through the blocks that take the body.
func (r *resolver) declareBlockPresets(spec *v1.RateLimitPolicySpec) {
	if spec.Presets == nil {
		return
	}
	for i := range spec.Presets.Blocks {
		preset := &spec.Presets.Blocks[i]
		if preset.Name == "" {
			r.fail("", "", v1.ProblemInvalidSpec, "a block preset without a name")
			continue
		}
		if _, dup := r.blockPresets[preset.Name]; dup {
			r.fail("", "", v1.ProblemInvalidSpec, "block preset %q is declared twice", preset.Name)
			continue
		}
		if preset.Preset != "" {
			r.fail("", "", v1.ProblemInvalidSpec,
				"block preset %q names preset %q; a preset body carries no preset of its own", preset.Name, preset.Preset)
		}
		for _, rule := range preset.Rules {
			if rule.Before != "" || rule.Drop {
				r.fail("", "", v1.ProblemInvalidSpec,
					"rule %q of block preset %q carries before or drop, which a block that takes the preset carries",
					rule.Name, preset.Name)
			}
		}
		r.blockPresets[preset.Name] = preset
	}
}

// presetUses is what the size estimate needs: how many times each preset is
// taken, and the serialized size of the preset rules that drop leaves out.
type presetUses struct {
	rules   map[string]int
	blocks  map[string]int
	dropped int
}

// checkReferences reports every reference that does not resolve and every
// rule shape a block may not carry, and counts the uses of each preset for
// the size estimate.
func (r *resolver) checkReferences(spec *v1.RateLimitPolicySpec) presetUses {
	uses := presetUses{rules: map[string]int{}, blocks: map[string]int{}}
	for _, block := range spec.Limits {
		if block.Preset == "" {
			for _, rule := range block.Rules {
				if rule.Before != "" || rule.Drop {
					r.fail(block.Name, rule.Name, v1.ProblemInvalidSpec,
						"before and drop apply in a block that takes a block preset; this block takes none")
				}
				r.checkRulePreset(block.Name, &rule, &uses)
			}
			continue
		}
		preset, ok := r.blockPresets[block.Preset]
		if !ok {
			r.fail(block.Name, "", v1.ProblemUnresolvedPresetReference,
				"preset %q is not declared under spec.presets.blocks", block.Preset)
			for _, rule := range block.Rules {
				r.checkRulePreset(block.Name, &rule, &uses)
			}
			continue
		}
		uses.blocks[block.Preset]++
		r.checkBlockUse(&block, preset, &uses)
	}
	return uses
}

// checkRulePreset reports a rule preset the rule names that is not declared,
// and counts the use otherwise.
func (r *resolver) checkRulePreset(block string, rule *v1.Rule, uses *presetUses) {
	if rule.Preset == "" {
		return
	}
	if _, ok := r.rulePresets[rule.Preset]; !ok {
		r.fail(block, rule.Name, v1.ProblemUnresolvedPresetReference,
			"preset %q is not declared under spec.presets.rules", rule.Preset)
		return
	}
	uses.rules[rule.Preset]++
}

// checkBlockUse checks the rules a block writes against the block preset it
// takes: an override carries no before and no preset, a drop carries nothing
// beside its name and names a rule of the preset, and a new rule's before
// names a rule of the preset or a new rule written earlier. The rule presets
// the preset's own rules take count once per block that takes the preset,
// less the rules the block drops.
func (r *resolver) checkBlockUse(block *v1.LimitBlock, preset *v1.LimitBlock, uses *presetUses) {
	held := map[string]*v1.Rule{}
	for i := range preset.Rules {
		held[preset.Rules[i].Name] = &preset.Rules[i]
	}
	dropped := map[string]bool{}
	earlier := map[string]bool{}
	for _, rule := range block.Rules {
		presetRule, inPreset := held[rule.Name]
		switch {
		case rule.Drop && !inPreset:
			r.fail(block.Name, rule.Name, v1.ProblemUnresolvedPresetReference,
				"drop names rule %q, which block preset %q does not hold", rule.Name, block.Preset)
		case rule.Drop:
			if !dropOnly(&rule) {
				r.fail(block.Name, rule.Name, v1.ProblemInvalidSpec,
					"a rule with drop carries nothing beside name")
			}
			dropped[rule.Name] = true
			uses.dropped += serializedSize(presetRule)
		case inPreset:
			if rule.Before != "" {
				r.fail(block.Name, rule.Name, v1.ProblemInvalidSpec,
					"before on rule %q, which block preset %q holds; an overridden rule keeps the preset's position",
					rule.Name, block.Preset)
			}
			if rule.Preset != "" {
				r.fail(block.Name, rule.Name, v1.ProblemInvalidSpec,
					"preset on rule %q, which overrides a rule of block preset %q by name", rule.Name, block.Preset)
			}
		default:
			if rule.Before != "" && held[rule.Before] == nil && !earlier[rule.Before] {
				r.fail(block.Name, rule.Name, v1.ProblemUnresolvedPresetReference,
					"before names rule %q, which is neither in block preset %q nor written earlier in the list",
					rule.Before, block.Preset)
			}
			earlier[rule.Name] = true
			r.checkRulePreset(block.Name, &rule, uses)
		}
	}
	for _, rule := range preset.Rules {
		if dropped[rule.Name] || rule.Preset == "" {
			continue
		}
		if _, ok := r.rulePresets[rule.Preset]; !ok {
			r.fail(block.Name, rule.Name, v1.ProblemUnresolvedPresetReference,
				"preset %q is not declared under spec.presets.rules; the block takes preset %q", rule.Preset, block.Preset)
			continue
		}
		uses.rules[rule.Preset]++
	}
}

// dropOnly reports a rule that carries nothing beside its name and drop.
func dropOnly(rule *v1.Rule) bool {
	return rule.Preset == "" && rule.Before == "" && rule.Matches == nil && rule.Counters == nil &&
		rule.Rates == nil && rule.Behavior == "" && rule.ReplacedRules == nil
}

// checkSize refuses a policy whose resolved form is estimated above
// [MaxResolvedSize] and returns the estimate: the serialized size of the
// spec as written with the defaults written in, plus each preset's size,
// with its defaults written in, once per rule or block that takes it, less
// the preset rules the blocks drop. The defaults are counted on both sides
// because the resolved rule carries them where every layer left the field
// out, and a field present in both is counted twice, so the estimate never
// falls below the resolved size.
func (r *resolver) checkSize(spec *v1.RateLimitPolicySpec, uses presetUses) int {
	written := spec.DeepCopy()
	for b := range written.Limits {
		applyBlockDefaults(&written.Limits[b])
	}
	total := serializedSize(written)
	for name, n := range uses.rules {
		preset := r.rulePresets[name].DeepCopy()
		applyRuleDefaults(preset)
		total += n * serializedSize(preset)
	}
	for name, n := range uses.blocks {
		preset := r.blockPresets[name].DeepCopy()
		applyBlockDefaults(preset)
		total += n * serializedSize(preset)
	}
	total -= uses.dropped
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

// mergeBlock is the block of the point of use over its preset: a copy of the
// preset with the target and the mode the block wrote on top, and the rules
// merged by name in three passes over the preset's list. Overrides first,
// in place: a rule of a name the preset holds replaces the preset's rule
// field by field and keeps the preset rule's own rule preset. Then the
// insertions, in the order written, each directly in front of the rule its
// before names or at the end. Then the drops, so a dropped rule serves as an
// anchor until then. The result carries the block's own name, no preset, and
// rules with no before and no drop.
func mergeBlock(use, preset *v1.LimitBlock) v1.LimitBlock {
	written := use.DeepCopy()
	out := preset.DeepCopy()
	out.Name = written.Name
	out.Preset = ""
	if written.Target != nil {
		out.Target = written.Target
	}
	if written.Mode != "" {
		out.Mode = written.Mode
	}

	index := func(name string) int {
		return slices.IndexFunc(out.Rules, func(rule v1.Rule) bool { return rule.Name == name })
	}
	for i := range written.Rules {
		rule := &written.Rules[i]
		if at := index(rule.Name); at >= 0 && !rule.Drop {
			out.Rules[at] = overrideRule(rule, &out.Rules[at])
		}
	}
	for i := range written.Rules {
		rule := &written.Rules[i]
		if rule.Drop || index(rule.Name) >= 0 {
			continue
		}
		inserted := *rule
		inserted.Before = ""
		if at := index(rule.Before); rule.Before != "" && at >= 0 {
			out.Rules = slices.Insert(out.Rules, at, inserted)
		} else {
			out.Rules = append(out.Rules, inserted)
		}
	}
	for _, rule := range written.Rules {
		if rule.Drop {
			if at := index(rule.Name); at >= 0 {
				out.Rules = slices.Delete(out.Rules, at, at+1)
			}
		}
	}
	return *out
}

// overrideRule is a rule of the point of use over the rule of the same name
// in the block preset: [mergeRule] with the preset rule's own rule preset
// kept, so that the rule preset, the block preset's rule, and the point of
// use apply in that order.
func overrideRule(written, base *v1.Rule) v1.Rule {
	out := mergeRule(written, base)
	out.Preset = base.Preset
	return out
}

// mergeRule is the rule of the point of use over its preset: a copy of the
// preset with every field the rule wrote on top, whole. A list the rule
// wrote empty is a value and replaces the preset's list; a list it left out
// is nil and keeps it. The result carries the rule's own name and no preset,
// before, or drop.
func mergeRule(use, preset *v1.Rule) v1.Rule {
	written := use.DeepCopy()
	out := preset.DeepCopy()
	out.Name = written.Name
	out.Preset = ""
	out.Before = ""
	out.Drop = false
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

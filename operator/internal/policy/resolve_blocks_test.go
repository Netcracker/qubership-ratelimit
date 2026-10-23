package policy

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// Block presets: a block of spec.limits takes a body of target, mode, and
// rules, and its own rules merge with the preset's by name.

// internalBypass is the rule preset the cascade starts with.
func internalBypass() v1.RulePreset {
	return v1.RulePreset{
		Name:     "internal-bypass",
		Matches:  []v1.Predicate{{Key: "sub", Operator: v1.OperatorEquals, Value: "prometheus"}},
		Behavior: v1.RuleBehaviorBypass,
	}
}

// planCascade is the block preset of the resource specification: a
// FirstMatch cascade of plans with no target, so every block that takes it
// brings one. Two of its rules take rule presets.
func planCascade() v1.BlockPreset {
	return v1.BlockPreset{
		Name: "plan-cascade",
		Mode: v1.BlockModeFirstMatch,
		Rules: []v1.Rule{
			{Name: "internal", Preset: "internal-bypass"},
			{Name: "enterprise",
				Matches:  []v1.Predicate{{Key: "plan", Operator: v1.OperatorEquals, Value: "enterprise"}},
				Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(1000)}},
			{Name: "per-user", Preset: "standard-client"},
			{Name: "anonymous", Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorDoesNotExist}},
				Counters: []string{}, Rates: []v1.Rate{minuteRate(20)}},
		},
	}
}

func prefixTarget(prefix string) *v1.Target {
	return &v1.Target{Routes: []v1.Route{{Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: prefix}}}}
}

// cascadeSpec is the domain's spec with the two rule presets, the cascade,
// and the given blocks.
func cascadeSpec(blocks ...v1.LimitBlock) *v1.RateLimitPolicySpec {
	return &v1.RateLimitPolicySpec{
		Domain: testDomain,
		Presets: &v1.Presets{
			Rules:  []v1.RulePreset{internalBypass(), standardClient()},
			Blocks: []v1.BlockPreset{planCascade()},
		},
		Limits: blocks,
	}
}

func ruleNames(block v1.LimitBlock) []string {
	names := make([]string, 0, len(block.Rules))
	for _, rule := range block.Rules {
		names = append(names, rule.Name)
	}
	return names
}

// The fields of a block preset are the fields of a block except preset, the
// one authoring field of a block. Both sets are read from the types, so a
// field added to LimitBlock and left out of BlockPreset fails here rather
// than being unavailable to a preset without a word.
func TestResolve_aBlockPresetHasEveryFieldOfABlockExceptPreset(t *testing.T) {
	blockFields := map[string]bool{}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[v1.LimitBlock]()) {
		if field.Name != "Preset" {
			blockFields[field.Name] = true
		}
	}
	presetFields := map[string]bool{}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[v1.BlockPreset]()) {
		presetFields[field.Name] = true
	}

	assert.Equal(t, blockFields, presetFields, "fields of v1.BlockPreset, against those of v1.LimitBlock")
}

// A block that writes a target and leaves the mode and the rules out takes
// them from its preset, the rules with the rule presets they name, and keeps
// its own name.
func TestResolve_aBlockTakesItsPresetUnderItsOwnNameAndTarget(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Target: prefixTarget("/orders")})
	spec.Presets.Blocks[0].Target = prefixTarget("/default")

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	require.Len(t, resolved.Spec.Limits, 1, "Resolved.Spec.Limits")
	orders := resolved.Spec.Limits[0]
	assert.Equal(t, "orders", orders.Name, "Name of the resolved block")
	assert.Empty(t, orders.Preset, "Preset of the resolved block")
	assert.Equal(t, prefixTarget("/orders"), orders.Target, "Target of the resolved block, written")
	assert.Equal(t, v1.BlockModeFirstMatch, orders.Mode, "Mode of the resolved block, left out")
	assert.Equal(t, []string{"internal", "enterprise", perUserName, "anonymous"}, ruleNames(orders),
		"rules of the resolved block")
	assert.Equal(t, v1.RuleBehaviorBypass, resolvedRule(t, resolved, "internal").Behavior,
		"Behavior of rule internal, from its rule preset internal-bypass")
	assert.Equal(t, []string{"sub"}, resolvedRule(t, resolved, perUserName).Counters,
		"Counters of rule per-user, from its rule preset standard-client")
	assert.Equal(t, map[string]string{"orders": "plan-cascade"}, resolved.BlockPresets, "Resolved.BlockPresets")
	assert.Equal(t, map[RuleRef]string{
		{Block: "orders", Rule: "internal"}:  "internal-bypass",
		{Block: "orders", Rule: perUserName}: "standard-client",
	}, resolved.Presets, "Resolved.Presets, where a rule the block took from its preset is under the block's name")
}

func TestResolve_aBlockThatWritesAModeTakesTheTargetOfItsPreset(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Mode: v1.BlockModeAll})
	spec.Presets.Blocks[0].Target = prefixTarget("/default")

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	orders := resolved.Spec.Limits[0]
	assert.Equal(t, prefixTarget("/default"), orders.Target, "Target of the resolved block, left out")
	assert.Equal(t, v1.BlockModeAll, orders.Mode, "Mode of the resolved block, written")
}

// The rules of the block merge with the preset's in three passes: overrides
// in place, then insertions in the order written, then drops, with a dropped
// rule serving as an anchor until the drops run. Every case asserts the
// order of the merged rules, that no rule carries before, dropped, or preset
// any more, and that the preset's per-user, which no case overrides, is
// still listed with the rule preset it took.
func TestResolve_theRulesOfTheBlockMergeWithThePresetsByName(t *testing.T) {
	partner := v1.Rule{Name: "partner",
		Matches:  []v1.Predicate{{Key: "sub", Operator: v1.OperatorInGroup, Value: "partners"}},
		Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(500)}}
	vip := v1.Rule{Name: "vip", Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(900)}}
	withBefore := func(rule v1.Rule, before string) v1.Rule {
		rule.Before = before
		return rule
	}
	cases := []struct {
		name  string
		rules []v1.Rule
		order []string
	}{
		{
			name:  "a new rule without before goes after the preset's rules",
			rules: []v1.Rule{partner},
			order: []string{"internal", "enterprise", "per-user", "anonymous", "partner"},
		},
		{
			name:  "a new rule goes in front of the rule its before names",
			rules: []v1.Rule{withBefore(partner, "per-user")},
			order: []string{"internal", "enterprise", "partner", "per-user", "anonymous"},
		},
		{
			name:  "a new rule before the preset's first rule goes first",
			rules: []v1.Rule{withBefore(partner, "internal")},
			order: []string{"partner", "internal", "enterprise", "per-user", "anonymous"},
		},
		{
			name:  "before may name a new rule written earlier in the list",
			rules: []v1.Rule{withBefore(partner, "per-user"), withBefore(vip, "partner")},
			order: []string{"internal", "enterprise", "vip", "partner", "per-user", "anonymous"},
		},
		{
			name:  "two new rules with one anchor keep the order they are written in",
			rules: []v1.Rule{withBefore(partner, "per-user"), withBefore(vip, "per-user")},
			order: []string{"internal", "enterprise", "partner", "vip", "per-user", "anonymous"},
		},
		{
			name:  "dropped leaves the preset's rule out",
			rules: []v1.Rule{{Name: "anonymous", Dropped: true}},
			order: []string{"internal", "enterprise", "per-user"},
		},
		{
			name:  "before with dropped on the same name replaces the rule in place",
			rules: []v1.Rule{withBefore(partner, "anonymous"), {Name: "anonymous", Dropped: true}},
			order: []string{"internal", "enterprise", "per-user", "partner"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: tc.rules})

			resolved, problems := Resolve(spec)

			require.Empty(t, problems, "Resolve problems")
			block := resolved.Spec.Limits[0]
			assert.Equal(t, tc.order, ruleNames(block), "rules of the resolved block")
			for _, rule := range block.Rules {
				assert.Empty(t, rule.Before, "Before of resolved rule %s", rule.Name)
				assert.False(t, rule.Dropped, "Dropped of resolved rule %s", rule.Name)
				assert.Empty(t, rule.Preset, "Preset of resolved rule %s", rule.Name)
			}
			assert.Equal(t, "standard-client", resolved.Presets[RuleRef{Block: "orders", Rule: "per-user"}],
				"Resolved.Presets of orders/per-user")
		})
	}
}

// An override by name keeps the preset rule's position and the rule preset
// that rule takes, and replaces the fields it writes.
func TestResolve_anOverrideKeepsThePresetsPositionAndReplacesTheFieldsItWrites(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
		{Name: perUserName, Rates: []v1.Rate{minuteRate(300)}},
	}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, []string{"internal", "enterprise", perUserName, "anonymous"}, ruleNames(resolved.Spec.Limits[0]),
		"rules of the resolved block")
	perUser := resolvedRule(t, resolved, perUserName)
	assert.Equal(t, []v1.Rate{{Requests: 300, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, perUser.Rates,
		"Rates of rule per-user, written")
	assert.Equal(t, []string{"sub"}, perUser.Counters, "Counters of rule per-user, from its rule preset")
	assert.Equal(t, "standard-client", resolved.Presets[RuleRef{Block: "orders", Rule: perUserName}],
		"Resolved.Presets of orders/per-user")
}

func TestResolve_aNewRuleOfTheBlockMayTakeARulePreset(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
		{Name: "vip", Preset: "standard-client", Before: perUserName},
	}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, []string{"internal", "enterprise", "vip", perUserName, "anonymous"},
		ruleNames(resolved.Spec.Limits[0]), "rules of the resolved block")
	vip := resolvedRule(t, resolved, "vip")
	burst := int32(20)
	assert.Equal(t, []string{"sub"}, vip.Counters, "Counters of rule vip")
	assert.Equal(t, []v1.Rate{
		{Requests: 100, PeriodSeconds: 60, Burst: &burst, Algorithm: v1.AlgorithmGCRA},
		{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow},
	}, vip.Rates, "Rates of rule vip")
	assert.Equal(t, "standard-client", resolved.Presets[RuleRef{Block: "orders", Rule: "vip"}],
		"Resolved.Presets of orders/vip")
}

func TestResolve_anOverrideAnInsertionAndADropApplyInOneBlock(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
		{Name: "enterprise", Rates: []v1.Rate{minuteRate(2000)}},
		{Name: "partner", Before: perUserName, Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(500)}},
		{Name: "internal", Dropped: true},
	}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, []string{"enterprise", "partner", perUserName, "anonymous"}, ruleNames(resolved.Spec.Limits[0]),
		"rules of the resolved block")
	assert.Equal(t, []v1.Rate{{Requests: 2000, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}},
		resolvedRule(t, resolved, "enterprise").Rates, "Rates of rule enterprise, written")
}

// A dropped rule carries nothing beside its name: every other field of
// Rule, set alone beside dropped, is refused. The set of fields is read from
// the type, so a field added to Rule and left out of the check fails here.
func TestResolve_aDroppedRuleCarriesNothingBesideItsName(t *testing.T) {
	for field := range reflect.TypeFor[v1.Rule]().Fields() {
		if field.Name == "Name" || field.Name == "Dropped" {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			rule := v1.Rule{Name: "anonymous", Dropped: true}
			fill(t, reflect.ValueOf(&rule).Elem().FieldByName(field.Name))

			resolved, problems := Resolve(cascadeSpec(
				v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{rule}}))

			assert.Nil(t, resolved, "Resolved")
			assert.Equal(t, []v1.RuleProblem{{Block: "orders", Rule: "anonymous", Reason: v1.ProblemInvalidSpec}},
				withoutMessage(problems), "Resolve problems with dropped beside %s", field.Name)
		})
	}
}

// Up to three layers apply to one rule, in this order: the rule preset, the
// rule of the block preset, the rule at the point of use. A rule of the block
// preset keeps its own rule preset under an override by name. Each pair of
// layers sets one field in both, so the order of every pair is established:
// counters by the first two, behavior by the last two, rates by the outer
// two, and matches by the first layer alone.
func TestResolve_threeLayersApplyToOneRuleInOrder(t *testing.T) {
	base := v1.RulePreset{Name: "base", Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorExists}},
		Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(100)}}
	spec := &v1.RateLimitPolicySpec{
		Domain: testDomain,
		Presets: &v1.Presets{
			Rules: []v1.RulePreset{base},
			Blocks: []v1.BlockPreset{{Name: "cascade", Rules: []v1.Rule{
				{Name: "per-user", Preset: "base", Counters: []string{}, Behavior: v1.RuleBehaviorShadow},
			}}},
		},
		Limits: []v1.LimitBlock{{Name: "orders", Preset: "cascade", Rules: []v1.Rule{
			{Name: "per-user", Rates: []v1.Rate{minuteRate(300)}, Behavior: v1.RuleBehaviorEnforce},
		}}},
	}

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	perUser := resolvedRule(t, resolved, perUserName)
	assert.Equal(t, base.Matches, perUser.Matches, "Matches of rule per-user, written in the rule preset alone")
	assert.Equal(t, []string{}, perUser.Counters,
		"Counters of rule per-user, written in the rule preset and in the rule of the block preset")
	assert.Equal(t, v1.RuleBehaviorEnforce, perUser.Behavior,
		"Behavior of rule per-user, written in the rule of the block preset and at the point of use")
	assert.Equal(t, []v1.Rate{{Requests: 300, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, perUser.Rates,
		"Rates of rule per-user, written in the rule preset and at the point of use")
	assert.Equal(t, "base", resolved.Presets[RuleRef{Block: "orders", Rule: "per-user"}],
		"Resolved.Presets of orders/per-user")
}

// A reference of a block that does not resolve is reported at the block and
// the rule of the point of use, and the message names the reference.
func TestResolve_reportsAnUnresolvedReferenceOfABlockAtThePointOfUse(t *testing.T) {
	cases := []struct {
		name  string
		block v1.LimitBlock
		want  v1.RuleProblem
		names string
	}{
		{
			name:  "a block preset nothing declares",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascad"},
			want:  v1.RuleProblem{Block: "orders", Reason: v1.ProblemUnresolvedPresetReference},
			names: `"plan-cascad"`,
		},
		{
			name: "dropped on a rule the preset does not hold",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "ghost", Dropped: true},
			}},
			want:  v1.RuleProblem{Block: "orders", Rule: "ghost", Reason: v1.ProblemUnresolvedPresetReference},
			names: `"ghost"`,
		},
		{
			name: "before of a rule neither in the preset nor written earlier",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "partner", Before: "vip", Rates: []v1.Rate{minuteRate(1)}},
				{Name: "vip", Rates: []v1.Rate{minuteRate(1)}},
			}},
			want:  v1.RuleProblem{Block: "orders", Rule: "partner", Reason: v1.ProblemUnresolvedPresetReference},
			names: `"vip"`,
		},
		{
			name: "a new rule naming a rule preset nothing declares",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "vip", Preset: "standard-clinet", Before: perUserName},
			}},
			want:  v1.RuleProblem{Block: "orders", Rule: "vip", Reason: v1.ProblemUnresolvedPresetReference},
			names: `"standard-clinet"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolved, problems := Resolve(cascadeSpec(tc.block))

			assert.Nil(t, resolved, "Resolved")
			require.Equal(t, []v1.RuleProblem{tc.want}, withoutMessage(problems), "Resolve problems")
			assert.Contains(t, problems[0].Message, tc.names, "Message of the problem")
		})
	}
}

// A rule shape that a block may not carry is InvalidSpec at the block and the
// rule of the point of use.
func TestResolve_rejectsARuleShapeABlockMayNotCarryAtThePointOfUse(t *testing.T) {
	cases := []struct {
		name  string
		block v1.LimitBlock
		want  v1.RuleProblem
	}{
		{
			name: "before in a block that takes no preset",
			block: v1.LimitBlock{Name: "api", Rules: []v1.Rule{
				{Name: "x", Before: "y", Rates: []v1.Rate{minuteRate(1)}},
			}},
			want: v1.RuleProblem{Block: "api", Rule: "x", Reason: v1.ProblemInvalidSpec},
		},
		{
			name:  "dropped in a block that takes no preset",
			block: v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "x", Dropped: true}}},
			want:  v1.RuleProblem{Block: "api", Rule: "x", Reason: v1.ProblemInvalidSpec},
		},
		{
			name: "dropped beside a field",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "anonymous", Dropped: true, Rates: []v1.Rate{minuteRate(1)}},
			}},
			want: v1.RuleProblem{Block: "orders", Rule: "anonymous", Reason: v1.ProblemInvalidSpec},
		},
		{
			name: "before on a rule the preset holds",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "anonymous", Before: "internal"},
			}},
			want: v1.RuleProblem{Block: "orders", Rule: "anonymous", Reason: v1.ProblemInvalidSpec},
		},
		{
			name: "preset on a rule that overrides by name",
			block: v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "anonymous", Preset: "standard-client"},
			}},
			want: v1.RuleProblem{Block: "orders", Rule: "anonymous", Reason: v1.ProblemInvalidSpec},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolved, problems := Resolve(cascadeSpec(tc.block))

			assert.Nil(t, resolved, "Resolved")
			assert.Equal(t, []v1.RuleProblem{tc.want}, withoutMessage(problems), "Resolve problems")
		})
	}
}

// A block whose preset does not resolve still has the rule presets of its own
// rules checked, so one generation reports every reference that does not
// resolve; its rule that names a declared rule preset is reported nowhere.
func TestResolve_aBlockWhosePresetDoesNotResolveStillHasItsRulesChecked(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascad", Rules: []v1.Rule{
		{Name: "vip", Preset: "standard-clinet"},
		{Name: "regular", Preset: "standard-client"},
	}})

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved, "Resolved")
	assert.Equal(t, []v1.RuleProblem{
		{Block: "orders", Reason: v1.ProblemUnresolvedPresetReference},
		{Block: "orders", Rule: "vip", Reason: v1.ProblemUnresolvedPresetReference},
	}, withoutMessage(problems), "Resolve problems")
}

// A rule preset that a rule of a block preset names is a reference of the
// body, checked through the blocks that take the rule: reported at each block
// that takes the preset, with both presets named, and at no block that drops
// the rule; a block preset that no block takes has its rule presets checked
// nowhere.
func TestResolve_aRulePresetABlockPresetNamesIsCheckedThroughTheBlocksThatTakeTheRule(t *testing.T) {
	spec := cascadeSpec(
		v1.LimitBlock{Name: "orders", Preset: "plan-cascade"},
		v1.LimitBlock{Name: "catalog", Preset: "plan-cascade"},
		v1.LimitBlock{Name: "exports", Preset: "plan-cascade", Rules: []v1.Rule{{Name: "internal", Dropped: true}}})
	spec.Presets.Blocks[0].Rules[0].Preset = "internal-bypas"
	spec.Presets.Blocks = append(spec.Presets.Blocks,
		v1.BlockPreset{Name: "unused", Rules: []v1.Rule{{Name: "internal", Preset: "internal-bypas"}}})

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved, "Resolved")
	require.Equal(t, []v1.RuleProblem{
		{Block: "orders", Rule: "internal", Reason: v1.ProblemUnresolvedPresetReference},
		{Block: "catalog", Rule: "internal", Reason: v1.ProblemUnresolvedPresetReference},
	}, withoutMessage(problems), "Resolve problems")
	for _, problem := range problems {
		assert.Contains(t, problem.Message, `"internal-bypas"`, "Message of the problem at %s/internal", problem.Block)
		assert.Contains(t, problem.Message, `"plan-cascade"`, "Message of the problem at %s/internal", problem.Block)
	}
}

// The shape of a block preset is checked whether a block takes it or not. A
// preset has no block and no rule to address a problem to, so the message is
// what locates the defect: it names the preset and the rule, or the kind of
// preset where the preset has no name.
func TestResolve_rejectsTheShapeOfABlockPresetNoBlockTakes(t *testing.T) {
	withRules := func(rules ...v1.Rule) v1.BlockPreset { return v1.BlockPreset{Name: "cascade", Rules: rules} }
	cases := []struct {
		name    string
		presets []v1.BlockPreset
		locates []string
	}{
		{
			name:    "a rule of a block preset with before",
			presets: []v1.BlockPreset{withRules(v1.Rule{Name: "a", Before: "b", Rates: []v1.Rate{minuteRate(1)}})},
			locates: []string{`"a"`, `"cascade"`},
		},
		{
			name:    "a rule of a block preset with dropped",
			presets: []v1.BlockPreset{withRules(v1.Rule{Name: "a", Dropped: true})},
			locates: []string{`"a"`, `"cascade"`},
		},
		{
			name:    "a block preset declared twice",
			presets: []v1.BlockPreset{planCascade(), planCascade()},
			locates: []string{`"plan-cascade"`},
		},
		{
			name:    "a block preset without a name",
			presets: []v1.BlockPreset{{Rules: []v1.Rule{simpleRule("a")}}},
			locates: []string{"block preset"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &v1.RateLimitPolicySpec{
				Domain:  testDomain,
				Presets: &v1.Presets{Rules: []v1.RulePreset{internalBypass(), standardClient()}, Blocks: tc.presets},
				Limits:  []v1.LimitBlock{{Name: "api", Rules: []v1.Rule{simpleRule("total")}}},
			}

			resolved, problems := Resolve(spec)

			assert.Nil(t, resolved, "Resolved")
			require.Equal(t, []v1.RuleProblem{{Reason: v1.ProblemInvalidSpec}}, withoutMessage(problems),
				"Resolve problems")
			for _, part := range tc.locates {
				assert.Contains(t, problems[0].Message, part, "Message of the problem")
			}
		})
	}
}

// A block that holds no rule once its preset is resolved is the engine's
// "a block without rules", reported with the block's preset named.
func TestCompile_aBlockWithNoRulesAfterResolutionIsInvalid(t *testing.T) {
	spec := &v1.RateLimitPolicySpec{
		Domain:  testDomain,
		Presets: &v1.Presets{Blocks: []v1.BlockPreset{{Name: "one-rule", Rules: []v1.Rule{simpleRule("only")}}}},
		Limits:  []v1.LimitBlock{{Name: "api", Preset: "one-rule", Rules: []v1.Rule{{Name: "only", Dropped: true}}}},
	}

	outcome := compileOf(objectWithSpec(spec)).Policies[key()]

	require.Equal(t, []v1.RuleProblem{{Block: "api", Reason: v1.ProblemInvalidSpec}},
		withoutMessage(outcome.Problems), "Outcome.Problems")
	assert.Contains(t, outcome.Problems[0].Message, `"one-rule"`, "Message of the problem")
}

// TestCompile_aPolicyWithBlockPresetsCompilesLikeThePolicyWrittenOut is the
// example of the resource specification: the cascade as declared, with one
// rule overridden by name, and with a rule inserted and one dropped, against
// the same three blocks written out in full.
func TestCompile_aPolicyWithBlockPresetsCompilesLikeThePolicyWrittenOut(t *testing.T) {
	partner := v1.Rule{Name: "partner",
		Matches:  []v1.Predicate{{Key: "sub", Operator: v1.OperatorInGroup, Value: "partners"}},
		Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(500)}}
	partnerBefore := partner
	partnerBefore.Before = "per-user"
	withPresets := cascadeSpec(
		v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Target: prefixTarget("/api/v1/orders")},
		v1.LimitBlock{Name: "catalog", Preset: "plan-cascade", Target: prefixTarget("/api/v1/catalog"),
			Rules: []v1.Rule{{Name: "per-user", Rates: []v1.Rate{minuteRate(300)}}}},
		v1.LimitBlock{Name: "exports", Preset: "plan-cascade", Target: prefixTarget("/api/v1/exports"),
			Rules: []v1.Rule{partnerBefore, {Name: "anonymous", Dropped: true}}},
	)
	withPresets.Mappings = []v1.ClaimMapping{{Key: "plan", Claim: "plan", Normalization: v1.NormalizeLowercase}}
	withPresets.Groups = []v1.Group{{Name: "partners", Values: []string{"00000000-0000-4000-8000-00000000c001"}}}

	bypass, standard := internalBypass(), standardClient()
	internal := v1.Rule{Name: "internal", Matches: bypass.Matches, Behavior: bypass.Behavior}
	perUser := v1.Rule{Name: "per-user", Counters: standard.Counters, Rates: standard.Rates}
	perUserCatalog := perUser
	perUserCatalog.Rates = []v1.Rate{minuteRate(300)}
	enterprise, anonymous := planCascade().Rules[1], planCascade().Rules[3]
	writtenOut := &v1.RateLimitPolicySpec{
		Domain:   testDomain,
		Mappings: withPresets.Mappings,
		Groups:   withPresets.Groups,
		Limits: []v1.LimitBlock{
			{Name: "orders", Target: prefixTarget("/api/v1/orders"), Mode: v1.BlockModeFirstMatch,
				Rules: []v1.Rule{internal, enterprise, perUser, anonymous}},
			{Name: "catalog", Target: prefixTarget("/api/v1/catalog"), Mode: v1.BlockModeFirstMatch,
				Rules: []v1.Rule{internal, enterprise, perUserCatalog, anonymous}},
			{Name: "exports", Target: prefixTarget("/api/v1/exports"), Mode: v1.BlockModeFirstMatch,
				Rules: []v1.Rule{internal, enterprise, partner, perUser}},
		},
	}

	fromPresets := compileOf(objectWithSpec(withPresets))
	fromWrittenOut := compileOf(objectWithSpec(writtenOut))

	require.NoError(t, fromWrittenOut.Policies[key()].Err, "Outcome.Err of the policy written out")
	require.NoError(t, fromPresets.Policies[key()].Err, "Outcome.Err of the policy with presets")
	assert.Equal(t, fromWrittenOut.Snapshots[testDomain], fromPresets.Snapshots[testDomain],
		"Snapshots[%q], counter key prefixes included", testDomain)
	assert.Equal(t, fromWrittenOut.Policies[key()].Rules, fromPresets.Policies[key()].Rules, "Outcome.Rules")
	assert.Equal(t, fromWrittenOut.State[testDomain].GoodSpec, fromPresets.State[testDomain].GoodSpec,
		"State[%q].GoodSpec, the last-good spec", testDomain)
}

// The decision budget counts resolved blocks, so a block preset is charged
// once per block that takes it: an All body of twenty buckets stamped on
// seven blocks is over the 128 of the domain, on six it is not.
func TestCompile_theDecisionBudgetChargesABlockPresetOncePerBlock(t *testing.T) {
	windows := []v1.Rate{{Requests: 1, PeriodSeconds: 10}, {Requests: 1, PeriodSeconds: 60},
		{Requests: 1, PeriodSeconds: 3600}, {Requests: 1, PeriodSeconds: 86400}}
	body := v1.BlockPreset{Name: "wide"}
	for i := range 5 {
		body.Rules = append(body.Rules, v1.Rule{Name: fmt.Sprintf("r%d", i), Rates: windows})
	}
	stamped := func(blocks int) *v1.RateLimitPolicySpec {
		spec := &v1.RateLimitPolicySpec{Domain: testDomain, Presets: &v1.Presets{Blocks: []v1.BlockPreset{body}}}
		for i := range blocks {
			spec.Limits = append(spec.Limits, v1.LimitBlock{Name: fmt.Sprintf("b%d", i), Preset: "wide",
				Target: prefixTarget(fmt.Sprintf("/api/%d", i))})
		}
		return spec
	}

	six := compileOf(objectWithSpec(stamped(6))).Policies[key()]
	seven := compileOf(objectWithSpec(stamped(7))).Policies[key()]

	assert.NoError(t, six.Err, "Outcome.Err with the preset taken by six blocks")
	assert.ErrorContains(t, seven.Err, v1.ProblemDomainBudgetExceeded,
		"Outcome.Err with the preset taken by seven blocks")
}

// TestResolve_estimatesABlockPresetOncePerBlockLessTheRulesDropped pins the
// block half of the size formula, computed here from the literal forms: the
// spec as written with the defaults written in, plus the block preset with
// its defaults once per block that takes it, plus the rule presets its rules
// take once per block, less the preset rules the blocks drop as written.
func TestResolve_estimatesABlockPresetOncePerBlockLessTheRulesDropped(t *testing.T) {
	bodyRules := []v1.Rule{
		{Name: "a", Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(100)}},
		{Name: "b", Preset: "standard-client"},
	}
	spec := &v1.RateLimitPolicySpec{
		Domain: testDomain,
		Presets: &v1.Presets{
			Rules:  []v1.RulePreset{standardClient()},
			Blocks: []v1.BlockPreset{{Name: "body", Rules: bodyRules}},
		},
		Limits: []v1.LimitBlock{
			{Name: "x", Preset: "body"},
			{Name: "y", Preset: "body", Rules: []v1.Rule{{Name: "a", Dropped: true}}},
		},
	}
	writtenWithDefaults := *spec.DeepCopy()
	writtenWithDefaults.Limits = []v1.LimitBlock{
		{Name: "x", Preset: "body", Mode: v1.BlockModeAll},
		{Name: "y", Preset: "body", Mode: v1.BlockModeAll,
			Rules: []v1.Rule{{Name: "a", Dropped: true, Behavior: v1.RuleBehaviorEnforce}}},
	}
	bodyWithDefaults := v1.LimitBlock{Name: "body", Mode: v1.BlockModeAll, Rules: []v1.Rule{
		{Name: "a", Counters: []string{"sub"}, Behavior: v1.RuleBehaviorEnforce,
			Rates: []v1.Rate{{Requests: 100, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}},
		{Name: "b", Preset: "standard-client", Behavior: v1.RuleBehaviorEnforce},
	}}
	burst := int32(20)
	standardWithDefaults := v1.Rule{
		Name: "standard-client", Counters: []string{"sub"}, Behavior: v1.RuleBehaviorEnforce,
		Rates: []v1.Rate{
			{Requests: 100, PeriodSeconds: 60, Burst: &burst, Algorithm: v1.AlgorithmGCRA},
			{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow},
		}}

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	want := serialized(t, writtenWithDefaults) + 2*serialized(t, bodyWithDefaults) +
		2*serialized(t, standardWithDefaults) - serialized(t, bodyRules[0])
	assert.Equal(t, want, resolved.EstimatedSize, "Resolved.EstimatedSize")
}

func TestResolve_theEstimateIsAtLeastTheResolvedSizeWithBlockPresets(t *testing.T) {
	partner := v1.Rule{Name: "partner", Before: "per-user", Counters: []string{"sub"},
		Rates: []v1.Rate{minuteRate(500)}}
	specs := map[string]*v1.RateLimitPolicySpec{
		"a block preset taken as is by three blocks": cascadeSpec(
			v1.LimitBlock{Name: "a", Preset: "plan-cascade"}, v1.LimitBlock{Name: "b", Preset: "plan-cascade"},
			v1.LimitBlock{Name: "c", Preset: "plan-cascade"}),
		"a block preset with an override, an insertion, and a dropped rule": cascadeSpec(
			v1.LimitBlock{Name: "a", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "enterprise", Rates: []v1.Rate{minuteRate(2000)}}, partner,
				{Name: "anonymous", Dropped: true},
			}}),
		"a block preset every rule of which is dropped but one": cascadeSpec(
			v1.LimitBlock{Name: "a", Preset: "plan-cascade", Rules: []v1.Rule{
				{Name: "internal", Dropped: true}, {Name: "enterprise", Dropped: true},
				{Name: "anonymous", Dropped: true},
			}}),
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			resolved, problems := Resolve(spec)

			require.Empty(t, problems, "Resolve problems")
			assert.GreaterOrEqual(t, resolved.EstimatedSize, serialized(t, resolved.Spec),
				"Resolved.EstimatedSize against the serialized size of Resolved.Spec")
		})
	}
}

// The preset of a block is named at every problem of that block, beside the
// rule preset where the rule took one.
func TestCompile_theBlocksPresetIsNamedAtTheProblemsOfTheBlock(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade"})
	spec.Presets.Rules[1].Counters = []string{"ghost"}

	outcome := compileOf(objectWithSpec(spec)).Policies[key()]

	require.Equal(t, []v1.RuleProblem{
		{Block: "orders", Rule: "enterprise", Reason: v1.ProblemUnresolvedKeyReference},
		{Block: "orders", Rule: perUserName, Reason: v1.ProblemUnresolvedKeyReference},
	}, withoutMessage(outcome.Problems), "Outcome.Problems")
	enterprise, perUser := outcome.Problems[0].Message, outcome.Problems[1].Message
	assert.Contains(t, enterprise, `"plan-cascade"`, "Message of the problem at orders/enterprise")
	assert.NotContains(t, enterprise, `"standard-client"`, "Message of the problem at orders/enterprise")
	assert.Contains(t, perUser, `"plan-cascade"`, "Message of the problem at orders/per-user")
	assert.Contains(t, perUser, `"standard-client"`, "Message of the problem at orders/per-user")
}

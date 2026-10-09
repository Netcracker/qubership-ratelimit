package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/manifest"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// The resolution of presets is the operator's own step in front of the
// engine: which fields a rule takes from its preset, what the compiler is
// handed, and what the status says when a reference does not resolve.

// specWithPresets builds the domain's spec from rule presets and blocks.
func specWithPresets(presets []v1.RulePreset, blocks ...v1.LimitBlock) *v1.RateLimitPolicySpec {
	return &v1.RateLimitPolicySpec{
		Domain:  testDomain,
		Presets: &v1.Presets{Rules: presets},
		Limits:  blocks,
	}
}

// perUserName is the name of the rule that takes standardClient in these
// tests; the name is the point of use's own.
const perUserName = "per-user"

// standardClient is a partial preset: axes and windows, no predicates.
func standardClient() v1.RulePreset {
	burst := int32(20)
	return v1.RulePreset{
		Name:     "standard-client",
		Counters: []string{"sub"},
		Rates: []v1.Rate{
			{Requests: 100, PeriodSeconds: 60, Burst: &burst},
			{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow},
		},
	}
}

// resolvedRule finds a rule of the resolved spec by name; the specs of these
// tests hold the name in one block only, so the name is enough.
func resolvedRule(t *testing.T, resolved *Resolved, rule string) v1.Rule {
	t.Helper()
	for _, b := range resolved.Spec.Limits {
		for _, r := range b.Rules {
			if r.Name == rule {
				return r
			}
		}
	}
	t.Fatalf("the resolved spec holds no rule %q", rule)
	return v1.Rule{}
}

// resolveOne resolves a spec in which the one rule use takes preset, and
// returns that rule as resolved.
func resolveOne(t *testing.T, preset v1.RulePreset, use v1.Rule) v1.Rule {
	t.Helper()
	resolved, problems := Resolve(specWithPresets([]v1.RulePreset{preset},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{use}}))
	require.Empty(t, problems, "Resolve problems")
	return resolvedRule(t, resolved, use.Name)
}

// withoutMessage reduces problems to their addresses and reasons, the part of
// a problem the status defines exactly. A test matches a message only on the
// name the message has to carry.
func withoutMessage(problems []v1.RuleProblem) []v1.RuleProblem {
	out := make([]v1.RuleProblem, 0, len(problems))
	for _, problem := range problems {
		problem.Message = ""
		out = append(out, problem)
	}
	return out
}

func TestResolve_aRuleTakesEveryFieldOfItsPresetUnderItsOwnName(t *testing.T) {
	spec := specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	burst := int32(20)
	assert.Equal(t, v1.Rule{
		Name:     perUserName,
		Counters: []string{"sub"},
		Rates: []v1.Rate{
			{Requests: 100, PeriodSeconds: 60, Burst: &burst, Algorithm: v1.AlgorithmGCRA},
			{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow},
		},
		Behavior: v1.RuleBehaviorEnforce,
	}, resolvedRule(t, resolved, perUserName), "resolved rule per-user")
	assert.Nil(t, resolved.Spec.Presets, "Resolved.Spec.Presets")
	assert.Equal(t, map[RuleRef]string{{Block: "api", Rule: perUserName}: "standard-client"}, resolved.Presets,
		"Resolved.Presets")
}

// nameField is the one field of a rule preset that is the preset's own:
// every other field is one a rule takes from it.
const nameField = "Name"

// The fields of a rule preset are the fields of a rule except name and the
// authoring fields preset, before, and dropped. Both sets are read from the
// types, so a field added to Rule and left out of RulePreset fails here
// rather than being unavailable to a preset without a word.
func TestResolve_aRulePresetHasEveryFieldOfARuleExceptTheAuthoringOnes(t *testing.T) {
	own := map[string]bool{nameField: true, "Preset": true, "Before": true, "Dropped": true}
	ruleFields := map[string]bool{}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[v1.Rule]()) {
		if !own[field.Name] {
			ruleFields[field.Name] = true
		}
	}
	presetFields := map[string]bool{}
	for _, field := range reflect.VisibleFields(reflect.TypeFor[v1.RulePreset]()) {
		if field.Name != nameField {
			presetFields[field.Name] = true
		}
	}

	assert.Equal(t, ruleFields, presetFields, "fields of v1.RulePreset, against those of v1.Rule")
}

// Every field of a rule preset except its name is one the rule takes from
// the preset when it leaves the field out. The set of fields is read from the
// type, so a field added to RulePreset and left out of ruleOf, the conversion
// the merge starts from, fails here rather than being dropped on the way to
// the engine.
func TestResolve_aRuleTakesEveryFieldOfItsPresetItLeavesOut(t *testing.T) {
	preset := v1.RulePreset{Name: "p"}
	presetValue := reflect.ValueOf(&preset).Elem()
	for i := range presetValue.NumField() {
		if presetValue.Type().Field(i).Name != nameField {
			fill(t, presetValue.Field(i))
		}
	}

	resolved, problems := Resolve(specWithPresets([]v1.RulePreset{preset},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "r", Preset: "p"}}}))

	require.Empty(t, problems, "Resolve problems")
	got := reflect.ValueOf(resolvedRule(t, resolved, "r"))
	for i := range presetValue.NumField() {
		field := presetValue.Type().Field(i)
		if field.Name == nameField {
			continue
		}
		assert.Equal(t, presetValue.Field(i).Interface(), got.FieldByName(field.Name).Interface(),
			"field %s of the resolved rule r, which the rule left out", field.Name)
	}
}

// fill sets v to a value that is not the zero value of its type, down to
// every leaf, so that a field set to it is told from one left out, and so
// that no default applies to it on the way.
func fill(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int32:
		v.SetInt(1)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(t, v.Index(0))
	case reflect.Struct:
		for _, field := range v.Fields() {
			fill(t, field)
		}
	default:
		t.Fatalf("no non-zero value for a field of kind %s; extend fill", v.Kind())
	}
}

// A field written at the point of use replaces the preset's field whole, a
// field left out comes from the preset, and a list written empty is a value,
// not an omission. The subtests are the override table of the resource
// specification, with the left-out counterpart of each list beside it.
func TestResolve_aFieldWrittenAtThePointOfUseReplacesThePresetsWhole(t *testing.T) {
	replacing := v1.RulePreset{Name: "replaces-a", Rates: []v1.Rate{minuteRate(100)}, ReplacedRules: []string{"a"}}

	t.Run("counters written empty over an axis are one shared bucket", func(t *testing.T) {
		got := resolveOne(t, standardClient(), v1.Rule{Name: "r", Preset: "standard-client", Counters: []string{}})

		assert.Equal(t, []string{}, got.Counters, "Counters of the resolved rule")
	})
	t.Run("counters left out keep the preset's axis", func(t *testing.T) {
		got := resolveOne(t, standardClient(), v1.Rule{Name: "r", Preset: "standard-client"})

		assert.Equal(t, []string{"sub"}, got.Counters, "Counters of the resolved rule")
	})
	t.Run("matches written empty over a predicate match everyone", func(t *testing.T) {
		got := resolveOne(t, internalBypass(), v1.Rule{Name: "r", Preset: "internal-bypass", Matches: []v1.Predicate{}})

		assert.Equal(t, []v1.Predicate{}, got.Matches, "Matches of the resolved rule")
		assert.Equal(t, v1.RuleBehaviorBypass, got.Behavior, "Behavior of the resolved rule, left out")
	})
	t.Run("rates written empty with Bypass over a counting preset carry no window", func(t *testing.T) {
		got := resolveOne(t, standardClient(),
			v1.Rule{Name: "r", Preset: "standard-client", Rates: []v1.Rate{}, Behavior: v1.RuleBehaviorBypass})

		assert.Equal(t, []v1.Rate{}, got.Rates, "Rates of the resolved rule")
		assert.Equal(t, v1.RuleBehaviorBypass, got.Behavior, "Behavior of the resolved rule")
	})
	t.Run("rates written replace the preset's windows whole", func(t *testing.T) {
		got := resolveOne(t, standardClient(),
			v1.Rule{Name: "r", Preset: "standard-client", Rates: []v1.Rate{minuteRate(300)}})

		assert.Equal(t, []v1.Rate{{Requests: 300, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, got.Rates,
			"Rates of the resolved rule")
		assert.Equal(t, []string{"sub"}, got.Counters, "Counters of the resolved rule, left out")
	})
	t.Run("a window written without algorithm over a FixedWindow preset is GCRA", func(t *testing.T) {
		daily := v1.RulePreset{Name: "daily",
			Rates: []v1.Rate{{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow}}}

		got := resolveOne(t, daily, v1.Rule{Name: "r", Preset: "daily", Rates: []v1.Rate{minuteRate(300)}})

		assert.Equal(t, []v1.Rate{{Requests: 300, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, got.Rates,
			"Rates of the resolved rule")
	})
	t.Run("Shadow over a Bypass preset is a Shadow rule with its own windows", func(t *testing.T) {
		got := resolveOne(t, internalBypass(), v1.Rule{Name: "r", Preset: "internal-bypass",
			Behavior: v1.RuleBehaviorShadow, Rates: []v1.Rate{minuteRate(5)}})

		assert.Equal(t, v1.RuleBehaviorShadow, got.Behavior, "Behavior of the resolved rule")
		assert.Equal(t, []v1.Rate{{Requests: 5, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, got.Rates,
			"Rates of the resolved rule")
		assert.Equal(t, internalBypass().Matches, got.Matches, "Matches of the resolved rule, left out")
	})
	t.Run("replacedRules written replace the preset's list", func(t *testing.T) {
		got := resolveOne(t, replacing, v1.Rule{Name: "r", Preset: "replaces-a", ReplacedRules: []string{"b"}})

		assert.Equal(t, []string{"b"}, got.ReplacedRules, "ReplacedRules of the resolved rule")
	})
	t.Run("replacedRules written empty over the preset's list leave none", func(t *testing.T) {
		got := resolveOne(t, replacing, v1.Rule{Name: "r", Preset: "replaces-a", ReplacedRules: []string{}})

		assert.Equal(t, []string{}, got.ReplacedRules, "ReplacedRules of the resolved rule")
	})
	t.Run("replacedRules left out keep the preset's list", func(t *testing.T) {
		got := resolveOne(t, replacing, v1.Rule{Name: "r", Preset: "replaces-a"})

		assert.Equal(t, []string{"a"}, got.ReplacedRules, "ReplacedRules of the resolved rule")
	})
}

// The defaults go in once, after the last layer: a rule that takes a Shadow
// preset without writing behavior is Shadow, and a mode absent at every layer
// is All, in a block that takes a block preset as in one that takes none. That
// the API server writes none of the three into an object is the envtest spec
// "stores mode, behavior, and algorithm only where the author wrote them".
func TestResolve_writesTheDefaultsAfterTheLastLayer(t *testing.T) {
	shadowTrial := v1.RulePreset{Name: "trial", Behavior: v1.RuleBehaviorShadow, Rates: []v1.Rate{minuteRate(5)}}
	spec := specWithPresets([]v1.RulePreset{shadowTrial, standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{
			{Name: "from-shadow", Preset: "trial"},
			{Name: "from-counting", Preset: "standard-client"},
			{Name: "plain", Rates: []v1.Rate{minuteRate(10)}},
		}},
		v1.LimitBlock{Name: "from-body", Preset: "modeless"})
	spec.Presets.Blocks = []v1.BlockPreset{{Name: "modeless", Rules: []v1.Rule{simpleRule("total")}}}

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	require.Len(t, resolved.Spec.Limits, 2, "Resolved.Spec.Limits")
	assert.Equal(t, v1.BlockModeAll, resolved.Spec.Limits[0].Mode, "Mode of block api, written nowhere")
	assert.Equal(t, v1.BlockModeAll, resolved.Spec.Limits[1].Mode,
		"Mode of block from-body, written neither in the block nor in its preset")
	assert.Equal(t, v1.RuleBehaviorShadow, resolvedRule(t, resolved, "from-shadow").Behavior,
		"Behavior of rule from-shadow, whose preset is Shadow")
	assert.Equal(t, v1.RuleBehaviorEnforce, resolvedRule(t, resolved, "from-counting").Behavior,
		"Behavior of rule from-counting, written neither in the rule nor in its preset")
	assert.Equal(t, v1.RuleBehaviorEnforce, resolvedRule(t, resolved, "plain").Behavior,
		"Behavior of rule plain, written nowhere")
	assert.Equal(t, v1.AlgorithmGCRA, resolvedRule(t, resolved, "plain").Rates[0].Algorithm,
		"Algorithm of rule plain, written nowhere")
}

func TestResolve_aSpecWithoutPresetsResolvesToItselfWithTheDefaults(t *testing.T) {
	spec := &v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "api", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{minuteRate(100)}}}},
	}}

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "api", Mode: v1.BlockModeAll, Rules: []v1.Rule{{
			Name:     "total",
			Rates:    []v1.Rate{{Requests: 100, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}},
			Behavior: v1.RuleBehaviorEnforce,
		}}},
	}}, resolved.Spec, "Resolved.Spec")
	assert.Empty(t, resolved.Presets, "Resolved.Presets")
}

// Resolve works on a copy: neither the blocks as written nor the presets they
// take change, whether a rule or a block takes the preset.
func TestResolve_leavesTheSpecItWasGivenUntouched(t *testing.T) {
	spec := cascadeSpec(
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}},
		v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
			{Name: "enterprise", Rates: []v1.Rate{minuteRate(2000)}},
			{Name: "partner", Before: perUserName, Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(500)}},
			{Name: "anonymous", Dropped: true},
		}})
	written := spec.DeepCopy()

	_, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, written, spec, "the spec Resolve was given, after the call")
}

func TestResolve_aRuleNamingAPresetTheSpecDoesNotDeclareIsAnUnresolvedReference(t *testing.T) {
	spec := specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-clinet"}}})

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved, "Resolved of a spec with a problem")
	require.Equal(t, []v1.RuleProblem{{Block: "api", Rule: perUserName, Reason: v1.ProblemUnresolvedPresetReference}},
		withoutMessage(problems), "Resolve problems")
	assert.Contains(t, problems[0].Message, `"standard-clinet"`, "Message of the problem")
}

// The shape of a rule preset is checked whether a rule takes it or not. A
// preset has no block and no rule to address a problem to, so the message is
// what locates the defect: it names the preset, or the kind of preset where
// the preset has no name.
func TestResolve_rejectsTheShapeOfARulePresetNoRuleTakes(t *testing.T) {
	cases := []struct {
		name    string
		presets []v1.RulePreset
		locates string
	}{
		{
			name:    "a preset declared twice",
			presets: []v1.RulePreset{standardClient(), standardClient()},
			locates: `"standard-client"`,
		},
		{
			name:    "a preset without a name",
			presets: []v1.RulePreset{{Rates: []v1.Rate{minuteRate(1)}}},
			locates: "rule preset",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := specWithPresets(tc.presets,
				v1.LimitBlock{Name: "api", Rules: []v1.Rule{simpleRule("total")}})

			resolved, problems := Resolve(spec)

			assert.Nil(t, resolved, "Resolved")
			require.Equal(t, []v1.RuleProblem{{Reason: v1.ProblemInvalidSpec}}, withoutMessage(problems),
				"Resolve problems")
			assert.Contains(t, problems[0].Message, tc.locates, "Message of the problem")
		})
	}
}

// widePredicates is the number of predicates of a wide preset: each carries a
// value of the longest length the schema admits, so the body serializes to
// about 600 KB, and two copies fit under MaxResolvedSize where three do not.
const widePredicates = 2000

// bigPreset is a preset of widePredicates predicates.
func bigPreset(name string) v1.RulePreset {
	preset := v1.RulePreset{Name: name, Rates: []v1.Rate{minuteRate(100)}}
	for i := range widePredicates {
		preset.Matches = append(preset.Matches, v1.Predicate{
			Key: "sub", Operator: v1.OperatorIn, Values: []string{fmt.Sprintf("%0256d", i)},
		})
	}
	return preset
}

// TestResolve_estimatesTheSpecAsWrittenPlusEachPresetOncePerUse pins the
// formula: the serialized size of the spec as written with the defaults
// written in, plus each preset, with its defaults written in, once per rule
// that takes it. The expected number is computed here from the literal forms
// of both, which is what a reader of the limits page would compute.
func TestResolve_estimatesTheSpecAsWrittenPlusEachPresetOncePerUse(t *testing.T) {
	preset := v1.RulePreset{Name: "p", Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(100)}}
	spec := specWithPresets([]v1.RulePreset{preset}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{
		{Name: "a", Preset: "p"},
		{Name: "b", Preset: "p"},
		{Name: "c", Rates: []v1.Rate{minuteRate(10)}},
	}})
	writtenWithDefaults := v1.RateLimitPolicySpec{
		Domain:  testDomain,
		Presets: &v1.Presets{Rules: []v1.RulePreset{preset}},
		Limits: []v1.LimitBlock{{Name: "api", Mode: v1.BlockModeAll, Rules: []v1.Rule{
			{Name: "a", Preset: "p", Behavior: v1.RuleBehaviorEnforce},
			{Name: "b", Preset: "p", Behavior: v1.RuleBehaviorEnforce},
			{Name: "c", Behavior: v1.RuleBehaviorEnforce,
				Rates: []v1.Rate{{Requests: 10, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}},
		}}},
	}
	presetWithDefaults := v1.Rule{Name: "p", Counters: []string{"sub"}, Behavior: v1.RuleBehaviorEnforce,
		Rates: []v1.Rate{{Requests: 100, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}}

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, serialized(t, writtenWithDefaults)+2*serialized(t, presetWithDefaults), resolved.EstimatedSize,
		"Resolved.EstimatedSize")
}

// serialized is the length of v as JSON, the unit of the size bound.
func serialized(t *testing.T, v any) int {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err, "json.Marshal(%T)", v)
	return len(raw)
}

// TestResolve_theEstimateIsAtLeastTheResolvedSize pins the claim the bound
// rests on, over the shapes that could break it: a spec with no preset,
// whose resolved form grows by the defaults alone; a preset taken as is; a
// preset every field of which the rule replaces; and a Bypass preset, which
// is shorter than a rule.
func TestResolve_theEstimateIsAtLeastTheResolvedSize(t *testing.T) {
	plain := func(n int) []v1.Rule {
		rules := make([]v1.Rule, 0, n)
		for i := range n {
			rules = append(rules, v1.Rule{Name: fmt.Sprintf("r%d", i), Rates: []v1.Rate{minuteRate(10)}})
		}
		return rules
	}
	specs := map[string]*v1.RateLimitPolicySpec{
		"no preset, every default left out": {Domain: testDomain, Limits: []v1.LimitBlock{
			{Name: "a", Rules: plain(40)}, {Name: "b", Rules: plain(40)},
		}},
		"a preset taken as is by many rules": specWithPresets([]v1.RulePreset{standardClient()},
			v1.LimitBlock{Name: "api", Rules: append(plain(40), v1.Rule{Name: "x", Preset: "standard-client"},
				v1.Rule{Name: "y", Preset: "standard-client"})}),
		"a preset every field of which the rule replaces": specWithPresets([]v1.RulePreset{standardClient()},
			v1.LimitBlock{Name: "api", Rules: []v1.Rule{{
				Name: "x", Preset: "standard-client", Counters: []string{"path"}, Behavior: v1.RuleBehaviorShadow,
				Rates: []v1.Rate{minuteRate(1)}, Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorExists}},
			}}}),
		"a Bypass preset": specWithPresets([]v1.RulePreset{internalBypass()},
			v1.LimitBlock{Name: "api", Rules: append(plain(40), v1.Rule{Name: "internal", Preset: "internal-bypass"})}),
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

func TestResolve_refusesAPolicyEstimatedAboveTheSizeBound(t *testing.T) {
	// One copy of the preset is about 600 KB and the spec as written holds
	// that copy; two rules taking it bring the estimate to three copies,
	// about 1.8 MB, over the 1.5 MiB bound.
	spec := specWithPresets([]v1.RulePreset{bigPreset("wide")}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{
		{Name: "a", Preset: "wide"}, {Name: "b", Preset: "wide"},
	}})

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved, "Resolved")
	require.Equal(t, []v1.RuleProblem{{Reason: v1.ProblemResolvedPolicyTooLarge}}, withoutMessage(problems),
		"Resolve problems")
	assert.Contains(t, problems[0].Message, "1572864", "Message of the problem, which names the bound in bytes")
}

func TestResolve_acceptsAPolicyEstimatedBelowTheSizeBound(t *testing.T) {
	// The same preset taken by one rule: two copies, about 1.2 MB.
	spec := specWithPresets([]v1.RulePreset{bigPreset("wide")},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "a", Preset: "wide"}}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems, "Resolve problems")
	assert.Len(t, resolvedRule(t, resolved, "a").Matches, widePredicates, "Matches of the resolved rule a")
}

// paddedSpec is a policy whose estimate grows by one byte per byte of pad:
// the pad is the value of a predicate in a rule written at the point of use,
// beside a rule that takes a preset.
func paddedSpec(pad int) *v1.RateLimitPolicySpec {
	return specWithPresets([]v1.RulePreset{standardClient()}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{
		{Name: "a", Preset: "standard-client"},
		{Name: "pad", Rates: []v1.Rate{minuteRate(1)}, Matches: []v1.Predicate{
			{Key: "sub", Operator: v1.OperatorEquals, Value: strings.Repeat("x", pad)}}},
	}})
}

// padFor is the pad that brings the estimate of paddedSpec to estimate bytes,
// measured from the estimate of a one-byte pad.
func padFor(t *testing.T, estimate int) int {
	t.Helper()
	base, problems := Resolve(paddedSpec(1))
	require.Empty(t, problems, "Resolve(paddedSpec(1)) problems")
	return estimate - base.EstimatedSize + 1
}

// The bound is inclusive: an estimate of exactly MaxResolvedSize bytes is
// within it. The estimate equal to the bound also shows that every byte of
// the pad is one byte of the estimate, which the test one byte over relies on.
func TestResolve_acceptsAnEstimateOfExactlyTheSizeBound(t *testing.T) {
	resolved, problems := Resolve(paddedSpec(padFor(t, MaxResolvedSize)))

	require.Empty(t, problems, "Resolve problems")
	assert.Equal(t, MaxResolvedSize, resolved.EstimatedSize, "Resolved.EstimatedSize")
}

// The message carries the estimate, which shows that the refused policy is
// the one exactly one byte over the bound.
func TestResolve_refusesAnEstimateOneByteOverTheSizeBound(t *testing.T) {
	resolved, problems := Resolve(paddedSpec(padFor(t, MaxResolvedSize+1)))

	assert.Nil(t, resolved, "Resolved")
	require.Equal(t, []v1.RuleProblem{{Reason: v1.ProblemResolvedPolicyTooLarge}}, withoutMessage(problems),
		"Resolve problems")
	assert.Contains(t, problems[0].Message, strconv.Itoa(MaxResolvedSize+1), "Message of the problem")
}

// TestResolve_countsAFieldTheRuleReplacesInBothLayers pins the price of an
// estimate that writes no preset into a rule: a rule that replaces the
// preset's largest field is charged for the preset's copy and for its own,
// so a policy whose resolved form fits under the bound can still be refused.
func TestResolve_countsAFieldTheRuleReplacesInBothLayers(t *testing.T) {
	own := bigPreset("own").Matches
	spec := specWithPresets([]v1.RulePreset{bigPreset("wide")},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "a", Preset: "wide", Matches: own}}})
	writtenOut := &v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "api", Rules: []v1.Rule{{Name: "a", Matches: own, Rates: []v1.Rate{minuteRate(100)}}}},
	}}
	require.Less(t, serialized(t, writtenOut), MaxResolvedSize,
		"the serialized size of the policy written out, which has to fit under the bound")

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved, "Resolved")
	assert.Equal(t, []v1.RuleProblem{{Reason: v1.ProblemResolvedPolicyTooLarge}}, withoutMessage(problems),
		"Resolve problems")
}

// TestCompile_aPolicyWithPresetsCompilesLikeThePolicyWrittenOut is the
// contract the counter keys rest on: a preset changes how a policy is
// written and nothing about what the engine builds from it, so renaming a
// preset moves no bucket.
func TestCompile_aPolicyWithPresetsCompilesLikeThePolicyWrittenOut(t *testing.T) {
	withPresets := specWithPresets([]v1.RulePreset{internalBypass(), standardClient()},
		v1.LimitBlock{Name: "orders", Target: prefixTarget("/orders"), Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{
			{Name: "internal", Preset: "internal-bypass"},
			{Name: perUserName, Preset: "standard-client"},
		}},
		v1.LimitBlock{Name: "catalog", Target: prefixTarget("/catalog"), Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{
			{Name: "internal", Preset: "internal-bypass"},
			{Name: perUserName, Preset: "standard-client", Rates: []v1.Rate{minuteRate(300)}},
		}})
	bypass, standard := internalBypass(), standardClient()
	internal := v1.Rule{Name: "internal", Matches: bypass.Matches, Behavior: bypass.Behavior}
	perUser := v1.Rule{Name: perUserName, Counters: standard.Counters, Rates: standard.Rates}
	perUserCatalog := perUser
	perUserCatalog.Rates = []v1.Rate{minuteRate(300)}
	writtenOut := &v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "orders", Target: prefixTarget("/orders"), Mode: v1.BlockModeFirstMatch,
			Rules: []v1.Rule{internal, perUser}},
		{Name: "catalog", Target: prefixTarget("/catalog"), Mode: v1.BlockModeFirstMatch,
			Rules: []v1.Rule{internal, perUserCatalog}},
	}}

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

func objectWithSpec(spec *v1.RateLimitPolicySpec) v1.RateLimitPolicy {
	object := policyObject()
	object.Spec = *spec
	return object
}

// TestCompile_theBundleHoldsTheResolvedSpec pins what a restart re-enforces:
// last-good is the spec with its presets written out, not the spec as
// written.
func TestCompile_theBundleHoldsTheResolvedSpec(t *testing.T) {
	object := objectWithSpec(specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}}))

	bundle := compileOf(object).State[testDomain]

	require.Equal(t, int64(1), bundle.GoodGeneration, "Bundle.GoodGeneration")
	assert.Nil(t, bundle.GoodSpec.Presets, "Bundle.GoodSpec.Presets")
	assert.Empty(t, bundle.GoodSpec.Limits[0].Rules[0].Preset, "Preset of rule per-user in Bundle.GoodSpec")
	assert.Equal(t, []string{"sub"}, bundle.GoodSpec.Limits[0].Rules[0].Counters,
		"Counters of rule per-user in Bundle.GoodSpec")
}

// TestCompile_thePayloadOfTheBundleCarriesNoAuthoringField pins what a
// service of the previous release depends on: its strict decode refuses a
// field it does not define, so presets, preset, before, and dropped stay out
// of the payload the ConfigMap carries. Rule fields such as counters stay in
// it.
func TestCompile_thePayloadOfTheBundleCarriesNoAuthoringField(t *testing.T) {
	spec := cascadeSpec(v1.LimitBlock{Name: "orders", Preset: "plan-cascade", Rules: []v1.Rule{
		{Name: "partner", Before: perUserName, Counters: []string{"sub"}, Rates: []v1.Rate{minuteRate(500)}},
		{Name: "anonymous", Dropped: true},
	}})
	spec.Mappings = []v1.ClaimMapping{{Key: "plan", Claim: "plan"}}
	result := compileOf(objectWithSpec(spec))
	require.NoError(t, result.Policies[key()].Err, "Outcome.Err")
	bundle := result.State[testDomain]

	compressed, _, err := manifest.EncodePayload(bundle.GoodSpec)

	require.NoError(t, err, "EncodePayload(Bundle.GoodSpec)")
	var document map[string]any
	_, err = manifest.DecodePayload(compressed, &document)
	require.NoError(t, err, "DecodePayload")
	keys := jsonKeys(document)
	assert.Contains(t, keys, "counters", "keys of the payload")
	assert.NotContains(t, keys, "presets", "keys of the payload")
	assert.NotContains(t, keys, "preset", "keys of the payload")
	assert.NotContains(t, keys, "before", "keys of the payload")
	assert.NotContains(t, keys, "dropped", "keys of the payload")
}

// jsonKeys lists the object keys of a decoded JSON document, at any depth,
// sorted and each once.
func jsonKeys(v any) []string {
	keys := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			for k, child := range node {
				keys[k] = true
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(v)
	return slices.Sorted(maps.Keys(keys))
}

func TestCompile_anUnresolvedPresetKeepsTheLastGoodGenerationServing(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "api", Rules: []v1.Rule{simpleRule("total")}})
	broken := objectWithSpec(specWithPresets(nil,
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}}))
	broken.Generation = 2

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{broken},
		State:     map[string]Bundle{testDomain: {UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec}},
	})

	outcome := result.Policies[key()]
	assert.ErrorContains(t, outcome.Err, v1.ProblemUnresolvedPresetReference, "Outcome.Err")
	assert.Equal(t, []v1.RuleProblem{{Block: "api", Rule: perUserName, Reason: v1.ProblemUnresolvedPresetReference}},
		withoutMessage(outcome.Problems), "Outcome.Problems")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Equal(t, 1, outcome.Rules, "Outcome.Rules")
	assert.Len(t, blocksOf(t, result, testDomain), 1, "Snapshots[%q].Blocks", testDomain)
	assert.Equal(t, Bundle{UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec}, result.State[testDomain],
		"Result.State[%q]", testDomain)
}

// The content of a preset is checked through the rules that take it: a preset
// nothing takes can hold a key the domain lacks and no problem reports it,
// while a preset with the same defect that a rule takes is reported at that
// rule.
func TestCompile_thePresetsContentIsCheckedThroughTheRulesThatTakeIt(t *testing.T) {
	ghost := []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}}
	object := objectWithSpec(specWithPresets([]v1.RulePreset{
		{Name: "by-ghost", Matches: ghost, Rates: []v1.Rate{minuteRate(10)}},
		{Name: "unused", Matches: ghost, Rates: []v1.Rate{minuteRate(10)}},
	}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "per-ghost", Preset: "by-ghost"}}}))

	outcome := compileOf(object).Policies[key()]

	assert.Equal(t, []v1.RuleProblem{{Block: "api", Rule: "per-ghost", Reason: v1.ProblemUnresolvedKeyReference}},
		withoutMessage(outcome.Problems), "Outcome.Problems")
}

// The preset is named at the rule that took it and nowhere else: a plain
// rule of the same block with the same defect, and a rule of the same name
// in another block that takes no preset, carry no preset name.
func TestCompile_thePresetIsNamedAtTheRuleThatTookItAlone(t *testing.T) {
	ghost := []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}}
	byGhost := v1.RulePreset{Name: "by-ghost", Matches: ghost, Rates: []v1.Rate{minuteRate(10)}}
	object := objectWithSpec(specWithPresets([]v1.RulePreset{byGhost},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{
			{Name: "per-ghost", Preset: "by-ghost"},
			{Name: "plain", Matches: ghost, Rates: []v1.Rate{minuteRate(10)}},
		}},
		v1.LimitBlock{Name: "other", Rules: []v1.Rule{
			{Name: "per-ghost", Matches: ghost, Rates: []v1.Rate{minuteRate(10)}},
		}}))

	outcome := compileOf(object).Policies[key()]

	require.Equal(t, []v1.RuleProblem{
		{Block: "api", Rule: "per-ghost", Reason: v1.ProblemUnresolvedKeyReference},
		{Block: "api", Rule: "plain", Reason: v1.ProblemUnresolvedKeyReference},
		{Block: "other", Rule: "per-ghost", Reason: v1.ProblemUnresolvedKeyReference},
	}, withoutMessage(outcome.Problems), "Outcome.Problems")
	assert.Contains(t, outcome.Problems[0].Message, `"by-ghost"`, "Message of the problem at api/per-ghost")
	assert.NotContains(t, outcome.Problems[1].Message, `"by-ghost"`, "Message of the problem at api/plain")
	assert.NotContains(t, outcome.Problems[2].Message, `"by-ghost"`, "Message of the problem at other/per-ghost")
}

// replacedRules that a rule takes from its preset resolve in the block that
// holds the rule: the preset is valid where the block holds the rule it
// names, and UnresolvedReplacedRules where it does not.
func TestCompile_theReplacedRulesOfAPresetResolveInTheBlockThatHoldsTheRule(t *testing.T) {
	scraper := internalBypass()
	scraper.ReplacedRules = []string{perUserName}
	object := objectWithSpec(specWithPresets([]v1.RulePreset{scraper},
		v1.LimitBlock{Name: "holds", Target: prefixTarget("/holds"), Rules: []v1.Rule{
			{Name: "scraper", Preset: "internal-bypass"}, simpleRule(perUserName),
		}},
		v1.LimitBlock{Name: "lacks", Target: prefixTarget("/lacks"), Rules: []v1.Rule{
			{Name: "scraper", Preset: "internal-bypass"}, simpleRule("per-caller"),
		}}))

	outcome := compileOf(object).Policies[key()]

	assert.Equal(t, []v1.RuleProblem{{Block: "lacks", Rule: "scraper", Reason: v1.ProblemUnresolvedReplacedRules}},
		withoutMessage(outcome.Problems), "Outcome.Problems")
}

// A capture that a rule takes from its preset resolves in the block that
// holds the rule: the preset counts by the capture where the block's route
// declares it, and is UnresolvedKeyReference where it does not.
func TestCompile_aCaptureOfAPresetResolvesInTheBlockThatHoldsTheRule(t *testing.T) {
	perID := v1.RulePreset{Name: "per-id", Counters: []string{"id"}, Rates: []v1.Rate{minuteRate(10)}}
	users := &v1.Target{Routes: []v1.Route{{Path: v1.PathMatch{Type: v1.PathMatchTemplate, Value: "/users/{id}"}}}}
	object := objectWithSpec(specWithPresets([]v1.RulePreset{perID},
		v1.LimitBlock{Name: "users", Target: users, Rules: []v1.Rule{{Name: "by-id", Preset: "per-id"}}},
		v1.LimitBlock{Name: "orders", Target: prefixTarget("/orders"),
			Rules: []v1.Rule{{Name: "by-id", Preset: "per-id"}}}))

	outcome := compileOf(object).Policies[key()]

	assert.Equal(t, []v1.RuleProblem{{Block: "orders", Rule: "by-id", Reason: v1.ProblemUnresolvedKeyReference}},
		withoutMessage(outcome.Problems), "Outcome.Problems")
}

// The engine reads the resolved spec the way it reads any other: an empty
// counters list, whether written or inherited, is one shared bucket. Pinned
// here because the resolver hands the engine an empty non-nil list where a
// written-out policy would have carried none.
func TestCompile_anEmptyCountersListFromAPresetIsOneSharedBucket(t *testing.T) {
	object := objectWithSpec(specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{
			{Name: "shared", Preset: "standard-client", Counters: []string{}},
		}}))

	result := compileOf(object)

	require.NoError(t, result.Policies[key()].Err, "Outcome.Err")
	blocks := blocksOf(t, result, testDomain)
	require.Len(t, blocks, 1, "Snapshots[%q].Blocks", testDomain)
	require.Len(t, blocks[0].Rules, 1, "Rules of block api in the snapshot")
	assert.Empty(t, blocks[0].Rules[0].Counters, "Counters of rule shared in the snapshot")
	assert.Regexp(t, ":api/shared:gcra:60:$", blocks[0].Rules[0].Rates[0].Prefix,
		"Rates[0].Prefix of rule shared in the snapshot, which carries the names of the point of use")
}

// A behavior the rule writes wins over the preset's. A default the API server
// wrote into an object stored before the schema change is such a value: the
// compiler cannot tell it from one the author wrote, so the documents say to
// remove it before the rule takes a preset.
func TestResolve_aRuleThatWritesEnforceOverAShadowPresetStaysEnforce(t *testing.T) {
	trial := v1.RulePreset{Name: "trial", Behavior: v1.RuleBehaviorShadow, Rates: []v1.Rate{minuteRate(5)}}

	got := resolveOne(t, trial, v1.Rule{Name: "stored-default", Preset: "trial", Behavior: v1.RuleBehaviorEnforce})

	assert.Equal(t, v1.RuleBehaviorEnforce, got.Behavior, "Behavior of the resolved rule")
}

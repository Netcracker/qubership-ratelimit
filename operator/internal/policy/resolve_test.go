package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/manifest"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/internal/convert"
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
// tests hold one block, so the name is enough.
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

func TestResolve_aRuleTakesEveryFieldOfItsPresetAndKeepsItsName(t *testing.T) {
	spec := specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems)
	burst := int32(20)
	assert.Equal(t, v1.Rule{
		Name:     perUserName,
		Counters: []string{"sub"},
		Rates: []v1.Rate{
			{Requests: 100, PeriodSeconds: 60, Burst: &burst, Algorithm: v1.AlgorithmGCRA},
			{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow},
		},
		Behavior: v1.RuleBehaviorEnforce,
	}, resolvedRule(t, resolved, perUserName))
	assert.Nil(t, resolved.Spec.Presets, "the resolved spec carries no presets section")
	assert.Equal(t, map[RuleRef]string{{Block: "api", Rule: perUserName}: "standard-client"}, resolved.Presets)
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

	assert.Equal(t, ruleFields, presetFields)
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

	require.Empty(t, problems)
	got := reflect.ValueOf(resolvedRule(t, resolved, "r"))
	for i := range presetValue.NumField() {
		field := presetValue.Type().Field(i)
		if field.Name == nameField {
			continue
		}
		assert.Equal(t, presetValue.Field(i).Interface(), got.FieldByName(field.Name).Interface(),
			"field %s of the preset did not reach the rule that took it", field.Name)
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
// not an omission. The rows are the override table of the resource
// specification, with the left-out counterpart of each list beside it.
func TestResolve_aFieldWrittenAtThePointOfUseReplacesThePresetsWhole(t *testing.T) {
	counting := standardClient()
	bypass := v1.RulePreset{
		Name:     "internal-bypass",
		Matches:  []v1.Predicate{{Key: "sub", Operator: v1.OperatorEquals, Value: "prometheus"}},
		Behavior: v1.RuleBehaviorBypass,
	}
	replacing := v1.RulePreset{Name: "standard-client", Rates: []v1.Rate{minuteRate(100)}, ReplacedRules: []string{"a"}}
	cases := []struct {
		name   string
		preset v1.RulePreset
		use    v1.Rule
		want   func(t *testing.T, got v1.Rule)
	}{
		{
			name:   "counters written empty over an axis is one shared bucket",
			preset: counting,
			use:    v1.Rule{Name: "r", Preset: "standard-client", Counters: []string{}},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []string{}, got.Counters)
			},
		},
		{
			name:   "counters left out keep the preset's axis",
			preset: counting,
			use:    v1.Rule{Name: "r", Preset: "standard-client"},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []string{"sub"}, got.Counters)
			},
		},
		{
			name:   "matches written empty over a predicate matches everyone",
			preset: bypass,
			use:    v1.Rule{Name: "r", Preset: "internal-bypass", Matches: []v1.Predicate{}},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []v1.Predicate{}, got.Matches)
				assert.Equal(t, v1.RuleBehaviorBypass, got.Behavior, "behavior left out comes from the preset")
			},
		},
		{
			name:   "rates written empty with Bypass over a counting preset carries no window",
			preset: counting,
			use:    v1.Rule{Name: "r", Preset: "standard-client", Rates: []v1.Rate{}, Behavior: v1.RuleBehaviorBypass},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []v1.Rate{}, got.Rates)
				assert.Equal(t, v1.RuleBehaviorBypass, got.Behavior)
			},
		},
		{
			name:   "rates written replace the preset's windows whole",
			preset: counting,
			use:    v1.Rule{Name: "r", Preset: "standard-client", Rates: []v1.Rate{minuteRate(300)}},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []v1.Rate{{Requests: 300, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, got.Rates)
				assert.Equal(t, []string{"sub"}, got.Counters, "counters left out stay the preset's")
			},
		},
		{
			name:   "a window written without algorithm over a FixedWindow preset is GCRA",
			preset: v1.RulePreset{Name: "standard-client", Rates: []v1.Rate{{Requests: 20000, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow}}},
			use:    v1.Rule{Name: "r", Preset: "standard-client", Rates: []v1.Rate{minuteRate(300)}},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []v1.Rate{{Requests: 300, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, got.Rates,
					"rates are replaced whole, so the written window carries no algorithm of the preset's")
			},
		},
		{
			name:   "Shadow over a Bypass preset is a Shadow rule with its own windows",
			preset: bypass,
			use: v1.Rule{Name: "r", Preset: "internal-bypass", Behavior: v1.RuleBehaviorShadow,
				Rates: []v1.Rate{minuteRate(5)}},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, v1.RuleBehaviorShadow, got.Behavior)
				assert.Equal(t, []v1.Rate{{Requests: 5, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}}, got.Rates)
				assert.Equal(t, bypass.Matches, got.Matches, "matches left out stay the preset's")
			},
		},
		{
			name:   "replacedRules written replace the preset's list",
			preset: replacing,
			use:    v1.Rule{Name: "r", Preset: "standard-client", ReplacedRules: []string{"b"}},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []string{"b"}, got.ReplacedRules)
			},
		},
		{
			name:   "replacedRules left out keep the preset's list",
			preset: replacing,
			use:    v1.Rule{Name: "r", Preset: "standard-client"},
			want: func(t *testing.T, got v1.Rule) {
				assert.Equal(t, []string{"a"}, got.ReplacedRules)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := specWithPresets([]v1.RulePreset{tc.preset}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{tc.use}})

			resolved, problems := Resolve(spec)

			require.Empty(t, problems)
			got := resolvedRule(t, resolved, "r")
			assert.Equal(t, "r", got.Name, "the name is always the point of use's")
			assert.Empty(t, got.Preset, "the resolved rule carries no preset")
			tc.want(t, got)
		})
	}
}

// The defaults go in once, after the preset and the point of use: a rule
// that takes a Shadow preset without writing behavior is Shadow, and a value
// absent at every layer is the default. The other half of the design, that
// the API server writes none of the three into an object, is the envtest
// spec "stores mode, behavior, and algorithm only where the author wrote
// them".
func TestResolve_writesTheDefaultsAfterTheLastLayer(t *testing.T) {
	shadowTrial := v1.RulePreset{Name: "trial", Behavior: v1.RuleBehaviorShadow, Rates: []v1.Rate{minuteRate(5)}}
	spec := specWithPresets([]v1.RulePreset{shadowTrial, standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{
			{Name: "from-shadow", Preset: "trial"},
			{Name: "from-counting", Preset: "standard-client"},
			{Name: "plain", Rates: []v1.Rate{minuteRate(10)}},
		}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems)
	assert.Equal(t, v1.BlockModeAll, resolved.Spec.Limits[0].Mode, "an absent mode is All")
	assert.Equal(t, v1.RuleBehaviorShadow, resolvedRule(t, resolved, "from-shadow").Behavior,
		"a rule that takes a Shadow preset without writing behavior is Shadow")
	assert.Equal(t, v1.RuleBehaviorEnforce, resolvedRule(t, resolved, "from-counting").Behavior,
		"behavior absent at every layer is Enforce")
	assert.Equal(t, v1.RuleBehaviorEnforce, resolvedRule(t, resolved, "plain").Behavior)
	assert.Equal(t, v1.AlgorithmGCRA, resolvedRule(t, resolved, "plain").Rates[0].Algorithm,
		"an absent algorithm is GCRA")
}

func TestResolve_aSpecWithoutPresetsResolvesToItselfWithTheDefaults(t *testing.T) {
	spec := &v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "api", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{minuteRate(100)}}}},
	}}

	resolved, problems := Resolve(spec)

	require.Empty(t, problems)
	assert.Equal(t, v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "api", Mode: v1.BlockModeAll, Rules: []v1.Rule{{
			Name:     "total",
			Rates:    []v1.Rate{{Requests: 100, PeriodSeconds: 60, Algorithm: v1.AlgorithmGCRA}},
			Behavior: v1.RuleBehaviorEnforce,
		}}},
	}}, resolved.Spec)
	assert.Empty(t, resolved.Presets)
}

func TestResolve_leavesTheSpecItWasGivenUntouched(t *testing.T) {
	spec := specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}})
	written := spec.DeepCopy()

	_, problems := Resolve(spec)

	require.Empty(t, problems)
	assert.Equal(t, written, spec, "Resolve(spec) wrote into its argument")
}

func TestResolve_aRuleNamingAPresetTheSpecDoesNotDeclareIsAnUnresolvedReference(t *testing.T) {
	spec := specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-clinet"}}})

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved, "a spec with a problem resolves to nothing")
	require.Len(t, problems, 1)
	assert.Equal(t, v1.RuleProblem{
		Block:   "api",
		Rule:    perUserName,
		Reason:  v1.ProblemUnresolvedPresetReference,
		Message: `preset "standard-clinet" is not declared under spec.presets.rules`,
	}, problems[0])
}

// The shape of a preset is checked whether a rule takes it or not; a shape
// a preset body may not have is reported with the preset named in the
// message, since a preset has no block and no rule to be addressed to.
func TestResolve_rejectsTheShapeOfAPresetNoRuleTakes(t *testing.T) {
	cases := []struct {
		name    string
		presets []v1.RulePreset
		message string
	}{
		{
			name:    "a preset declared twice",
			presets: []v1.RulePreset{standardClient(), standardClient()},
			message: `rule preset "standard-client" is declared twice`,
		},
		{
			name:    "a preset without a name",
			presets: []v1.RulePreset{{Rates: []v1.Rate{minuteRate(1)}}},
			message: "a rule preset without a name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := specWithPresets(tc.presets,
				v1.LimitBlock{Name: "api", Rules: []v1.Rule{simpleRule("total")}})

			resolved, problems := Resolve(spec)

			assert.Nil(t, resolved)
			require.Len(t, problems, 1)
			assert.Equal(t, v1.RuleProblem{Reason: v1.ProblemInvalidSpec, Message: tc.message}, problems[0])
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

	require.Empty(t, problems)
	assert.Equal(t, serialized(t, writtenWithDefaults)+2*serialized(t, presetWithDefaults), resolved.EstimatedSize)
}

// serialized is the length of v as JSON, the unit of the size bound.
func serialized(t *testing.T, v any) int {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
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
	bypass := v1.RulePreset{Name: "bypass", Behavior: v1.RuleBehaviorBypass,
		Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorEquals, Value: "prometheus"}}}
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
		"a Bypass preset": specWithPresets([]v1.RulePreset{bypass},
			v1.LimitBlock{Name: "api", Rules: append(plain(40), v1.Rule{Name: "internal", Preset: "bypass"})}),
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			resolved, problems := Resolve(spec)

			require.Empty(t, problems)
			assert.GreaterOrEqual(t, resolved.EstimatedSize, serialized(t, resolved.Spec),
				"the estimate fell below the serialized size of the resolved spec")
		})
	}
}

func TestResolve_refusesAPolicyEstimatedAboveTheSizeBound(t *testing.T) {
	// One copy of the preset is about 600 KB and the spec as written holds
	// that copy; two rules taking it bring the estimate to three copies,
	// about 1.8 MB, over the 1.5 MiB bound.
	preset := bigPreset("wide")
	spec := specWithPresets([]v1.RulePreset{preset}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{
		{Name: "a", Preset: "wide"}, {Name: "b", Preset: "wide"},
	}})

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved)
	require.Len(t, problems, 1)
	assert.Equal(t, v1.ProblemResolvedPolicyTooLarge, problems[0].Reason)
	assert.Empty(t, problems[0].Block, "the size of the policy is a problem of the policy as a whole")
	assert.Contains(t, problems[0].Message, "1572864", "the message names the bound in bytes")
}

func TestResolve_acceptsAPolicyEstimatedBelowTheSizeBound(t *testing.T) {
	// The same preset taken by one rule: two copies, about 1.2 MB.
	spec := specWithPresets([]v1.RulePreset{bigPreset("wide")},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "a", Preset: "wide"}}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems)
	assert.Len(t, resolvedRule(t, resolved, "a").Matches, widePredicates)
}

// The bound is inclusive: an estimate of MaxResolvedSize bytes is within it
// and one byte more is over it. The padding sits in a rule written at the
// point of use, where every byte of it is one byte of the estimate.
func TestResolve_acceptsAnEstimateAtTheBoundAndRefusesOneByteOver(t *testing.T) {
	spec := func(pad int) *v1.RateLimitPolicySpec {
		return specWithPresets([]v1.RulePreset{standardClient()}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{
			{Name: "a", Preset: "standard-client"},
			{Name: "pad", Rates: []v1.Rate{minuteRate(1)}, Matches: []v1.Predicate{
				{Key: "sub", Operator: v1.OperatorEquals, Value: strings.Repeat("x", pad)}}},
		}})
	}
	base, problems := Resolve(spec(1))
	require.Empty(t, problems)
	atBound := MaxResolvedSize - base.EstimatedSize + 1

	resolved, problems := Resolve(spec(atBound))

	require.Empty(t, problems, "an estimate of exactly %d bytes is within the bound", MaxResolvedSize)
	assert.Equal(t, MaxResolvedSize, resolved.EstimatedSize)

	resolved, problems = Resolve(spec(atBound + 1))

	assert.Nil(t, resolved)
	require.Len(t, problems, 1)
	assert.Equal(t, v1.ProblemResolvedPolicyTooLarge, problems[0].Reason)
	assert.Contains(t, problems[0].Message, strconv.Itoa(MaxResolvedSize+1), "the message names the estimate")
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
	require.Less(t, serialized(t, writtenOut), MaxResolvedSize, "the resolved policy itself fits under the bound")

	resolved, problems := Resolve(spec)

	assert.Nil(t, resolved)
	require.Len(t, problems, 1)
	assert.Equal(t, v1.ProblemResolvedPolicyTooLarge, problems[0].Reason)
}

// TestCompile_aPolicyWithPresetsCompilesLikeThePolicyWrittenOut is the
// contract the counter keys rest on: a preset changes how a policy is
// written and nothing about what the engine builds from it, so renaming a
// preset moves no bucket.
func TestCompile_aPolicyWithPresetsCompilesLikeThePolicyWrittenOut(t *testing.T) {
	internalBypass := v1.RulePreset{
		Name:     "internal-bypass",
		Matches:  []v1.Predicate{{Key: "sub", Operator: v1.OperatorEquals, Value: "prometheus"}},
		Behavior: v1.RuleBehaviorBypass,
	}
	target := func(prefix string) *v1.Target {
		return &v1.Target{Routes: []v1.Route{{Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: prefix}}}}
	}
	withPresets := specWithPresets([]v1.RulePreset{internalBypass, standardClient()},
		v1.LimitBlock{Name: "orders", Target: target("/orders"), Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{
			{Name: "internal", Preset: "internal-bypass"},
			{Name: perUserName, Preset: "standard-client"},
		}},
		v1.LimitBlock{Name: "catalog", Target: target("/catalog"), Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{
			{Name: "internal", Preset: "internal-bypass"},
			{Name: "per-user", Preset: "standard-client", Rates: []v1.Rate{minuteRate(300)}},
		}})
	internal := v1.Rule{Name: "internal", Matches: internalBypass.Matches, Behavior: internalBypass.Behavior}
	standard := standardClient()
	perUser := v1.Rule{Name: perUserName, Counters: standard.Counters, Rates: standard.Rates}
	perUserCatalog := perUser
	perUserCatalog.Rates = []v1.Rate{minuteRate(300)}
	writtenOut := &v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "orders", Target: target("/orders"), Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{internal, perUser}},
		{Name: "catalog", Target: target("/catalog"), Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{internal, perUserCatalog}},
	}}

	fromPresets := compileOf(objectWithSpec(withPresets))
	fromWrittenOut := compileOf(objectWithSpec(writtenOut))

	require.NoError(t, fromPresets.Policies[key()].Err)
	require.NoError(t, fromWrittenOut.Policies[key()].Err)
	assert.Equal(t, fromWrittenOut.Snapshots[testDomain], fromPresets.Snapshots[testDomain],
		"the snapshot, its counter key prefixes included, has to be the one the written-out policy builds")
	assert.Equal(t, fromWrittenOut.Policies[key()].Rules, fromPresets.Policies[key()].Rules)
	assert.Equal(t, fromWrittenOut.State[testDomain].GoodSpec, fromPresets.State[testDomain].GoodSpec,
		"last-good holds the resolved spec, which is the written-out one")
}

func objectWithSpec(spec *v1.RateLimitPolicySpec) v1.RateLimitPolicy {
	object := policyObject()
	object.Spec = *spec
	return object
}

// TestCompile_theBundleAndThePayloadCarryNoPreset pins what a service of the
// previous release depends on: the configuration the operator writes is the
// resolved spec, and a preset field never reaches a payload.
func TestCompile_theBundleAndThePayloadCarryNoPreset(t *testing.T) {
	object := objectWithSpec(specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: perUserName, Preset: "standard-client"}}}))

	result := compileOf(object)

	bundle := result.State[testDomain]
	require.Equal(t, int64(1), bundle.GoodGeneration)
	assert.Nil(t, bundle.GoodSpec.Presets)
	assert.Empty(t, bundle.GoodSpec.Limits[0].Rules[0].Preset)
	assert.Equal(t, []string{"sub"}, bundle.GoodSpec.Limits[0].Rules[0].Counters, "the rule is written out")

	compressed, _, err := manifest.EncodePayload(bundle.GoodSpec)
	require.NoError(t, err)
	var document map[string]any
	_, err = manifest.DecodePayload(compressed, &document)
	require.NoError(t, err)
	assert.NotContains(t, jsonKeys(document), "presets")
	assert.NotContains(t, jsonKeys(document), "preset")
}

// jsonKeys lists every object key of a decoded JSON document, at any depth.
func jsonKeys(v any) []string {
	var keys []string
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			keys = append(keys, k)
			keys = append(keys, jsonKeys(child)...)
		}
	case []any:
		for _, child := range node {
			keys = append(keys, jsonKeys(child)...)
		}
	}
	return keys
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
	require.Error(t, outcome.Err)
	assert.Contains(t, outcome.Err.Error(), v1.ProblemUnresolvedPresetReference)
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, "api", outcome.Problems[0].Block)
	assert.Equal(t, perUserName, outcome.Problems[0].Rule)
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "the last-good generation keeps serving")
	assert.Equal(t, 1, outcome.Rules)
}

// The content of a preset is checked through the rules that take it: a preset
// nothing takes can hold a key the domain lacks and no problem reports it,
// while the same preset taken by a rule is reported at that rule, with the
// preset named in the message.
func TestCompile_thePresetsContentIsCheckedThroughTheRulesThatTakeIt(t *testing.T) {
	ghost := v1.RulePreset{Name: "by-ghost", Matches: []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}},
		Rates: []v1.Rate{minuteRate(10)}}

	t.Run("a preset no rule takes is silent", func(t *testing.T) {
		object := objectWithSpec(specWithPresets([]v1.RulePreset{ghost},
			v1.LimitBlock{Name: "api", Rules: []v1.Rule{simpleRule("total")}}))

		outcome := compileOf(object).Policies[key()]

		require.NoError(t, outcome.Err)
		assert.Empty(t, outcome.Problems)
		assert.True(t, outcome.Enforced(), "the generation with an unused preset is not the enforced one")
	})

	t.Run("a preset a rule takes is reported at that rule", func(t *testing.T) {
		object := objectWithSpec(specWithPresets([]v1.RulePreset{ghost},
			v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "per-ghost", Preset: "by-ghost"}}}))

		outcome := compileOf(object).Policies[key()]

		require.Len(t, outcome.Problems, 1)
		assert.Equal(t, v1.ProblemUnresolvedKeyReference, outcome.Problems[0].Reason)
		assert.Equal(t, "api", outcome.Problems[0].Block)
		assert.Equal(t, "per-ghost", outcome.Problems[0].Rule)
		assert.Equal(t, `key "ghost" is not in the effective set of the domain; the rule takes preset "by-ghost"`,
			outcome.Problems[0].Message)
	})
}

// The preset is named at the rule that took it and nowhere else: a plain
// rule of the same block with the same defect, and a rule of the same name
// in a block that takes no preset, keep the engine's message.
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

	messages := map[RuleRef]string{}
	for _, problem := range outcome.Problems {
		messages[RuleRef{Block: problem.Block, Rule: problem.Rule}] = problem.Message
	}
	const engines = `key "ghost" is not in the effective set of the domain`
	assert.Equal(t, map[RuleRef]string{
		{Block: "api", Rule: "per-ghost"}:   engines + `; the rule takes preset "by-ghost"`,
		{Block: "api", Rule: "plain"}:       engines,
		{Block: "other", Rule: "per-ghost"}: engines,
	}, messages)
}

// The engine reads the resolved spec the way it reads any other: an empty
// counters list, whether written or inherited, is one shared bucket. Pinned
// here because the resolver hands the engine an empty non-nil list where a
// written-out policy would have carried none.
func TestCompile_anEmptyCountersListFromAPresetIsOneSharedBucket(t *testing.T) {
	spec := specWithPresets([]v1.RulePreset{standardClient()},
		v1.LimitBlock{Name: "api", Rules: []v1.Rule{{Name: "shared", Preset: "standard-client", Counters: []string{}}}})
	resolved, problems := Resolve(spec)
	require.Empty(t, problems)

	snapshot, engineProblems := enginecompile.Compile(testNamespace, testDomain, convert.Policy(&resolved.Spec))

	require.Empty(t, engineProblems)
	require.Len(t, snapshot.Blocks[0].Rules, 1)
	assert.Empty(t, snapshot.Blocks[0].Rules[0].Counters)
	assert.Regexp(t, ":api/shared:gcra:60:$", snapshot.Blocks[0].Rules[0].Rates[0].Prefix,
		"the key prefix is the point of use's")
}

// A behavior the rule writes wins over the preset's. A default the API server
// wrote into an object stored before the schema change is such a value: the
// compiler cannot tell it from one the author wrote, so the documents say to
// remove it before the rule takes a preset.
func TestResolve_aRuleThatWritesEnforceOverAShadowPresetStaysEnforce(t *testing.T) {
	trial := v1.RulePreset{Name: "trial", Behavior: v1.RuleBehaviorShadow, Rates: []v1.Rate{minuteRate(5)}}
	spec := specWithPresets([]v1.RulePreset{trial}, v1.LimitBlock{Name: "api", Rules: []v1.Rule{
		{Name: "stored-default", Preset: "trial", Behavior: v1.RuleBehaviorEnforce},
	}})

	resolved, problems := Resolve(spec)

	require.Empty(t, problems)
	assert.Equal(t, v1.RuleBehaviorEnforce, resolvedRule(t, resolved, "stored-default").Behavior,
		"a written behavior, a stored default among them, wins over the preset's")
}

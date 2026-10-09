package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

const testDomain = "gateway.public"

// The conversion is a rename, not a translation: the enums are string-typed on
// both sides and carry the same values. That is a deliberate coupling and a
// fragile one, so it is asserted rather than trusted: a value renamed on either
// side would otherwise turn into a silently unmatched rule. Whoever adds an
// enum value on either side adds its row to this table.
func TestEnumValues_areSpelledTheSameInTheAPIAndTheModel(t *testing.T) {
	cases := []struct {
		name       string
		api, model string
	}{
		{"PathMatchExact", string(v1.PathMatchExact), string(model.PathExact)},
		{"PathMatchPrefix", string(v1.PathMatchPrefix), string(model.PathPrefix)},
		{"PathMatchTemplate", string(v1.PathMatchTemplate), string(model.PathTemplate)},

		{"BlockModeAll", string(v1.BlockModeAll), string(model.ModeAll)},
		{"BlockModeFirstMatch", string(v1.BlockModeFirstMatch), string(model.ModeFirstMatch)},

		{"RuleBehaviorEnforce", string(v1.RuleBehaviorEnforce), string(model.BehaviorEnforce)},
		{"RuleBehaviorShadow", string(v1.RuleBehaviorShadow), string(model.BehaviorShadow)},
		{"RuleBehaviorBypass", string(v1.RuleBehaviorBypass), string(model.BehaviorBypass)},

		{"OperatorEquals", string(v1.OperatorEquals), string(model.OperatorEquals)},
		{"OperatorIn", string(v1.OperatorIn), string(model.OperatorIn)},
		{"OperatorInGroup", string(v1.OperatorInGroup), string(model.OperatorInGroup)},
		{"OperatorContains", string(v1.OperatorContains), string(model.OperatorContains)},
		{"OperatorExists", string(v1.OperatorExists), string(model.OperatorExists)},
		{"OperatorDoesNotExist", string(v1.OperatorDoesNotExist), string(model.OperatorDoesNotExist)},

		{"ClaimTypeString", string(v1.ClaimTypeString), string(model.ValueString)},
		{"ClaimTypeStringArray", string(v1.ClaimTypeStringArray), string(model.ValueStringArray)},

		{"NormalizeNone", string(v1.NormalizeNone), string(model.NormalizeNone)},
		{"NormalizeLowercase", string(v1.NormalizeLowercase), string(model.NormalizeLowercase)},

		{"KeyPath", v1.KeyPath, model.KeyPath},
		{"KeyMethod", v1.KeyMethod, model.KeyMethod},
		{"KeySub", v1.KeySub, model.KeySub},
		{"KeyToken", v1.KeyToken, model.KeyToken},

		{"CostSourceQueryParameter", string(v1.CostSourceQueryParameter), string(model.CostQueryParameter)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.api, c.model)
		})
	}
}

// The reasons reach the status as the engine spells them, and alerts are
// written against those strings. Whoever adds a reason on either side adds its
// row to this table.
func TestProblemReasons_areSpelledTheSameInTheAPIAndTheCompiler(t *testing.T) {
	cases := []struct {
		name          string
		api, compiler string
	}{
		{"UnresolvedKeyReference",
			v1.ProblemUnresolvedKeyReference, string(enginecompile.ReasonUnresolvedKeyReference)},
		{"UnresolvedGroupReference",
			v1.ProblemUnresolvedGroupReference, string(enginecompile.ReasonUnresolvedGroupReference)},
		{"IncompatibleOperator", v1.ProblemIncompatibleOperator, string(enginecompile.ReasonIncompatibleOperator)},
		{"InvalidCounterAxis", v1.ProblemInvalidCounterAxis, string(enginecompile.ReasonInvalidCounterAxis)},
		{"CaptureShadowsMappedKey",
			v1.ProblemCaptureShadowsMappedKey, string(enginecompile.ReasonCaptureShadowsMappedKey)},
		{"InvalidSpec", v1.ProblemInvalidSpec, string(enginecompile.ReasonInvalidSpec)},
		{"InvalidWindow", v1.ProblemInvalidWindow, string(enginecompile.ReasonInvalidWindow)},
		{"UnresolvedReplacedRules",
			v1.ProblemUnresolvedReplacedRules, string(enginecompile.ReasonUnresolvedReplacedRules)},
		{"DomainBudgetExceeded", v1.ProblemDomainBudgetExceeded, string(enginecompile.ReasonDomainBudgetExceeded)},
		{"CostExceedsCapacity", v1.ProblemCostExceedsCapacity, string(enginecompile.ReasonCostExceedsCapacity)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.api, c.compiler)
		})
	}
}

// The status derives the severity of a problem from its reason alone, and the
// compiler sets it on every problem it raises; the two agree on both
// informational reasons and on a blocking one.
func TestBlockingProblem_agreesWithTheCompiler(t *testing.T) {
	route := func(cost *model.RouteCost, value string) model.Route {
		return model.Route{Path: model.PathMatch{Type: model.PathTemplate, Value: value}, Cost: cost}
	}
	policy := func(mappings []model.KeyMapping, r model.Route, counters ...string) model.Policy {
		return model.Policy{Domain: testDomain, Mappings: mappings, Blocks: []model.Block{{
			Name:   "api",
			Target: model.Target{Routes: []model.Route{r}},
			Rules: []model.Rule{{Name: "r", Counters: counters,
				Rates: []model.Rate{{Requests: 10, Period: time.Minute}}}},
		}}}
	}
	cases := []struct {
		name   string
		policy model.Policy
		reason string
	}{
		{"a default cost above a window's capacity", policy(nil, route(
			&model.RouteCost{Source: model.CostQueryParameter, Name: "limit", Default: 11}, "/api/{id}")),
			v1.ProblemCostExceedsCapacity},
		{"a capture that shadows a mapped key", policy(
			[]model.KeyMapping{{Key: "id", Claim: "id"}}, route(nil, "/api/{id}")),
			v1.ProblemCaptureShadowsMappedKey},
		{"a counter axis nothing produces", policy(nil, route(nil, "/api/{id}"), "tenant"),
			v1.ProblemUnresolvedKeyReference},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, problems := enginecompile.Compile("core-1-core", testDomain, &c.policy)

			require.Len(t, problems, 1, "the problems of %s", c.name)
			assert.Equal(t, c.reason, string(problems[0].Reason))
			assert.Equal(t, problems[0].Blocking, v1.BlockingProblem(c.reason), "BlockingProblem(%s)", c.reason)
		})
	}
}

func TestPolicy_convertsEveryFieldOfTheSpec(t *testing.T) {
	burst := int32(10)
	defaultCost := int32(20)
	spec := &v1.RateLimitPolicySpec{
		Domain: testDomain,
		Mappings: []v1.ClaimMapping{{
			Key:           "tenant",
			Claim:         "org_id",
			Type:          v1.ClaimTypeString,
			Normalization: v1.NormalizeLowercase,
			Fallbacks:     []string{"sub"},
		}, {
			Key:       "entitlements",
			ClaimPath: []string{"https://acme.com/entitlements"},
			Type:      v1.ClaimTypeStringArray,
		}},
		Groups: []v1.Group{{Name: "partners", Values: []string{"p1", "p2"}}},
		Limits: []v1.LimitBlock{{
			Name: "api",
			Mode: v1.BlockModeFirstMatch,
			Target: &v1.Target{Routes: []v1.Route{{
				Path:    v1.PathMatch{Type: v1.PathMatchTemplate, Value: "/api/{id}"},
				Methods: []v1.HTTPMethod{"GET", "POST"},
				Cost:    &v1.RouteCost{Source: v1.CostSourceQueryParameter, Name: "limit", Default: &defaultCost},
			}}},
			Rules: []v1.Rule{{
				Name: "per-user",
				Matches: []v1.Predicate{
					{Key: "sub", Operator: v1.OperatorIn, Values: []string{"a"}},
					{Key: "tenant", Operator: v1.OperatorEquals, Value: "acme"},
				},
				Counters:      []string{"sub"},
				Behavior:      v1.RuleBehaviorShadow,
				ReplacedRules: []string{"other"},
				Rates: []v1.Rate{{
					Requests: 100, PeriodSeconds: 60, Burst: &burst, Algorithm: v1.AlgorithmGCRA,
				}},
			}},
		}},
	}

	got := Policy(spec)

	assert.Equal(t, &model.Policy{
		Domain: testDomain,
		Mappings: []model.KeyMapping{{
			Key:           "tenant",
			Claim:         "org_id",
			Type:          model.ValueString,
			Normalization: model.NormalizeLowercase,
			Fallbacks:     []string{"sub"},
		}, {
			Key:       "entitlements",
			ClaimPath: []string{"https://acme.com/entitlements"},
			Type:      model.ValueStringArray,
		}},
		Groups: []model.Group{{Name: "partners", Values: []string{"p1", "p2"}}},
		Blocks: []model.Block{{
			Name: "api",
			Mode: model.ModeFirstMatch,
			Target: model.Target{Routes: []model.Route{{
				Path:    model.PathMatch{Type: model.PathTemplate, Value: "/api/{id}"},
				Methods: []string{"GET", "POST"},
				Cost:    &model.RouteCost{Source: model.CostQueryParameter, Name: "limit", Default: 20},
			}}},
			Rules: []model.Rule{{
				Name: "per-user",
				Matches: []model.Predicate{
					{Key: "sub", Operator: model.OperatorIn, Values: []string{"a"}},
					{Key: "tenant", Operator: model.OperatorEquals, Value: "acme"},
				},
				Counters:      []string{"sub"},
				Behavior:      model.BehaviorShadow,
				ReplacedRules: []string{"other"},
				Rates:         []model.Rate{{Requests: 100, Period: time.Minute, Burst: 10, Algorithm: "GCRA"}},
			}},
		}},
	}, got)
}

// convertedRate converts a spec whose one rule carries rate, and returns that
// rule's one converted rate.
func convertedRate(t *testing.T, rate v1.Rate) model.Rate {
	t.Helper()
	policy := Policy(&v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{{
		Name: "api", Rules: []v1.Rule{{Name: "r", Rates: []v1.Rate{rate}}},
	}}})
	require.Len(t, policy.Blocks, 1)
	require.Len(t, policy.Blocks[0].Rules, 1)
	require.Len(t, policy.Blocks[0].Rules[0].Rates, 1)
	return policy.Blocks[0].Rules[0].Rates[0]
}

// Zero is how the engine is told "unset", and it applies the documented
// default of a full bucket. Spelling that out here would put one rule in two
// places, and the two would drift. A set burst is converted as it is, in
// TestPolicy_convertsEveryFieldOfTheSpec.
func TestPolicy_leavesAnUnsetBurstAtZero(t *testing.T) {
	rate := convertedRate(t, v1.Rate{Requests: 100, PeriodSeconds: 60})

	assert.Equal(t, int64(0), rate.Burst)
}

// An unset default cost stays zero, which the engine reads as one, as it reads
// an unset burst. A set default is converted as it is, in
// TestPolicy_convertsEveryFieldOfTheSpec.
func TestPolicy_leavesAnUnsetDefaultCostAtZero(t *testing.T) {
	policy := Policy(&v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{{
		Name: "api",
		Target: &v1.Target{Routes: []v1.Route{{
			Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: "/api"},
			Cost: &v1.RouteCost{Source: v1.CostSourceQueryParameter, Name: "limit"},
		}}},
		Rules: []v1.Rule{{Name: "r", Rates: []v1.Rate{{Requests: 100, PeriodSeconds: 60}}}},
	}}})

	require.Len(t, policy.Blocks, 1)
	require.Len(t, policy.Blocks[0].Target.Routes, 1)
	assert.Equal(t, &model.RouteCost{Source: model.CostQueryParameter, Name: "limit"},
		policy.Blocks[0].Target.Routes[0].Cost)
}

// A nil spec, which is how "no policy" arrives, converts to a nil policy
// rather than an empty one. compile.Compile reads a nil policy as the empty
// domain: the built-in keys and no blocks.
func TestPolicy_convertsANilSpecToANilPolicy(t *testing.T) {
	assert.Nil(t, Policy(nil))
}

// The API carries the period as whole seconds, with the unit in the field name
// as the Kubernetes API conventions require, so nothing parses a duration
// string.
func TestPolicy_readsThePeriodAsSeconds(t *testing.T) {
	cases := []struct {
		name    string
		seconds int32
		want    time.Duration
	}{
		{"one second", 1, time.Second},
		{"thirty seconds", 30, 30 * time.Second},
		{"sixty seconds are a minute", 60, time.Minute},
		{"3600 seconds are an hour", 3600, time.Hour},
		{"86400 seconds are a day", 86400, 24 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rate := convertedRate(t, v1.Rate{Requests: 100, PeriodSeconds: c.seconds})

			assert.Equal(t, c.want, rate.Period, "PeriodSeconds %d", c.seconds)
		})
	}
}

// A block without a target applies to all traffic of the domain, and the
// engine reads that from a target with no routes.
func TestPolicy_convertsABlockWithoutATargetToATargetWithNoRoutes(t *testing.T) {
	policy := Policy(&v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{{
		Name: "api", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: 100, PeriodSeconds: 60}}}},
	}}})

	require.Len(t, policy.Blocks, 1)
	assert.Empty(t, policy.Blocks[0].Target.Routes, "the routes of the block without a target")
}

// The blocks and the rules within each keep the author's order: a FirstMatch
// block applies the first rule that matches, so the order of its rules is
// semantics. The names are out of alphabetical order, so a sort fails the
// test too.
func TestPolicy_keepsTheOrderOfTheBlocksAndOfTheirRules(t *testing.T) {
	rule := func(name string) v1.Rule {
		return v1.Rule{Name: name, Rates: []v1.Rate{{Requests: 100, PeriodSeconds: 60}}}
	}
	policy := Policy(&v1.RateLimitPolicySpec{Domain: testDomain, Limits: []v1.LimitBlock{
		{Name: "orders", Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{rule("partners"), rule("everyone")}},
		{Name: "invoices", Rules: []v1.Rule{rule("per-user"), rule("anonymous")}},
	}})

	got := make([]string, 0, 4)
	for _, block := range policy.Blocks {
		for _, rule := range block.Rules {
			got = append(got, block.Name+"/"+rule.Name)
		}
	}
	assert.Equal(t, []string{"orders/partners", "orders/everyone", "invoices/per-user", "invoices/anonymous"}, got)
}

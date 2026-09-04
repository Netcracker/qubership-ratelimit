package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// The conversion is a rename, not a translation: the enums are string-typed on
// both sides and carry the same values. That is a deliberate coupling and a
// fragile one, so it is asserted rather than trusted — a value renamed on either
// side would otherwise turn into a silently unmatched rule.

func TestModelVocabulary_matchesTheAPI(t *testing.T) {
	assert.Equal(t, string(model.PathExact), string(v1alpha1.PathMatchExact))
	assert.Equal(t, string(model.PathPrefix), string(v1alpha1.PathMatchPrefix))
	assert.Equal(t, string(model.PathTemplate), string(v1alpha1.PathMatchTemplate))

	assert.Equal(t, string(model.ModeAll), string(v1alpha1.BlockModeAll))
	assert.Equal(t, string(model.ModeFirstMatch), string(v1alpha1.BlockModeFirstMatch))

	assert.Equal(t, string(model.BehaviorEnforce), string(v1alpha1.RuleBehaviorEnforce))
	assert.Equal(t, string(model.BehaviorShadow), string(v1alpha1.RuleBehaviorShadow))
	assert.Equal(t, string(model.BehaviorBypass), string(v1alpha1.RuleBehaviorBypass))

	assert.Equal(t, string(model.OperatorEquals), string(v1alpha1.OperatorEquals))
	assert.Equal(t, string(model.OperatorIn), string(v1alpha1.OperatorIn))
	assert.Equal(t, string(model.OperatorInGroup), string(v1alpha1.OperatorInGroup))
	assert.Equal(t, string(model.OperatorContains), string(v1alpha1.OperatorContains))
	assert.Equal(t, string(model.OperatorExists), string(v1alpha1.OperatorExists))
	assert.Equal(t, string(model.OperatorDoesNotExist), string(v1alpha1.OperatorDoesNotExist))

	assert.Equal(t, string(model.ValueString), string(v1alpha1.ClaimTypeString))
	assert.Equal(t, string(model.ValueStringArray), string(v1alpha1.ClaimTypeStringArray))

	assert.Equal(t, string(model.NormalizeNone), string(v1alpha1.NormalizeNone))
	assert.Equal(t, string(model.NormalizeLowercase), string(v1alpha1.NormalizeLowercase))

	assert.Equal(t, model.KeyPath, v1alpha1.KeyPath)
	assert.Equal(t, model.KeyMethod, v1alpha1.KeyMethod)
	assert.Equal(t, model.KeyClient, v1alpha1.KeyClient)
	assert.Equal(t, model.KeyToken, v1alpha1.KeyToken)
}

func TestProblemVocabulary_matchesTheAPI(t *testing.T) {
	// The reasons reach the status as the engine spells them, and alerts are
	// written against those strings.
	assert.Equal(t, string(enginecompile.ReasonUnresolvedKeyReference), v1alpha1.ProblemUnresolvedKeyReference)
	assert.Equal(t, string(enginecompile.ReasonUnresolvedGroupReference), v1alpha1.ProblemUnresolvedGroupReference)
	assert.Equal(t, string(enginecompile.ReasonIncompatibleOperator), v1alpha1.ProblemIncompatibleOperator)
	assert.Equal(t, string(enginecompile.ReasonInvalidCounterAxis), v1alpha1.ProblemInvalidCounterAxis)
	assert.Equal(t, string(enginecompile.ReasonCaptureShadowsMappedKey), v1alpha1.ProblemCaptureShadowsMappedKey)
	assert.Equal(t, string(enginecompile.ReasonInvalidSpec), v1alpha1.ProblemInvalidSpec)
	assert.Equal(t, string(enginecompile.ReasonInvalidWindow), v1alpha1.ProblemInvalidWindow)
	assert.Equal(t, string(enginecompile.ReasonUnresolvedReplacedRules), v1alpha1.ProblemUnresolvedReplacedRules)
	assert.Equal(t, string(enginecompile.ReasonDomainBudgetExceeded), v1alpha1.ProblemDomainBudgetExceeded)
}

func TestModelPolicy_carriesTheWholeSpec(t *testing.T) {
	burst := int32(10)
	spec := &v1alpha1.RateLimitPolicySpec{
		Domain: testDomain,
		Mappings: []v1alpha1.ClaimMapping{{
			Key:           "tenant",
			Claim:         "org_id",
			Type:          v1alpha1.ClaimTypeString,
			Normalization: v1alpha1.NormalizeLowercase,
			Fallbacks:     []string{"sub"},
		}, {
			Key:       "entitlements",
			ClaimPath: []string{"https://acme.com/entitlements"},
			Type:      v1alpha1.ClaimTypeStringArray,
		}},
		Groups: []v1alpha1.ClientGroup{{Name: "partners", Clients: []string{"p1", "p2"}}},
		Limits: []v1alpha1.LimitBlock{{
			Name: "api",
			Mode: v1alpha1.BlockModeFirstMatch,
			Target: &v1alpha1.Target{Routes: []v1alpha1.Route{{
				Path:    v1alpha1.PathMatch{Type: v1alpha1.PathMatchTemplate, Value: "/api/{id}"},
				Methods: []v1alpha1.HTTPMethod{"GET", "POST"},
			}}},
			Rules: []v1alpha1.Rule{{
				Name:          "per-user",
				Matches:       []v1alpha1.Predicate{{Key: "client", Operator: v1alpha1.OperatorIn, Values: []string{"a"}}},
				Counters:      []string{"client"},
				Behavior:      v1alpha1.RuleBehaviorShadow,
				ReplacedRules: []string{"other"},
				Rates: []v1alpha1.Rate{{
					Requests: 100, PeriodSeconds: 60, Burst: &burst, Algorithm: v1alpha1.AlgorithmGCRA,
				}},
			}},
		}},
	}

	out := modelPolicy(spec)

	require.NotNil(t, out)
	assert.Equal(t, testDomain, out.Domain)
	require.Len(t, out.Groups, 1)
	assert.Equal(t, []string{"p1", "p2"}, out.Groups[0].Clients)

	require.Len(t, out.Mappings, 2)
	assert.Equal(t, "org_id", out.Mappings[0].Claim)
	assert.Equal(t, model.NormalizeLowercase, out.Mappings[0].Normalization)
	assert.Equal(t, []string{"sub"}, out.Mappings[0].Fallbacks)
	assert.Equal(t, []string{"https://acme.com/entitlements"}, out.Mappings[1].ClaimPath)
	assert.Equal(t, model.ValueStringArray, out.Mappings[1].Type)

	require.Len(t, out.Blocks, 1)
	block := out.Blocks[0]
	assert.Equal(t, model.ModeFirstMatch, block.Mode)
	require.Len(t, block.Target.Routes, 1)
	assert.Equal(t, model.PathTemplate, block.Target.Routes[0].Path.Type)
	assert.Equal(t, []string{"GET", "POST"}, block.Target.Routes[0].Methods)

	require.Len(t, block.Rules, 1)
	rule := block.Rules[0]
	assert.Equal(t, model.BehaviorShadow, rule.Behavior)
	assert.Equal(t, []string{"client"}, rule.Counters)
	assert.Equal(t, []string{"other"}, rule.ReplacedRules)
	require.Len(t, rule.Matches, 1)
	assert.Equal(t, model.OperatorIn, rule.Matches[0].Operator)
	require.Len(t, rule.Rates, 1)
	assert.Equal(t, int64(100), rule.Rates[0].Requests)
	assert.Equal(t, time.Minute, rule.Rates[0].Period)
	assert.Equal(t, int64(10), rule.Rates[0].Burst)
	assert.Equal(t, "GCRA", rule.Rates[0].Algorithm)
}

func TestModelRule_anUnsetBurstStaysZero(t *testing.T) {
	// Zero is how the engine is told "unset", and it applies the documented
	// default of a full bucket. Spelling that out here would put one rule in two
	// places, and the two would drift.
	rule := modelRule(&v1alpha1.Rule{
		Name:  "r",
		Rates: []v1alpha1.Rate{{Requests: 100, PeriodSeconds: 60}},
	})

	assert.Zero(t, rule.Rates[0].Burst)
}

// TestModelPolicy_noSpecIsTheEmptyDomain pins how "no policy" reaches the
// engine: as a nil policy rather than an empty one, which is the built-ins-only
// domain.
func TestModelPolicy_noSpecIsTheEmptyDomain(t *testing.T) {
	assert.Nil(t, modelPolicy(nil))
}

// TestModelPeriod_isPlainSeconds pins the unit the API moved to: the field name
// carries it, the way the Kubernetes API conventions ask, so nothing parses a
// duration string any more.
func TestModelPeriod_isPlainSeconds(t *testing.T) {
	cases := map[int32]time.Duration{
		1:     time.Second,
		30:    30 * time.Second,
		60:    time.Minute,
		3600:  time.Hour,
		86400: 24 * time.Hour,
	}
	for seconds, want := range cases {
		rule := modelRule(&v1alpha1.Rule{
			Name:  "r",
			Rates: []v1alpha1.Rate{{Requests: 100, PeriodSeconds: seconds}},
		})
		assert.Equal(t, want, rule.Rates[0].Period)
	}
}

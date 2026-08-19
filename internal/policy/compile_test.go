package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

const (
	testNamespace = "biz"
	testDomain    = "gateway.public"
)

func policyObject(name string, blocks ...v1alpha1.LimitBlock) v1alpha1.RateLimitPolicy {
	return v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name, Generation: 1},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain: testDomain,
			Limits: blocks,
		},
	}
}

func mappingObject(entries ...v1alpha1.ClaimMapping) v1alpha1.RateLimitMapping {
	return v1alpha1.RateLimitMapping{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testDomain, Generation: 1},
		Spec: v1alpha1.RateLimitMappingSpec{
			Domain:   testDomain,
			Mappings: entries,
		},
	}
}

func minuteRate(requests int32) v1alpha1.Rate {
	return v1alpha1.Rate{Requests: requests, Period: "1m"}
}

func simpleRule(name string, when ...v1alpha1.Predicate) v1alpha1.Rule {
	return v1alpha1.Rule{Name: name, When: when, Rates: []v1alpha1.Rate{minuteRate(100)}}
}

func key(name string) client.ObjectKey {
	return client.ObjectKey{Namespace: testNamespace, Name: name}
}

func TestCompile_isAPureFunctionOfTheSet(t *testing.T) {
	// The order the objects arrived in must not reach the snapshot: two replicas
	// listing the same namespace have to produce the same rules.
	first := policyObject("alpha", v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("r")}})
	second := policyObject("zeta", v1alpha1.LimitBlock{Name: "z", Rules: []v1alpha1.Rule{simpleRule("r")}})

	forward := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{first, second}})
	reverse := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{second, first}})

	assert.Equal(t, []string{"alpha", "zeta"}, blockPolicies(forward))
	assert.Equal(t, blockPolicies(forward), blockPolicies(reverse))
}

func blockPolicies(result *Result) []string {
	blocks := result.Snapshot.Domain(testDomain).Blocks
	names := make([]string, 0, len(blocks))
	for _, block := range blocks {
		names = append(names, block.Policy)
	}
	return names
}

func TestCompile_blockNamesAreScopedToTheirPolicy(t *testing.T) {
	// Two policies naming one block are independent additive blocks, not a
	// conflict: the counter key carries the policy, the block and the rule.
	first := policyObject("alpha", v1alpha1.LimitBlock{Name: "shared", Rules: []v1alpha1.Rule{simpleRule("r")}})
	second := policyObject("beta", v1alpha1.LimitBlock{Name: "shared", Rules: []v1alpha1.Rule{simpleRule("r")}})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{first, second}})

	blocks := result.Snapshot.Domain(testDomain).Blocks
	require.Len(t, blocks, 2)
	assert.Equal(t, "alpha", blocks[0].Policy)
	assert.Equal(t, "beta", blocks[1].Policy)
	assert.NoError(t, result.Policies[key("alpha")].Err)
	assert.NoError(t, result.Policies[key("beta")].Err)
}

func TestCompile_reportsWhatEachPolicyContributed(t *testing.T) {
	object := policyObject("orders",
		v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("one"), simpleRule("two")}},
		v1alpha1.LimitBlock{Name: "b", Rules: []v1alpha1.Rule{simpleRule("one")}},
	)

	outcome := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}}).Policies[key("orders")]

	assert.Equal(t, 2, outcome.Blocks)
	assert.Equal(t, 3, outcome.Rules)
	assert.Equal(t, int64(1), outcome.Generation)
	assert.Equal(t, int64(1), outcome.ActiveGeneration)
	assert.True(t, outcome.Ready())
}

func TestCompile_builtInClientKeyWorksWithNoMapping(t *testing.T) {
	// A policy never waits for a mapping.
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name:  "a",
		Rules: []v1alpha1.Rule{simpleRule("per-user", v1alpha1.Predicate{Key: "client", Operator: v1alpha1.OperatorExists})},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	assert.Empty(t, result.Policies[key("orders")].Problems)
	assert.Equal(t, []string{"client", "method", "path"}, result.Snapshot.Domain(testDomain).EffectiveKeys())
}

func TestCompile_anUnresolvedKeyInvalidatesTheWholeGeneration(t *testing.T) {
	// One dead rule cannot be applied on its own: a FirstMatch cascade missing a
	// rule silently hands its traffic to the neighbours, which are either stricter
	// or looser than the author intended. So the generation is enforced whole or
	// not at all.
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "quote-api",
		Rules: []v1alpha1.Rule{
			simpleRule("per-plan", v1alpha1.Predicate{Key: "plan", Operator: v1alpha1.OperatorExists}),
			simpleRule("total"),
		},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	outcome := result.Policies[key("orders")]
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemUnresolvedKeyReference, outcome.Problems[0].Reason)
	assert.Equal(t, "quote-api", outcome.Problems[0].Block)
	assert.Equal(t, "per-plan", outcome.Problems[0].Rule)
	assert.Contains(t, outcome.Problems[0].Message, `key "plan" is not in the effective set`)

	assert.False(t, outcome.Ready())
	assert.Zero(t, outcome.ActiveGeneration)
	assert.Empty(t, result.Snapshot.Domain(testDomain).Blocks,
		"the healthy rule of an invalid policy must not be applied either")
}

func TestCompile_namesTheFixForAnUnresolvedReference(t *testing.T) {
	// "No mapping at all" and "the mapping does not declare this key" are
	// different fixes, so they are different reasons.
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name:  "api",
		Rules: []v1alpha1.Rule{simpleRule("per-plan", v1alpha1.Predicate{Key: "plan", Operator: v1alpha1.OperatorExists})},
	})

	withoutMapping := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})
	assert.Equal(t, v1alpha1.ReasonMappingRequired, withoutMapping.Policies[key("orders")].Reason)

	withMapping := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mappingObject(
			v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"})},
	})
	assert.Equal(t, v1alpha1.ReasonUnresolvedReferences, withMapping.Policies[key("orders")].Reason)
}

func TestCompile_anIncompatibleReferenceHasItsOwnReason(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("by-role",
			v1alpha1.Predicate{Key: "roles", Operator: v1alpha1.OperatorEquals, Value: "admin"})},
	})
	mapping := mappingObject(v1alpha1.ClaimMapping{
		Key: "roles", Claim: "realm_access.roles", Type: v1alpha1.ClaimTypeStringArray,
	})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	assert.Equal(t, v1alpha1.ReasonIncompatibleReferences, result.Policies[key("orders")].Reason)
}

func TestCompile_equalsAgainstAnArrayKeyIsIncompatible(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("by-role",
			v1alpha1.Predicate{Key: "roles", Operator: v1alpha1.OperatorEquals, Value: "admin"})},
	})
	mapping := mappingObject(v1alpha1.ClaimMapping{
		Key: "roles", Claim: "realm_access.roles", Type: v1alpha1.ClaimTypeStringArray,
	})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	outcome := result.Policies[key("orders")]
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemIncompatibleOperator, outcome.Problems[0].Reason)
	assert.Zero(t, outcome.ActiveGeneration, "a blocking problem keeps the generation out")
}

func TestCompile_anArrayKeyCannotBeACounterAxis(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{{
			Name:     "per-role",
			Counters: []string{"roles"},
			Rates:    []v1alpha1.Rate{minuteRate(100)},
		}},
	})
	mapping := mappingObject(v1alpha1.ClaimMapping{
		Key: "roles", Claim: "roles", Type: v1alpha1.ClaimTypeStringArray,
	})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	outcome := result.Policies[key("orders")]
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemInvalidCounterAxis, outcome.Problems[0].Reason)
	assert.Zero(t, outcome.ActiveGeneration)
}

func TestCompile_inGroupNeedsAGroupThatExists(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("partners",
			v1alpha1.Predicate{Key: "client", Operator: v1alpha1.OperatorInGroup, Value: "absent"})},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	outcome := result.Policies[key("orders")]
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemUnresolvedGroupReference, outcome.Problems[0].Reason)
	assert.Zero(t, outcome.ActiveGeneration)
}

func TestCompile_groupMembersAreLowerCased(t *testing.T) {
	// The source policies compared identities with OrdinalIgnoreCase, and the
	// normalization is what preserves that.
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("partners",
			v1alpha1.Predicate{Key: "client", Operator: v1alpha1.OperatorInGroup, Value: "partners"})},
	})
	object.Spec.Groups = []v1alpha1.ClientGroup{{Name: "partners", Clients: []string{"MVNO_Acc1"}}}

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	predicate := result.Snapshot.Domain(testDomain).Blocks[0].Rules[0].Predicates[0]
	assert.True(t, predicate.Fold)
	assert.Contains(t, predicate.Set, "mvno_acc1")
}

func TestCompile_aPrivateGroupShadowsTheSharedOne(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("partners",
			v1alpha1.Predicate{Key: "client", Operator: v1alpha1.OperatorInGroup, Value: "partners"})},
	})
	object.Spec.Groups = []v1alpha1.ClientGroup{{Name: "partners", Clients: []string{"private"}}}

	mapping := mappingObject()
	mapping.Spec.Groups = []v1alpha1.ClientGroup{{Name: "partners", Clients: []string{"shared"}}}

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	members := result.Snapshot.Domain(testDomain).Blocks[0].Rules[0].Predicates[0].Set
	assert.Contains(t, members, "private")
	assert.NotContains(t, members, "shared")
}

func TestCompile_aSharedGroupIsVisibleToEveryPolicyOfTheDomain(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("partners",
			v1alpha1.Predicate{Key: "client", Operator: v1alpha1.OperatorInGroup, Value: "partners"})},
	})
	mapping := mappingObject()
	mapping.Spec.Groups = []v1alpha1.ClientGroup{{Name: "partners", Clients: []string{"p1"}}}

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	assert.Empty(t, result.Policies[key("orders")].Problems)
	assert.Contains(t, result.Snapshot.Domain(testDomain).Blocks[0].Rules[0].Predicates[0].Set, "p1")
}

func TestCompile_aMappingEntryNamedClientOverridesTheBuiltInOne(t *testing.T) {
	// The override replaces the built-in definition rather than joining it, so the
	// domain has exactly one definition of every key. Redefining it as an array is
	// what makes the difference visible.
	mapping := mappingObject(v1alpha1.ClaimMapping{
		Key: "client", Claim: "groups", Type: v1alpha1.ClaimTypeStringArray,
	})

	result := Compile(Input{Mappings: []v1alpha1.RateLimitMapping{mapping}})

	keys := result.Snapshot.Domain(testDomain).Keys
	require.Contains(t, keys, v1alpha1.KeyClient)
	assert.Equal(t, KeyArray, keys[v1alpha1.KeyClient])
}

func TestCompile_theShapeOfAClaimDecidesWhatARuleMayDoWithIt(t *testing.T) {
	mapping := mappingObject(
		v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}},
		v1alpha1.ClaimMapping{Key: "roles", Claim: "realm_access.roles", Type: v1alpha1.ClaimTypeStringArray},
	)

	result := Compile(Input{Mappings: []v1alpha1.RateLimitMapping{mapping}})

	keys := result.Snapshot.Domain(testDomain).Keys
	assert.Equal(t, KeyScalar, keys["tenant"], "a scalar key may serve as a counter axis")
	assert.Equal(t, KeyArray, keys["roles"], "an array key may not, and rejects Equals")
}

func TestCompile_publishesTheEffectiveKeys(t *testing.T) {
	mapping := mappingObject(
		v1alpha1.ClaimMapping{Key: "roles", Claim: "realm_access.roles", Type: v1alpha1.ClaimTypeStringArray},
		v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"},
	)

	outcome := Compile(Input{Mappings: []v1alpha1.RateLimitMapping{mapping}}).Mappings[key(testDomain)]

	require.NoError(t, outcome.Err)
	assert.Equal(t, []string{"client", "method", "path", "roles", "tenant"}, outcome.EffectiveKeys)
}

func TestCompile_aCaptureShadowingAMappedKeyIsReported(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Target: &v1alpha1.Target{Routes: []v1alpha1.Route{{
			Path: v1alpha1.PathMatch{Type: v1alpha1.PathMatchTemplate, Value: "/api/{tenant}/orders"},
		}}},
		Rules: []v1alpha1.Rule{simpleRule("r")},
	})
	mapping := mappingObject(v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{object},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	problems := result.Policies[key("orders")].Problems
	require.Len(t, problems, 1)
	assert.Equal(t, v1alpha1.ProblemCaptureShadowsMappedKey, problems[0].Reason)
	assert.Empty(t, problems[0].Rule, "the shadowing is a property of the block, not of one rule")
	assert.True(t, result.Policies[key("orders")].Ready(),
		"shadowing is informational and must not invalidate the generation")
	assert.Len(t, result.Snapshot.Domain(testDomain).Blocks, 1)
}

func TestCompile_aCaptureIsAKeyOfItsBlock(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Target: &v1alpha1.Target{Routes: []v1alpha1.Route{{
			Path: v1alpha1.PathMatch{Type: v1alpha1.PathMatchTemplate, Value: "/api/orders/{order_id}"},
		}}},
		Rules: []v1alpha1.Rule{{
			Name:     "per-order",
			Counters: []string{"order_id"},
			Rates:    []v1alpha1.Rate{minuteRate(10)},
		}},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	assert.Empty(t, result.Policies[key("orders")].Problems)
}

func TestCompile_aDanglingReplacesRejectsThePolicy(t *testing.T) {
	// The CRD cost estimator would not accept this check in CEL, so the compiler
	// stands in for it: a name that silences nothing while looking like it does is
	// a spec error, not a diagnostic.
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{{
			Name:     "narrow",
			Replaces: []string{"absent"},
			Rates:    []v1alpha1.Rate{minuteRate(10)},
		}},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	require.Error(t, result.Policies[key("orders")].Err)
	assert.Empty(t, result.Snapshot.Domain(testDomain).Blocks,
		"a rejected policy must contribute nothing")
}

func TestCompile_aRepeatedTemplatePlaceholderRejectsThePolicy(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Target: &v1alpha1.Target{Routes: []v1alpha1.Route{{
			Path: v1alpha1.PathMatch{Type: v1alpha1.PathMatchTemplate, Value: "/api/{id}/sub/{id}"},
		}}},
		Rules: []v1alpha1.Rule{simpleRule("r")},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	require.Error(t, result.Policies[key("orders")].Err)
}

func TestCompile_oneBadPolicyLeavesTheRestOfTheDomainAlone(t *testing.T) {
	// A single bad policy must not be able to turn the limits of a whole gateway
	// off.
	broken := policyObject("broken", v1alpha1.LimitBlock{
		Name:  "a",
		Rules: []v1alpha1.Rule{{Name: "r", Replaces: []string{"absent"}, Rates: []v1alpha1.Rate{minuteRate(1)}}},
	})
	healthy := policyObject("healthy", v1alpha1.LimitBlock{
		Name: "b", Rules: []v1alpha1.Rule{simpleRule("r")},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{broken, healthy}})

	assert.Error(t, result.Policies[key("broken")].Err)
	assert.NoError(t, result.Policies[key("healthy")].Err)
	require.Len(t, result.Snapshot.Domain(testDomain).Blocks, 1)
	assert.Equal(t, "healthy", result.Snapshot.Domain(testDomain).Blocks[0].Policy)
}

func TestCompile_aMappingWhoseNameIsNotItsDomainIsIgnored(t *testing.T) {
	// The API server rejects it, so this only happens through a client that
	// bypassed validation. Taking it would make the singleton a lie.
	mapping := mappingObject(v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"})
	mapping.Name = "something-else"

	result := Compile(Input{Mappings: []v1alpha1.RateLimitMapping{mapping}})

	assert.Empty(t, result.Snapshot.Names())
}

func TestCompile_defaultsFollowTheSchema(t *testing.T) {
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name:  "a",
		Rules: []v1alpha1.Rule{{Name: "r", Rates: []v1alpha1.Rate{{Requests: 100, Period: "1m"}}}},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}})

	block := result.Snapshot.Domain(testDomain).Blocks[0]
	assert.Equal(t, v1alpha1.BlockModeAll, block.Mode)
	assert.Equal(t, v1alpha1.RuleBehaviorEnforce, block.Rules[0].Behavior)
	assert.Equal(t, v1alpha1.AlgorithmGCRA, block.Rules[0].Rates[0].Algorithm)
	assert.Equal(t, int64(100), block.Rules[0].Rates[0].Burst, "an unset burst is a full bucket")
}

func TestParsePeriod(t *testing.T) {
	valid := map[string]time.Duration{
		"1s":  time.Second,
		"30s": 30 * time.Second,
		"5m":  5 * time.Minute,
		"1h":  time.Hour,
		"1d":  24 * time.Hour,
	}
	for input, want := range valid {
		t.Run(input, func(t *testing.T) {
			got, err := ParsePeriod(input)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}

	invalid := []string{"", "s", "0s", "1", "1w", "2d", "25h", "1m30s", "-1m", "1.5m"}
	for _, input := range invalid {
		t.Run("rejects "+input, func(t *testing.T) {
			_, err := ParsePeriod(input)
			assert.Error(t, err)
		})
	}
}

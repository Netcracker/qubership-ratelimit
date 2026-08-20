package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// What the engine decides — which rules compile, which references resolve, what a
// counter key looks like — is covered by the engine module's own suite and is not
// restated here. These tests are about the part that is ours: which generation of
// each object the engine is handed, and how what it says back becomes status.

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
	// The order the objects arrived in must not reach the engine: two replicas
	// listing the same namespace have to hand it the same set.
	first := policyObject("alpha", v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("r")}})
	second := policyObject("zeta", v1alpha1.LimitBlock{Name: "z", Rules: []v1alpha1.Rule{simpleRule("r")}})

	forward := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{first, second}})
	reverse := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{second, first}})

	assert.Equal(t, []string{"alpha", "zeta"}, blockPolicies(forward))
	assert.Equal(t, blockPolicies(forward), blockPolicies(reverse))
}

func blockPolicies(result *Result) []string {
	blocks := result.Snapshots[testDomain].Blocks
	names := make([]string, 0, len(blocks))
	for i := range blocks {
		names = append(names, blocks[i].Policy)
	}
	return names
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

func TestCompile_aBlockingProblemKeepsTheWholeGenerationOut(t *testing.T) {
	// One dead rule cannot be applied on its own: a FirstMatch cascade missing a
	// rule silently hands its traffic to the neighbours. The engine drops such a
	// policy; what is asserted here is that the status says so.
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

	assert.False(t, outcome.Ready())
	assert.Zero(t, outcome.ActiveGeneration)
	assert.Empty(t, result.Snapshots[testDomain].Blocks,
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

	outcome := result.Policies[key("orders")]
	assert.Equal(t, v1alpha1.ReasonIncompatibleReferences, outcome.Reason)
	assert.Zero(t, outcome.ActiveGeneration)
}

func TestCompile_aMalformedSpecClearsAccepted(t *testing.T) {
	// Accepted reports structural validity, and a spec the engine calls malformed
	// is the only thing that clears it. An unresolved reference does not: the spec
	// is well formed, it just names something the domain does not produce.
	object := policyObject("orders", v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{{
			Name:     "narrow",
			Replaces: []string{"absent"},
			Rates:    []v1alpha1.Rate{minuteRate(10)},
		}},
	})

	outcome := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{object}}).Policies[key("orders")]

	require.Error(t, outcome.Err)
	assert.Equal(t, v1alpha1.ReasonInvalidSpec, outcome.Reason)
}

func TestCompile_oneBadPolicyLeavesTheRestOfTheDomainAlone(t *testing.T) {
	// A single bad policy must not be able to turn the limits of a whole gateway
	// off.
	broken := policyObject("broken", v1alpha1.LimitBlock{
		Name:  "a",
		Rules: []v1alpha1.Rule{simpleRule("r", v1alpha1.Predicate{Key: "plan", Operator: v1alpha1.OperatorExists})},
	})
	healthy := policyObject("healthy", v1alpha1.LimitBlock{
		Name: "b", Rules: []v1alpha1.Rule{simpleRule("r")},
	})

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{broken, healthy}})

	assert.False(t, result.Policies[key("broken")].Ready())
	assert.True(t, result.Policies[key("healthy")].Ready())
	require.Len(t, result.Snapshots[testDomain].Blocks, 1)
	assert.Equal(t, "healthy", result.Snapshots[testDomain].Blocks[0].Policy)
}

func TestCompile_publishesTheEffectiveKeysOfTheMapping(t *testing.T) {
	mapping := mappingObject(
		v1alpha1.ClaimMapping{Key: "roles", Claim: "realm_access.roles", Type: v1alpha1.ClaimTypeStringArray},
		v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"},
	)

	outcome := Compile(Input{Mappings: []v1alpha1.RateLimitMapping{mapping}}).Mappings[key(testDomain)]

	require.NoError(t, outcome.Err)
	assert.Subset(t, outcome.EffectiveKeys, []string{"client", "roles", "tenant"})
	assert.True(t, outcome.Ready())
}

func TestCompile_aMappingWhoseNameIsNotItsDomainIsIgnored(t *testing.T) {
	// The API server rejects it, so this only happens through a client that
	// bypassed validation. Taking it would make the singleton a lie.
	mapping := mappingObject(v1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"})
	mapping.Name = "something-else"

	result := Compile(Input{Mappings: []v1alpha1.RateLimitMapping{mapping}})

	assert.Empty(t, result.Snapshots)
	require.Error(t, result.Mappings[key("something-else")].Err)
}

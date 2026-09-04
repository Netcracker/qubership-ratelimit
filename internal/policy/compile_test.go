package policy

import (
	"fmt"
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
// the policy the engine is handed, and how what it says back becomes status.

const (
	testNamespace = "biz"
	testDomain    = "gateway.public"
)

// policyObject builds the domain's one policy. Its name is its domain, which is
// what makes a second policy for the domain unrepresentable.
func policyObject(blocks ...v1alpha1.LimitBlock) v1alpha1.RateLimitPolicy {
	return v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: testDomain, Generation: 1, UID: "uid-1",
		},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain: testDomain,
			Limits: blocks,
		},
	}
}

func minuteRate(requests int32) v1alpha1.Rate {
	return v1alpha1.Rate{Requests: requests, PeriodSeconds: 60}
}

func simpleRule(name string, matches ...v1alpha1.Predicate) v1alpha1.Rule {
	return v1alpha1.Rule{Name: name, Matches: matches, Rates: []v1alpha1.Rate{minuteRate(100)}}
}

func key() client.ObjectKey {
	return client.ObjectKey{Namespace: testNamespace, Name: testDomain}
}

// compileOf runs one compilation over the domain's policy.
func compileOf(objects ...v1alpha1.RateLimitPolicy) *Result {
	return Compile(Input{Namespace: testNamespace, Policies: objects})
}

func TestCompile_reportsWhatTheGenerationContributed(t *testing.T) {
	object := policyObject(
		v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("one"), simpleRule("two")}},
		v1alpha1.LimitBlock{Name: "b", Rules: []v1alpha1.Rule{simpleRule("one")}},
	)

	outcome := compileOf(object).Policies[key()]

	assert.Equal(t, 2, outcome.Blocks)
	assert.Equal(t, 3, outcome.Rules)
	assert.Equal(t, int64(1), outcome.Generation)
	assert.Equal(t, int64(1), outcome.ActiveGeneration)
	assert.True(t, outcome.Enforced())
	assert.True(t, outcome.Compiled())
	assert.Subset(t, outcome.EffectiveKeys, []string{"client", "method", "path"})
}

func TestCompile_aBlockingProblemKeepsTheWholeGenerationOut(t *testing.T) {
	// One dead rule cannot be applied on its own: a FirstMatch cascade missing a
	// rule silently hands its traffic to the neighbours. The engine drops such a
	// generation; what is asserted here is that the status says so.
	object := policyObject(v1alpha1.LimitBlock{
		Name: "quote-api",
		Rules: []v1alpha1.Rule{
			simpleRule("per-plan", v1alpha1.Predicate{Key: "plan", Operator: v1alpha1.OperatorExists}),
			simpleRule("total"),
		},
	})

	result := compileOf(object)

	outcome := result.Policies[key()]
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemUnresolvedKeyReference, outcome.Problems[0].Reason)
	assert.Equal(t, "quote-api", outcome.Problems[0].Block)
	assert.Equal(t, "per-plan", outcome.Problems[0].Rule)

	assert.False(t, outcome.Compiled())
	assert.Zero(t, outcome.ActiveGeneration)
	assert.Empty(t, result.Snapshots[testDomain].Blocks,
		"the healthy rule of an invalid generation must not be applied either")
}

// TestCompile_summarizesEveryBlockingReason pins what the Accepted message
// says: a count and the distinct reasons, with the addresses left to
// RuleProblems.
func TestCompile_summarizesEveryBlockingReason(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{
			simpleRule("one", v1alpha1.Predicate{Key: "plan", Operator: v1alpha1.OperatorExists}),
			{Name: "two", Rates: []v1alpha1.Rate{{Requests: 500_001, PeriodSeconds: 1}}},
		},
	})

	outcome := compileOf(object).Policies[key()]

	require.Error(t, outcome.Err)
	assert.Contains(t, outcome.Err.Error(), "2 blocking problems")
	assert.Contains(t, outcome.Err.Error(), v1alpha1.ProblemUnresolvedKeyReference)
	assert.Contains(t, outcome.Err.Error(), v1alpha1.ProblemInvalidWindow)
}

// TestCompile_theMappingsOfTheObjectResolveItsOwnRules pins the point of the
// singleton: extraction and rules are one generation, so a rule over a mapped
// key resolves without waiting for a second object.
func TestCompile_theMappingsOfTheObjectResolveItsOwnRules(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("by-role",
			v1alpha1.Predicate{Key: "roles", Operator: v1alpha1.OperatorContains, Value: "admin"})},
	})
	object.Spec.Mappings = []v1alpha1.ClaimMapping{
		{Key: "roles", Claim: "realm_access.roles", Type: v1alpha1.ClaimTypeStringArray},
	}

	outcome := compileOf(object).Policies[key()]

	require.NoError(t, outcome.Err)
	assert.True(t, outcome.Enforced())
	assert.Subset(t, outcome.EffectiveKeys, []string{"client", "roles"})
}

func TestCompile_anUndeclaredKeyBlocksTheGeneration(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{
		Name: "a",
		Rules: []v1alpha1.Rule{simpleRule("by-role",
			v1alpha1.Predicate{Key: "roles", Operator: v1alpha1.OperatorEquals, Value: "admin"})},
	})

	outcome := compileOf(object).Policies[key()]

	require.Error(t, outcome.Err)
	assert.Zero(t, outcome.ActiveGeneration)
}

// TestCompile_theLastGoodGenerationKeepsServing pins the reason last-good is
// persisted at all: a rejected edit costs the author an answer, never the
// gateway its limits.
func TestCompile_theLastGoodGenerationKeepsServing(t *testing.T) {
	good := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})

	broken := *good.DeepCopy()
	broken.Generation = 2
	broken.Spec.Limits[0].Rules[0].Matches = []v1alpha1.Predicate{
		{Key: "ghost", Operator: v1alpha1.OperatorExists}}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{broken},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "the latest generation is the one the problems are about")
	assert.Equal(t, int64(2), outcome.Generation)
	assert.Equal(t, int64(1), outcome.ActiveGeneration)
	assert.Equal(t, 1, outcome.Rules, "the last-good generation is the one being counted")
	require.Len(t, result.Snapshots[testDomain].Blocks, 1)
	assert.Equal(t, int64(1), result.State[testDomain].GoodGeneration,
		"the bundle must keep pointing at the generation that runs")
}

// TestCompile_aRecreatedObjectInheritsNothing pins the UID guard: a policy
// deleted and recreated under the same name starts at generation 1 too, and
// reviving its namesake's spec would enforce rules nobody wrote.
func TestCompile_aRecreatedObjectInheritsNothing(t *testing.T) {
	good := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})

	recreated := *good.DeepCopy()
	recreated.UID = "uid-2"
	recreated.Spec.Limits[0].Rules[0].Matches = []v1alpha1.Predicate{
		{Key: "ghost", Operator: v1alpha1.OperatorExists}}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{recreated},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.Zero(t, outcome.ActiveGeneration, "somebody else's last-good spec must not be resurrected")
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
	assert.Empty(t, result.State[testDomain].UID, "and it must not be written back either")
}

// TestCompile_aClaimedDomainIsNotAnUnknownOne pins the snapshot of a domain
// whose policy compiles to nothing: it exists, so its requests are allowed
// rather than logged as an unknown domain, which would point at the wrong fix.
func TestCompile_aClaimedDomainIsNotAnUnknownOne(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{
		Name:  "a",
		Rules: []v1alpha1.Rule{simpleRule("r", v1alpha1.Predicate{Key: "ghost", Operator: v1alpha1.OperatorExists})},
	})

	result := compileOf(object)

	require.Contains(t, result.Snapshots, testDomain)
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
}

// TestCompile_aNameThatIsNotItsDomainIsRefused pins the singleton: the API
// server rejects such an object, so it can only arrive from a client that
// bypassed validation, and taking it would let two names claim one domain.
func TestCompile_aNameThatIsNotItsDomainIsRefused(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("r")}})
	object.Name = "something-else"

	result := Compile(Input{Namespace: testNamespace, Policies: []v1alpha1.RateLimitPolicy{object}})

	assert.Empty(t, result.Snapshots)
	require.Error(t, result.Policies[client.ObjectKey{Namespace: testNamespace, Name: "something-else"}].Err)
}

// TestCompile_oneBadDomainLeavesTheOthersAlone pins the blast radius: domains
// are independent objects, and a rejected edit to one cannot reach another.
func TestCompile_oneBadDomainLeavesTheOthersAlone(t *testing.T) {
	broken := policyObject(v1alpha1.LimitBlock{
		Name:  "a",
		Rules: []v1alpha1.Rule{simpleRule("r", v1alpha1.Predicate{Key: "ghost", Operator: v1alpha1.OperatorExists})},
	})
	healthy := policyObject(v1alpha1.LimitBlock{Name: "b", Rules: []v1alpha1.Rule{simpleRule("r")}})
	healthy.Name = "gateway.private"
	healthy.Spec.Domain = "gateway.private"
	healthy.UID = "uid-2"

	result := compileOf(broken, healthy)

	assert.False(t, result.Policies[key()].Enforced())
	assert.True(t, result.Policies[client.ObjectKey{Namespace: testNamespace, Name: "gateway.private"}].Enforced())
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
	assert.Len(t, result.Snapshots["gateway.private"].Blocks, 1)
}

// TestCompile_theBucketBudgetBlocksTheGeneration pins the budget as blocking
// rather than advisory: a generation the runtime backstop would refuse on its
// widest paths never becomes the active one.
func TestCompile_theBucketBudgetBlocksTheGeneration(t *testing.T) {
	rules := make([]v1alpha1.Rule, 0, 33)
	for i := range 33 {
		rules = append(rules, v1alpha1.Rule{
			Name: fmt.Sprintf("r%d", i),
			Rates: []v1alpha1.Rate{
				{Requests: 100, PeriodSeconds: 60},
				{Requests: 100, PeriodSeconds: 3600},
				{Requests: 100, PeriodSeconds: 30},
				{Requests: 100, PeriodSeconds: 10},
			},
		})
	}
	object := policyObject(v1alpha1.LimitBlock{Name: "b", Rules: rules})

	result := compileOf(object)

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled())
	assert.Zero(t, outcome.ActiveGeneration, "a budget-blocked generation enforces nothing")
	assert.Contains(t, outcome.Err.Error(), v1alpha1.ProblemDomainBudgetExceeded)
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
}

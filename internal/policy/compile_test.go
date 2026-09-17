package policy

import (
	"fmt"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	outcome := result.Policies[client.ObjectKey{Namespace: testNamespace, Name: "something-else"}]
	require.Error(t, outcome.Err)

	// The condition message only summarizes, so the cause has to reach
	// ruleProblems as well. Without it the status would read
	// "CompilationFailed" with an empty problem list and PROBLEMS 0, and the
	// mismatch would be nowhere to be found.
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemInvalidSpec, outcome.Problems[0].Reason)
	assert.Contains(t, outcome.Problems[0].Message, "something-else")
	assert.Contains(t, outcome.Problems[0].Message, testDomain)
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

// The schema skew tests. A cluster can run a CRD newer than this build: the
// API server then stores fields this build's schema does not define, and a
// typed decode drops them without a word. What must not happen is enforcing
// the remainder as if it were the spec.

// unstructuredPolicy renders an object the way the API server stores it, with
// extra is merged into its spec - the fields a newer schema would define.
func unstructuredPolicy(t *testing.T, object v1alpha1.RateLimitPolicy, extra map[string]any) *unstructured.Unstructured {
	t.Helper()
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&object)
	require.NoError(t, err)
	stored := &unstructured.Unstructured{Object: content}
	stored.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("RateLimitPolicy"))

	spec, found, err := unstructured.NestedMap(stored.Object, "spec")
	require.NoError(t, err)
	require.True(t, found)
	maps.Copy(spec, extra)
	require.NoError(t, unstructured.SetNestedMap(stored.Object, spec, "spec"))
	return stored
}

func TestDecode_namesTheFieldsThisSchemaDoesNotDefine(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}}),
		map[string]any{"burstProfile": "steady"})

	decoded, skew, err := Decode(stored)
	require.NoError(t, err, "an object with an unknown field is still readable")

	require.Len(t, skew, 1)
	assert.Equal(t, v1alpha1.ProblemInvalidSpec, skew[0].Reason)
	assert.Contains(t, skew[0].Message, "burstProfile",
		"the message has to name the field, which is the only clue the author gets")
	assert.Equal(t, testDomain, decoded.Spec.Domain,
		"the part that decoded is still there, because the status is written on it")
}

// TestDecode_ignoresFieldsOutsideTheSpec pins where the strict pass stops. The
// status belongs to this component and moves with every release: during a
// rolling upgrade the new leader writes a field the old replicas have no
// schema for, and treating that as skew would stop the whole fleet taking new
// generations until the rollout ended. Metadata belongs to the API server and
// grows on its own schedule.
func TestDecode_ignoresFieldsOutsideTheSpec(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}}), nil)

	require.NoError(t, unstructured.SetNestedField(stored.Object,
		"tomorrow", "status", "futureField"))
	require.NoError(t, unstructured.SetNestedField(stored.Object,
		"tomorrow", "metadata", "futureField"))

	decoded, skew, err := Decode(stored)
	require.NoError(t, err)
	assert.Empty(t, skew, "only the spec is this build's to be strict about")
	assert.Equal(t, testDomain, decoded.Spec.Domain)
}

// TestDecode_reportsTheSpecFieldWithItsPath keeps the message useful: the
// author gets the path, not just the leaf.
func TestDecode_reportsTheSpecFieldWithItsPath(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}}),
		map[string]any{"burstProfile": "steady"})
	require.NoError(t, unstructured.SetNestedField(stored.Object,
		"tomorrow", "status", "futureField"))

	_, skew, err := Decode(stored)
	require.NoError(t, err)

	require.Len(t, skew, 1, "the status field must not be counted alongside the spec one")
	assert.Contains(t, skew[0].Message, `spec.burstProfile`)
}

func TestDecode_isSilentOnAnObjectThisSchemaFullyDefines(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}}), nil)

	_, skew, err := Decode(stored)
	require.NoError(t, err)
	assert.Empty(t, skew)
}

// TestCompile_anUnknownFieldKeepsTheLastGoodGenerationServing is the whole
// point of the strict decode: the decoded spec compiles perfectly well, and
// enforcing it anyway would enforce something nobody wrote.
func TestCompile_anUnknownFieldKeepsTheLastGoodGenerationServing(t *testing.T) {
	good := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})

	newer := *good.DeepCopy()
	newer.Generation = 2

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{newer},
		Skew: map[client.ObjectKey][]v1alpha1.RuleProblem{
			key(): {{Reason: v1alpha1.ProblemInvalidSpec, Message: `unknown field "spec.burstProfile"`}},
		},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "a spec this build cannot read whole is not a spec it may enforce")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "the last-good generation keeps serving")
	require.Len(t, outcome.Problems, 1)
	assert.Equal(t, v1alpha1.ProblemInvalidSpec, outcome.Problems[0].Reason)
	require.Len(t, result.Snapshots[testDomain].Blocks, 1,
		"the snapshot is the last-good one, not the partially decoded latest")
}

// TestCompile_anUnknownFieldWithNoLastGoodEnforcesNothing is the other half:
// with nothing to fall back to the domain is claimed and empty. The decoded
// spec would have compiled to one working block, which is exactly the outcome
// that must not happen.
func TestCompile_anUnknownFieldWithNoLastGoodEnforcesNothing(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{object},
		Skew: map[client.ObjectKey][]v1alpha1.RuleProblem{
			key(): {{Reason: v1alpha1.ProblemInvalidSpec, Message: `unknown field "spec.burstProfile"`}},
		},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled())
	assert.Zero(t, outcome.ActiveGeneration)
	assert.Zero(t, outcome.Rules)
	require.NotNil(t, result.Snapshots[testDomain],
		"the domain is claimed, which is not the same as unknown")
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
}

// TestCompile_anUnknownFieldDoesNotFallBackToItsOwnGeneration covers the window
// of a CRD change. A replica whose watch still served the previous schema read
// this generation with the new field pruned, compiled the remainder, and
// persisted it as last-good; the re-list then brought the field and the skew.
// That bundle is the partial enforcement the refusal exists to prevent, so the
// domain enforces nothing rather than falling back to it.
func TestCompile_anUnknownFieldDoesNotFallBackToItsOwnGeneration(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})
	object.Generation = 2

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{object},
		Skew: map[client.ObjectKey][]v1alpha1.RuleProblem{
			key(): {{Reason: v1alpha1.ProblemInvalidSpec, Message: `unknown field "spec.burstProfile"`}},
		},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 2, GoodSpec: object.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled())
	assert.Zero(t, outcome.ActiveGeneration, "a bundle of the skewed generation itself came from a pruned read")
	assert.Zero(t, outcome.Rules)
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
	assert.Empty(t, result.State[testDomain].UID, "the pruned bundle is not carried forward")
}

// TestCompile_anUnknownEnumValueIsRefusedByTheCompiler is the skew a strict
// decode cannot catch: the field is one this schema defines, and only its
// value is from a newer vocabulary. The compiler is what refuses it, and the
// reason is the same one.
func TestCompile_anUnknownEnumValueIsRefusedByTheCompiler(t *testing.T) {
	good := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})

	newer := *good.DeepCopy()
	newer.Generation = 2
	newer.Spec.Limits[0].Target = &v1alpha1.Target{
		Routes: []v1alpha1.Route{{
			Path: v1alpha1.PathMatch{Type: "GlobMatch", Value: "/orders"},
		}},
	}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{newer},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled())
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "the last-good generation keeps serving")
	require.NotEmpty(t, outcome.Problems)
	assert.Equal(t, v1alpha1.ProblemInvalidSpec, outcome.Problems[0].Reason)
	assert.Contains(t, outcome.Problems[0].Message, "GlobMatch")
}

// The size fit. A namespace's configuration has to fit one ConfigMap, and the
// generations that pushed it over are the ones set back.

// wideBlocks is a payload large enough to measure against a small limit and
// still compile: many blocks on disjoint path prefixes, one rule each, with
// names that compress poorly. Disjoint targets keep the worst-case decision at
// one block, so the size grows and the bucket budget does not.
func wideBlocks(name string, blocks int) []v1alpha1.LimitBlock {
	out := make([]v1alpha1.LimitBlock, 0, blocks)
	for i := range blocks {
		out = append(out, v1alpha1.LimitBlock{
			Name: fmt.Sprintf("%s-%d-%x", name, i, i*2654435761),
			Target: &v1alpha1.Target{Routes: []v1alpha1.Route{{
				Path: v1alpha1.PathMatch{Type: v1alpha1.PathMatchPrefix, Value: fmt.Sprintf("/%s/%d/", name, i)},
			}}},
			Rules: []v1alpha1.Rule{{
				Name:  fmt.Sprintf("r-%x", i*40503),
				Rates: []v1alpha1.Rate{minuteRate(int32(100 + i))},
			}},
		})
	}
	return out
}

func TestFit_leavesANamespaceThatFitsAlone(t *testing.T) {
	object := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})
	in := Input{Namespace: testNamespace, Policies: []v1alpha1.RateLimitPolicy{object}}
	result := Compile(in)

	Fit(in, result, ConfigMapLimit)

	outcome := result.Policies[key()]
	assert.False(t, outcome.TooLarge)
	assert.Equal(t, int64(1), outcome.ActiveGeneration)
}

func TestFit_setsAGenerationThatDoesNotFitBackToLastGood(t *testing.T) {
	good := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})
	grown := *good.DeepCopy()
	grown.Generation = 2
	grown.Spec.Limits = wideBlocks("wide", 100)

	in := Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{grown},
		State:     map[string]Bundle{testDomain: {UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec}},
	}
	result := Compile(in)
	require.Equal(t, int64(2), result.Policies[key()].ActiveGeneration, "it compiles; the fit is what keeps it out")

	// A limit the small generation fits and the wide one does not: the
	// small one is a few hundred bytes compressed, the wide one over two
	// thousand.
	Fit(in, result, 1024)

	outcome := result.Policies[key()]
	assert.True(t, outcome.Compiled(), "the spec is right; Compiled stays true")
	assert.True(t, outcome.TooLarge)
	assert.Contains(t, outcome.TooLargeReason, "over the limit of 1024")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "the last-good generation keeps serving")
	assert.Equal(t, int64(2), outcome.Generation)
	assert.Equal(t, int64(1), result.State[testDomain].GoodGeneration, "the bundle to persist is the one that fits")
	require.Len(t, result.Snapshots[testDomain].Blocks, 1, "the snapshot is the last-good one")
}

func TestFit_withoutLastGoodTheDomainIsClaimedAndEmpty(t *testing.T) {
	object := policyObject(wideBlocks("wide", 100)...)
	in := Input{Namespace: testNamespace, Policies: []v1alpha1.RateLimitPolicy{object}}
	result := Compile(in)

	Fit(in, result, 1024)

	outcome := result.Policies[key()]
	assert.True(t, outcome.TooLarge)
	assert.Zero(t, outcome.ActiveGeneration)
	assert.Equal(t, Bundle{}, result.State[testDomain], "nothing to persist for a domain nothing fits")
	require.NotNil(t, result.Snapshots[testDomain])
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
}

func TestFit_keepsOutTheFewestGenerationsLargestFirst(t *testing.T) {
	// Two domains moved; one is wide, one is small. The limit admits the
	// small one beside the wide one's last-good, so only the wide one is kept
	// out, and the small one lands.
	wide := policyObject(wideBlocks("wide", 100)...)
	wide.Name, wide.Spec.Domain, wide.UID = "gateway.wide", "gateway.wide", "uid-wide"
	small := policyObject(v1alpha1.LimitBlock{Name: "a", Rules: []v1alpha1.Rule{simpleRule("total")}})
	small.Name, small.Spec.Domain, small.UID = "gateway.small", "gateway.small", "uid-small"

	in := Input{Namespace: testNamespace, Policies: []v1alpha1.RateLimitPolicy{wide, small}}
	result := Compile(in)

	Fit(in, result, 1024)

	assert.True(t, result.Policies[client.ObjectKey{Namespace: testNamespace, Name: "gateway.wide"}].TooLarge)
	assert.False(t, result.Policies[client.ObjectKey{Namespace: testNamespace, Name: "gateway.small"}].TooLarge,
		"the small domain fits once the wide one is out; keeping it out too would be one generation too many")
	assert.Equal(t, int64(1), result.Policies[client.ObjectKey{Namespace: testNamespace, Name: "gateway.small"}].ActiveGeneration)
}

func TestFit_isDeterministicAcrossRuns(t *testing.T) {
	// The writer and the status reconciler run the fit separately and must
	// agree; two runs over the same input have to keep the same generations.
	build := func() (Input, *Result) {
		names := []string{"gateway.a", "gateway.b", "gateway.c"}
		policies := make([]v1alpha1.RateLimitPolicy, 0, len(names))
		for _, name := range names {
			p := policyObject(wideBlocks(name, 40)...)
			p.Name, p.Spec.Domain, p.UID = name, name, types.UID("uid-"+name)
			policies = append(policies, p)
		}
		in := Input{Namespace: testNamespace, Policies: policies}
		return in, Compile(in)
	}
	verdict := func() map[string]bool {
		in, result := build()
		Fit(in, result, 1500)
		out := map[string]bool{}
		for key, outcome := range result.Policies {
			out[key.Name] = outcome.TooLarge
		}
		return out
	}
	first := verdict()
	for range 10 {
		assert.Equal(t, first, verdict())
	}
	assert.Contains(t, first, "gateway.a")
}

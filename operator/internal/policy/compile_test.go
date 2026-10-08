package policy

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
)

// What the engine decides — which rules compile, which references resolve, what a
// counter key looks like — is covered by the engine module's own suite and is not
// restated here. These tests are about the part that is ours: which generation of
// the policy the engine is handed, and how what it says back becomes status.

const (
	testNamespace = "biz"
	testDomain    = "gateway.public"
)

// policyObject builds the domain's one policy at generation 1. Its name is its
// domain, which is what makes a second policy for the domain unrepresentable.
func policyObject(blocks ...v1.LimitBlock) v1.RateLimitPolicy {
	return policyFor(testDomain, "uid-1", blocks...)
}

// policyFor builds the one policy of the given domain at generation 1.
func policyFor(domain string, uid types.UID, blocks ...v1.LimitBlock) v1.RateLimitPolicy {
	return v1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: domain, Generation: 1, UID: uid,
		},
		Spec: v1.RateLimitPolicySpec{
			Domain: domain,
			Limits: blocks,
		},
	}
}

func minuteRate(requests int32) v1.Rate {
	return v1.Rate{Requests: requests, PeriodSeconds: 60}
}

func simpleRule(name string, matches ...v1.Predicate) v1.Rule {
	return v1.Rule{Name: name, Matches: matches, Rates: []v1.Rate{minuteRate(100)}}
}

func keyOf(name string) client.ObjectKey {
	return client.ObjectKey{Namespace: testNamespace, Name: name}
}

func key() client.ObjectKey {
	return keyOf(testDomain)
}

// compileOf runs one compilation over the domain's policy.
func compileOf(objects ...v1.RateLimitPolicy) *Result {
	return Compile(Input{Namespace: testNamespace, Policies: objects})
}

// blocksOf returns the blocks of the domain's snapshot, and fails the test when
// the compilation wrote no snapshot for the domain.
func blocksOf(t *testing.T, result *Result, domain string) []enginecompile.Block {
	t.Helper()
	snapshot := result.Snapshots[domain]
	require.NotNil(t, snapshot, "Result.Snapshots[%q]", domain)
	return snapshot.Blocks
}

func TestCompile_reportsWhatTheGenerationContributed(t *testing.T) {
	object := policyObject(
		v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("one"), simpleRule("two")}},
		v1.LimitBlock{Name: "b", Rules: []v1.Rule{simpleRule("one")}},
	)

	outcome := compileOf(object).Policies[key()]

	assert.Equal(t, 2, outcome.Blocks, "Outcome.Blocks")
	assert.Equal(t, 3, outcome.Rules, "Outcome.Rules")
	assert.Equal(t, int64(1), outcome.Generation, "Outcome.Generation")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.True(t, outcome.Enforced(), "Enforced()")
	assert.True(t, outcome.Compiled(), "Compiled() with Err %v", outcome.Err)
	assert.Subset(t, outcome.EffectiveKeys, []string{"method", "path", "sub"}, "Outcome.EffectiveKeys")
}

func TestCompile_aBlockingProblemKeepsTheWholeGenerationOut(t *testing.T) {
	// One dead rule cannot be applied on its own: a FirstMatch cascade missing a
	// rule silently hands its traffic to the neighbors. The engine drops such a
	// generation; what is asserted here is that the status says so, and that
	// the healthy rule "total" is not applied either.
	object := policyObject(v1.LimitBlock{
		Name: "invoices-api",
		Rules: []v1.Rule{
			simpleRule("per-plan", v1.Predicate{Key: "plan", Operator: v1.OperatorExists}),
			simpleRule("total"),
		},
	})

	result := compileOf(object)

	outcome := result.Policies[key()]
	require.Len(t, outcome.Problems, 1, "Outcome.Problems")
	assert.Equal(t, v1.ProblemUnresolvedKeyReference, outcome.Problems[0].Reason, "Problems[0].Reason")
	assert.Equal(t, "invoices-api", outcome.Problems[0].Block, "Problems[0].Block")
	assert.Equal(t, "per-plan", outcome.Problems[0].Rule, "Problems[0].Rule")

	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
}

// TestCompile_summarizesEveryBlockingReason pins what the Accepted message
// says: a count and the distinct reasons, with the addresses left to
// RuleProblems.
func TestCompile_summarizesEveryBlockingReason(t *testing.T) {
	object := policyObject(v1.LimitBlock{
		Name: "a",
		Rules: []v1.Rule{
			simpleRule("one", v1.Predicate{Key: "plan", Operator: v1.OperatorExists}),
			{Name: "two", Rates: []v1.Rate{{Requests: 500_001, PeriodSeconds: 1}}},
		},
	})

	outcome := compileOf(object).Policies[key()]

	assert.ErrorContains(t, outcome.Err, "2 blocking problems")
	assert.ErrorContains(t, outcome.Err, v1.ProblemUnresolvedKeyReference)
	assert.ErrorContains(t, outcome.Err, v1.ProblemInvalidWindow)
}

// TestCompile_theMappingsOfTheObjectResolveItsOwnRules pins the point of the
// singleton: extraction and rules are one generation, so a rule over a mapped
// key resolves without waiting for a second object.
func TestCompile_theMappingsOfTheObjectResolveItsOwnRules(t *testing.T) {
	object := policyObject(v1.LimitBlock{
		Name: "a",
		Rules: []v1.Rule{simpleRule("by-role",
			v1.Predicate{Key: "roles", Operator: v1.OperatorContains, Value: "admin"})},
	})
	object.Spec.Mappings = []v1.ClaimMapping{
		{Key: "roles", Claim: "realm_access.roles", Type: v1.ClaimTypeStringArray},
	}

	outcome := compileOf(object).Policies[key()]

	assert.NoError(t, outcome.Err, "Outcome.Err")
	assert.True(t, outcome.Enforced(), "Enforced()")
	assert.Subset(t, outcome.EffectiveKeys, []string{"roles", "sub"}, "Outcome.EffectiveKeys")
}

func TestCompile_anUndeclaredKeyBlocksTheGeneration(t *testing.T) {
	object := policyObject(v1.LimitBlock{
		Name: "a",
		Rules: []v1.Rule{simpleRule("by-role",
			v1.Predicate{Key: "roles", Operator: v1.OperatorEquals, Value: "admin"})},
	})

	outcome := compileOf(object).Policies[key()]

	assert.Error(t, outcome.Err, "Outcome.Err")
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	require.Len(t, outcome.Problems, 1, "Outcome.Problems")
	assert.Equal(t, v1.ProblemUnresolvedKeyReference, outcome.Problems[0].Reason, "Problems[0].Reason")
}

// TestCompile_theLastGoodGenerationKeepsServing pins the reason last-good is
// persisted at all: a rejected edit costs the author an answer, never the
// gateway its limits. The problems describe the latest generation; the
// counts, the snapshot, and the bundle to persist are the last-good one's.
func TestCompile_theLastGoodGenerationKeepsServing(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})

	broken := *good.DeepCopy()
	broken.Generation = 2
	broken.Spec.Limits[0].Rules[0].Matches = []v1.Predicate{
		{Key: "ghost", Operator: v1.OperatorExists}}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{broken},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Equal(t, int64(2), outcome.Generation, "Outcome.Generation")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Equal(t, 1, outcome.Rules, "Outcome.Rules")
	assert.Len(t, blocksOf(t, result, testDomain), 1, "Snapshots[%q].Blocks", testDomain)
	assert.Equal(t, Bundle{UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec}, result.State[testDomain],
		"Result.State[%q]", testDomain)
}

// A saved last-good spec this build no longer compiles leaves the domain
// unprotected, and the outcome says so with the reason, so the status tells
// it apart from a policy that never compiled.
func TestCompile_aLastGoodThisBuildCannotCompileSaysSo(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})
	saved := *good.Spec.DeepCopy()
	saved.Limits[0].Rules[0].Matches = []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}}

	broken := *good.DeepCopy()
	broken.Generation = 2
	broken.Spec.Limits[0].Rules[0].Matches = []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{broken},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: saved,
		}},
	})

	outcome := result.Policies[key()]
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Contains(t, outcome.LastGoodLost, "last-good generation 1 does not compile with this operator build",
		"Outcome.LastGoodLost")
	assert.Contains(t, outcome.LastGoodLost, v1.ProblemUnresolvedKeyReference, "Outcome.LastGoodLost")
}

// TestCompile_aRecreatedObjectInheritsNothing pins the UID guard: a policy
// deleted and recreated under the same name starts at generation 1 too, and
// reviving its namesake's spec would enforce rules nobody wrote. A last-good
// that was never this object's is not one it lost, and it is not written back.
func TestCompile_aRecreatedObjectInheritsNothing(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})

	recreated := *good.DeepCopy()
	recreated.UID = "uid-2"
	recreated.Spec.Limits[0].Rules[0].Matches = []v1.Predicate{
		{Key: "ghost", Operator: v1.OperatorExists}}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{recreated},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Empty(t, outcome.LastGoodLost, "Outcome.LastGoodLost")
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
	assert.Equal(t, Bundle{}, result.State[testDomain], "Result.State[%q]", testDomain)
}

// TestCompile_aClaimedDomainIsNotAnUnknownOne pins the snapshot of a domain
// whose policy compiles to nothing: it exists, so its requests are allowed
// rather than logged as an unknown domain, which would point at the wrong fix.
func TestCompile_aClaimedDomainIsNotAnUnknownOne(t *testing.T) {
	object := policyObject(v1.LimitBlock{
		Name:  "a",
		Rules: []v1.Rule{simpleRule("r", v1.Predicate{Key: "ghost", Operator: v1.OperatorExists})},
	})

	result := compileOf(object)

	require.Contains(t, result.Snapshots, testDomain, "Result.Snapshots")
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
}

// TestCompile_aNameThatIsNotItsDomainIsRefused pins the singleton: the API
// server rejects such an object, so it can only arrive from a client that
// bypassed validation, and taking it would let two names claim one domain.
func TestCompile_aNameThatIsNotItsDomainIsRefused(t *testing.T) {
	object := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("r")}})
	object.Name = "something-else"

	result := Compile(Input{Namespace: testNamespace, Policies: []v1.RateLimitPolicy{object}})

	assert.Empty(t, result.Snapshots, "Result.Snapshots")
	outcome := result.Policies[keyOf("something-else")]
	assert.Error(t, outcome.Err, "Outcome.Err")

	// The condition message only summarizes, so the cause has to reach
	// ruleProblems as well. Without it the status would read
	// "CompilationFailed" with an empty problem list and PROBLEMS 0, and the
	// mismatch would be nowhere to be found.
	require.Len(t, outcome.Problems, 1, "Outcome.Problems")
	assert.Equal(t, v1.ProblemInvalidSpec, outcome.Problems[0].Reason, "Problems[0].Reason")
	assert.Contains(t, outcome.Problems[0].Message, "something-else", "Problems[0].Message")
	assert.Contains(t, outcome.Problems[0].Message, testDomain, "Problems[0].Message")
}

// TestCompile_oneBadDomainLeavesTheOthersAlone pins the blast radius: domains
// are independent objects, and a rejected edit to one cannot reach another.
func TestCompile_oneBadDomainLeavesTheOthersAlone(t *testing.T) {
	broken := policyObject(v1.LimitBlock{
		Name:  "a",
		Rules: []v1.Rule{simpleRule("r", v1.Predicate{Key: "ghost", Operator: v1.OperatorExists})},
	})
	healthy := policyFor("gateway.private", "uid-2", v1.LimitBlock{Name: "b", Rules: []v1.Rule{simpleRule("r")}})

	result := compileOf(broken, healthy)

	assert.False(t, result.Policies[key()].Enforced(), "Enforced() of %s", testDomain)
	assert.True(t, result.Policies[keyOf("gateway.private")].Enforced(), "Enforced() of gateway.private")
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
	assert.Len(t, blocksOf(t, result, "gateway.private"), 1, "Snapshots[gateway.private].Blocks")
}

// TestCompile_theBucketBudgetBlocksTheGeneration pins the budget as blocking
// rather than advisory: a generation the runtime backstop would refuse on its
// widest paths never becomes the active one.
func TestCompile_theBucketBudgetBlocksTheGeneration(t *testing.T) {
	rules := make([]v1.Rule, 0, 33)
	for i := range 33 {
		rules = append(rules, v1.Rule{
			Name: fmt.Sprintf("r%d", i),
			Rates: []v1.Rate{
				{Requests: 100, PeriodSeconds: 60},
				{Requests: 100, PeriodSeconds: 3600},
				{Requests: 100, PeriodSeconds: 30},
				{Requests: 100, PeriodSeconds: 10},
			},
		})
	}
	object := policyObject(v1.LimitBlock{Name: "b", Rules: rules})

	result := compileOf(object)

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.ErrorContains(t, outcome.Err, v1.ProblemDomainBudgetExceeded)
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
}

// The schema skew tests. A cluster can run a CRD newer than this build: the
// API server then stores fields this build's schema does not define, and a
// typed decode drops them without a word. What must not happen is enforcing
// the remainder as if it were the spec.

// unstructuredPolicy renders an object the way the API server stores it, with
// extra is merged into its spec - the fields a newer schema would define.
func unstructuredPolicy(t *testing.T, object v1.RateLimitPolicy, extra map[string]any) *unstructured.Unstructured {
	t.Helper()
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&object)
	require.NoError(t, err)
	stored := &unstructured.Unstructured{Object: content}
	stored.SetGroupVersionKind(v1.GroupVersion.WithKind("RateLimitPolicy"))

	spec, found, err := unstructured.NestedMap(stored.Object, "spec")
	require.NoError(t, err)
	require.True(t, found)
	maps.Copy(spec, extra)
	require.NoError(t, unstructured.SetNestedMap(stored.Object, spec, "spec"))
	return stored
}

// The problem message is the only clue the author gets, so it names the field.
// The part that decoded is still there, because the status is written on it.
func TestDecode_namesTheFieldsThisSchemaDoesNotDefine(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}}),
		map[string]any{"burstProfile": "steady"})

	decoded, skew, err := Decode(stored)

	require.NoError(t, err, "Decode(spec.burstProfile=steady)")
	require.Len(t, skew, 1, "Decode(spec.burstProfile=steady) skew")
	assert.Equal(t, v1.ProblemInvalidSpec, skew[0].Reason, "skew[0].Reason")
	assert.Contains(t, skew[0].Message, "burstProfile", "skew[0].Message")
	assert.Equal(t, testDomain, decoded.Spec.Domain, "decoded Spec.Domain")
}

// TestDecode_reportsOnlyTheUnknownFieldsOfTheSpec pins where the strict pass
// stops, and that the author gets the path, not just the leaf. The status
// belongs to this component and moves with every release: during a rolling
// upgrade the new leader writes a field the old replicas have no schema for,
// and treating that as skew would stop the whole fleet taking new generations
// until the rollout ended. Metadata belongs to the API server and grows on its
// own schedule.
func TestDecode_reportsOnlyTheUnknownFieldsOfTheSpec(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}}),
		map[string]any{"burstProfile": "steady"})
	require.NoError(t, unstructured.SetNestedField(stored.Object,
		"tomorrow", "status", "futureField"))
	require.NoError(t, unstructured.SetNestedField(stored.Object,
		"tomorrow", "metadata", "futureField"))

	decoded, skew, err := Decode(stored)

	require.NoError(t, err, "Decode(spec.burstProfile, status.futureField, metadata.futureField)")
	require.Len(t, skew, 1, "skew of spec.burstProfile, status.futureField, metadata.futureField")
	assert.Contains(t, skew[0].Message, "spec.burstProfile", "skew[0].Message")
	assert.Equal(t, testDomain, decoded.Spec.Domain, "decoded Spec.Domain")
}

func TestDecode_isSilentOnAnObjectThisSchemaFullyDefines(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(
		v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}}), nil)

	_, skew, err := Decode(stored)

	assert.NoError(t, err)
	assert.Empty(t, skew, "Decode skew")
}

// TestDecode_keepsAListWrittenEmptyApartFromOneLeftOut pins the mechanism the
// override rule of presets rests on: the stored object reaches the resolver
// with counters: [] as an empty list and an absent counters as nil, so the
// two can mean a value and an omission.
func TestDecode_keepsAListWrittenEmptyApartFromOneLeftOut(t *testing.T) {
	stored := unstructuredPolicy(t, policyObject(), map[string]any{
		"limits": []any{map[string]any{
			"name": "api",
			"rules": []any{
				map[string]any{"name": "written", "counters": []any{}},
				map[string]any{"name": "left-out"},
			},
		}},
	})

	decoded, skew, err := Decode(stored)

	require.NoError(t, err, "Decode(counters: [] in rule written, no counters in rule left-out)")
	assert.Empty(t, skew, "Decode skew")
	require.Len(t, decoded.Spec.Limits, 1, "decoded Spec.Limits")
	rules := decoded.Spec.Limits[0].Rules
	require.Len(t, rules, 2, "decoded rules of block api")
	assert.Equal(t, []string{}, rules[0].Counters, "decoded Counters of rule written, stored as []")
	assert.Nil(t, rules[1].Counters, "decoded Counters of rule left-out, stored without the field")
}

// TestCompile_anUnknownFieldKeepsTheLastGoodGenerationServing is the whole
// point of the strict decode: the decoded spec compiles perfectly well, and
// enforcing it anyway would enforce something nobody wrote. A spec this build
// cannot read whole is not a spec it may enforce, so the last-good one serves.
func TestCompile_anUnknownFieldKeepsTheLastGoodGenerationServing(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})

	newer := *good.DeepCopy()
	newer.Generation = 2

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{newer},
		Skew: map[client.ObjectKey][]v1.RuleProblem{
			key(): {{Reason: v1.ProblemInvalidSpec, Message: `unknown field "spec.burstProfile"`}},
		},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	require.Len(t, outcome.Problems, 1, "Outcome.Problems")
	assert.Equal(t, v1.ProblemInvalidSpec, outcome.Problems[0].Reason, "Problems[0].Reason")
	assert.Len(t, blocksOf(t, result, testDomain), 1, "Snapshots[%q].Blocks", testDomain)
}

// TestCompile_anUnknownFieldWithNoLastGoodEnforcesNothing is the other half:
// with nothing to fall back to the domain is claimed and empty. The decoded
// spec would have compiled to one working block, which is exactly the outcome
// that must not happen.
func TestCompile_anUnknownFieldWithNoLastGoodEnforcesNothing(t *testing.T) {
	object := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{object},
		Skew: map[client.ObjectKey][]v1.RuleProblem{
			key(): {{Reason: v1.ProblemInvalidSpec, Message: `unknown field "spec.burstProfile"`}},
		},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Zero(t, outcome.Rules, "Outcome.Rules")
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
}

// TestCompile_anUnknownFieldDoesNotFallBackToItsOwnGeneration covers the window
// of a CRD change. A replica whose watch still served the previous schema read
// this generation with the new field pruned, compiled the remainder, and
// persisted it as last-good; the re-list then brought the field and the skew.
// That bundle is the partial enforcement the refusal exists to prevent, so the
// domain enforces nothing rather than falling back to it, the status says why,
// and the bundle is not carried forward.
func TestCompile_anUnknownFieldDoesNotFallBackToItsOwnGeneration(t *testing.T) {
	object := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})
	object.Generation = 2

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{object},
		Skew: map[client.ObjectKey][]v1.RuleProblem{
			key(): {{Reason: v1.ProblemInvalidSpec, Message: `unknown field "spec.burstProfile"`}},
		},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 2, GoodSpec: object.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Equal(t, "last-good generation 2 was saved from a read that did not carry every field",
		outcome.LastGoodLost, "Outcome.LastGoodLost")
	assert.Zero(t, outcome.Rules, "Outcome.Rules")
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
	assert.Equal(t, Bundle{}, result.State[testDomain], "Result.State[%q]", testDomain)
}

// TestCompile_anUnknownEnumValueIsRefusedByTheCompiler is the skew a strict
// decode cannot catch: the field is one this schema defines, and only its
// value is from a newer vocabulary. The compiler is what refuses it, and the
// reason is the same one.
func TestCompile_anUnknownEnumValueIsRefusedByTheCompiler(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})

	newer := *good.DeepCopy()
	newer.Generation = 2
	newer.Spec.Limits[0].Target = &v1.Target{
		Routes: []v1.Route{{
			Path: v1.PathMatch{Type: "GlobMatch", Value: "/orders"},
		}},
	}

	result := Compile(Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{newer},
		State: map[string]Bundle{testDomain: {
			UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec,
		}},
	})

	outcome := result.Policies[key()]
	assert.False(t, outcome.Compiled(), "Compiled()")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	require.NotEmpty(t, outcome.Problems, "Outcome.Problems")
	assert.Equal(t, v1.ProblemInvalidSpec, outcome.Problems[0].Reason, "Problems[0].Reason")
	assert.Contains(t, outcome.Problems[0].Message, "GlobMatch", "Problems[0].Message")
}

// The size fit. A namespace's configuration has to fit one ConfigMap, and the
// generations that pushed it over are the ones set back.

// wideBlocks is a payload large enough to measure against a small limit and
// still compile: many blocks on disjoint path prefixes, one rule each, with
// names that compress poorly. Disjoint targets keep the worst-case decision at
// one block, so the size grows and the bucket budget does not.
func wideBlocks(name string, blocks int) []v1.LimitBlock {
	out := make([]v1.LimitBlock, 0, blocks)
	for i := range blocks {
		out = append(out, v1.LimitBlock{
			Name: fmt.Sprintf("%s-%d-%x", name, i, i*2654435761),
			Target: &v1.Target{Routes: []v1.Route{{
				Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: fmt.Sprintf("/%s/%d/", name, i)},
			}}},
			Rules: []v1.Rule{{
				Name:  fmt.Sprintf("r-%x", i*40503),
				Rates: []v1.Rate{minuteRate(int32(100 + i))},
			}},
		})
	}
	return out
}

func TestFit_leavesANamespaceThatFitsAlone(t *testing.T) {
	object := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})
	in := Input{Namespace: testNamespace, Policies: []v1.RateLimitPolicy{object}}
	result := Compile(in)

	Fit(in, result, ConfigMapLimit)

	outcome := result.Policies[key()]
	assert.False(t, outcome.TooLarge, "Outcome.TooLarge")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
}

// A generation set back by the fit still compiles: the spec is right, and the
// namespace is full. The last-good generation keeps serving, and the bundle to
// persist is the one that fits.
func TestFit_setsAGenerationThatDoesNotFitBackToLastGood(t *testing.T) {
	good := policyObject(v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})
	grown := *good.DeepCopy()
	grown.Generation = 2
	grown.Spec.Limits = wideBlocks("wide", 100)

	in := Input{
		Namespace: testNamespace,
		Policies:  []v1.RateLimitPolicy{grown},
		State:     map[string]Bundle{testDomain: {UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec}},
	}
	result := Compile(in)
	require.Equal(t, int64(2), result.Policies[key()].ActiveGeneration,
		"ActiveGeneration before Fit: the wide generation compiles, and only the fit keeps it out")

	// A limit the small generation fits and the wide one does not: the
	// small one is a few hundred bytes compressed, the wide one over two
	// thousand.
	Fit(in, result, 1024)

	outcome := result.Policies[key()]
	assert.True(t, outcome.Compiled(), "Compiled() with Err %v", outcome.Err)
	assert.True(t, outcome.TooLarge, "Outcome.TooLarge")
	assert.Contains(t, outcome.TooLargeReason, "over the limit of 1024", "Outcome.TooLargeReason")
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Equal(t, int64(2), outcome.Generation, "Outcome.Generation")
	assert.Equal(t, Bundle{UID: "uid-1", GoodGeneration: 1, GoodSpec: good.Spec}, result.State[testDomain],
		"Result.State[%q]", testDomain)
	assert.Len(t, blocksOf(t, result, testDomain), 1, "Snapshots[%q].Blocks", testDomain)
}

func TestFit_withoutLastGoodTheDomainIsClaimedAndEmpty(t *testing.T) {
	object := policyObject(wideBlocks("wide", 100)...)
	in := Input{Namespace: testNamespace, Policies: []v1.RateLimitPolicy{object}}
	result := Compile(in)

	Fit(in, result, 1024)

	outcome := result.Policies[key()]
	assert.True(t, outcome.TooLarge, "Outcome.TooLarge")
	assert.Zero(t, outcome.ActiveGeneration, "Outcome.ActiveGeneration")
	assert.Equal(t, Bundle{}, result.State[testDomain], "Result.State[%q]", testDomain)
	assert.Empty(t, blocksOf(t, result, testDomain), "Snapshots[%q].Blocks", testDomain)
}

// Two domains moved; one is wide, one is small. The limit admits the small one
// beside the wide one's last-good, so only the wide one is kept out, and the
// small one lands: keeping it out too would be one generation too many.
func TestFit_keepsOutTheFewestGenerationsLargestFirst(t *testing.T) {
	wide := policyFor("gateway.wide", "uid-wide", wideBlocks("wide", 100)...)
	small := policyFor("gateway.small", "uid-small", v1.LimitBlock{Name: "a", Rules: []v1.Rule{simpleRule("total")}})

	in := Input{Namespace: testNamespace, Policies: []v1.RateLimitPolicy{wide, small}}
	result := Compile(in)

	Fit(in, result, 1024)

	assert.True(t, result.Policies[keyOf("gateway.wide")].TooLarge, "TooLarge of gateway.wide")
	assert.False(t, result.Policies[keyOf("gateway.small")].TooLarge, "TooLarge of gateway.small")
	assert.Equal(t, int64(1), result.Policies[keyOf("gateway.small")].ActiveGeneration,
		"ActiveGeneration of gateway.small")
}

// The writer and the status reconciler run the fit separately and must agree,
// so two runs over the same input keep the same generations out. The three
// domains compress to the same size, so the order among them is the only thing
// that decides which ones the limit of 2000 bytes keeps out, and it keeps some
// out and lets others land.
func TestFit_isDeterministicAcrossRuns(t *testing.T) {
	verdict := func() map[string]bool {
		in := Input{Namespace: testNamespace, Policies: []v1.RateLimitPolicy{
			policyFor("gateway.a", "uid-gateway.a", wideBlocks("gateway.a", 40)...),
			policyFor("gateway.b", "uid-gateway.b", wideBlocks("gateway.b", 40)...),
			policyFor("gateway.c", "uid-gateway.c", wideBlocks("gateway.c", 40)...),
		}}
		result := Compile(in)
		Fit(in, result, 2000)
		out := map[string]bool{}
		for objectKey, outcome := range result.Policies {
			out[objectKey.Name] = outcome.TooLarge
		}
		return out
	}

	first := verdict()
	require.Contains(t, slices.Collect(maps.Values(first)), true, "TooLarge by domain: %v", first)
	require.Contains(t, slices.Collect(maps.Values(first)), false, "TooLarge by domain: %v", first)
	for run := range 10 {
		assert.Equal(t, first, verdict(), "TooLarge by domain on run %d after the first", run+1)
	}
}

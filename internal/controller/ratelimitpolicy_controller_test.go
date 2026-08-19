package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

const (
	testNamespace = "biz"
	testName      = "public-gateway"
	testDomain    = "gateway.public"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, ratelimitv1alpha1.AddToScheme(s))
	return s
}

// fakeClientWith builds a client that knows both kinds and gives each of them a
// status subresource. Without that last part the fake client writes status into
// the object itself, and a reconciler that only meant to touch status would come
// back having rewritten the spec.
func fakeClientWith(t *testing.T, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&ratelimitv1alpha1.RateLimitPolicy{}, &ratelimitv1alpha1.RateLimitMapping{}).
		Build()
	return fakeClient, scheme
}

func newReconciler(t *testing.T, objects ...client.Object) (*RateLimitPolicyReconciler, client.Client) {
	t.Helper()
	fakeClient, scheme := fakeClientWith(t, objects...)
	return &RateLimitPolicyReconciler{Client: fakeClient, Scheme: scheme}, fakeClient
}

func testPolicy(generation int64, rules ...ratelimitv1alpha1.Rule) *ratelimitv1alpha1.RateLimitPolicy {
	if len(rules) == 0 {
		rules = []ratelimitv1alpha1.Rule{{
			Name:  "total",
			Rates: []ratelimitv1alpha1.Rate{{Requests: 100, Period: "1m"}},
		}}
	}
	return &ratelimitv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       testName,
			Generation: generation,
		},
		Spec: ratelimitv1alpha1.RateLimitPolicySpec{
			Domain: testDomain,
			Limits: []ratelimitv1alpha1.LimitBlock{{Name: "api", Rules: rules}},
		},
	}
}

func testRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testName}}
}

func fetch(t *testing.T, c client.Client) *ratelimitv1alpha1.RateLimitPolicy {
	t.Helper()
	var object ratelimitv1alpha1.RateLimitPolicy
	require.NoError(t, c.Get(context.Background(), testRequest().NamespacedName, &object))
	return &object
}

func condition(t *testing.T, conditions []metav1.Condition, conditionType string) *metav1.Condition {
	t.Helper()
	found := meta.FindStatusCondition(conditions, conditionType)
	require.NotNil(t, found, "condition %s is missing", conditionType)
	return found
}

func TestReconcile_acceptsThePolicy(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, testPolicy(3))

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	stored := fetch(t, fakeClient)
	assert.Equal(t, int64(3), stored.Status.ObservedGeneration)

	accepted := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, metav1.ConditionTrue, accepted.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonRulesCompiled, accepted.Reason)
	assert.Equal(t, int64(3), accepted.ObservedGeneration)
	assert.Equal(t, "1 blocks, 1 rules compiled for domain gateway.public", accepted.Message)

	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonSnapshotApplied, ready.Reason)
	assert.Equal(t, int64(3), stored.Status.ActiveGeneration)
}

func TestReconcile_isIdempotent(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, testPolicy(1))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	first := fetch(t, fakeClient).ResourceVersion

	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	assert.Equal(t, first, fetch(t, fakeClient).ResourceVersion,
		"a second reconcile of an unchanged policy must not write status")
}

func TestReconcile_tracksANewGeneration(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, testPolicy(1))
	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	stored.Generation = 2
	stored.Spec.Domain = "gateway.private"
	require.NoError(t, fakeClient.Update(context.Background(), stored))

	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	updated := fetch(t, fakeClient)
	assert.Equal(t, int64(2), updated.Status.ObservedGeneration)
	accepted := condition(t, updated.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, int64(2), accepted.ObservedGeneration)
	assert.Contains(t, accepted.Message, "gateway.private")
}

func TestReconcile_aBlockingProblemKeepsTheGenerationOut(t *testing.T) {
	// A generation is enforced whole or not at all, so a reference that does not
	// resolve clears Ready and leaves nothing active.
	reconciler, fakeClient := newReconciler(t, testPolicy(1, ratelimitv1alpha1.Rule{
		Name:  "per-plan",
		When:  []ratelimitv1alpha1.Predicate{{Key: "plan", Operator: ratelimitv1alpha1.OperatorExists}},
		Rates: []ratelimitv1alpha1.Rate{{Requests: 10, Period: "1m"}},
	}))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	require.Len(t, stored.Status.RuleProblems, 1)
	assert.Equal(t, ratelimitv1alpha1.ProblemUnresolvedKeyReference, stored.Status.RuleProblems[0].Reason)
	assert.Equal(t, int32(1), stored.Status.Problems, "the printer column reads this count")

	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	// The domain has no mapping at all, which is a different fix from a mapping
	// that does not declare the key.
	assert.Equal(t, ratelimitv1alpha1.ReasonMappingRequired, ready.Reason)
	assert.Contains(t, ready.Message, "contributes no rules")
	assert.Zero(t, stored.Status.ActiveGeneration)

	// Accepted stays true: the spec is structurally fine, it just references
	// something the domain does not produce.
	assert.Equal(t, metav1.ConditionTrue,
		condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionAccepted).Status)
}

func TestReconcile_reportsTheGenerationThatKeepsRunning(t *testing.T) {
	// The pair of generations is the whole point: a rejected edit has to be visible
	// without hiding the fact that the earlier one is still serving traffic.
	broken := testPolicy(2, ratelimitv1alpha1.Rule{
		Name:  "per-plan",
		When:  []ratelimitv1alpha1.Predicate{{Key: "plan", Operator: ratelimitv1alpha1.OperatorExists}},
		Rates: []ratelimitv1alpha1.Rate{{Requests: 10, Period: "1m"}},
	})
	broken.UID = "uid-orders"

	good := testPolicy(1)
	good.UID = "uid-orders"
	state := policy.Compile(policy.Input{
		Policies: []ratelimitv1alpha1.RateLimitPolicy{*good},
	}).State[testDomain]

	reconciler, fakeClient := newReconciler(t, broken)
	reconciler.State = fakeState{testDomain: state}

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	assert.Equal(t, int64(2), stored.Status.ObservedGeneration)
	assert.Equal(t, int64(1), stored.Status.ActiveGeneration)

	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, "generation 2 is not enforced; generation 1 remains active", ready.Message)
}

// fakeState hands a reconciler the last-good bundles a real store would have
// persisted.
type fakeState map[string]policy.Bundle

func (f fakeState) Load(_ context.Context, domains []string) (map[string]policy.Bundle, error) {
	out := make(map[string]policy.Bundle, len(domains))
	for _, domain := range domains {
		if bundle, ok := f[domain]; ok {
			out[domain] = bundle
		}
	}
	return out, nil
}

func TestReconcile_reportsASpecTheCompilerRejects(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, testPolicy(1, ratelimitv1alpha1.Rule{
		Name:     "narrow",
		Replaces: []string{"absent"},
		Rates:    []ratelimitv1alpha1.Rate{{Requests: 10, Period: "1m"}},
	}))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	accepted := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, metav1.ConditionFalse, accepted.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonInvalidSpec, accepted.Reason)
	assert.Contains(t, accepted.Message, `replaces "absent"`)

	assert.Equal(t, metav1.ConditionFalse,
		condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady).Status,
		"a policy that contributed no rules is not Ready")
}

func TestReconcile_aMappingRevivesARuleThatReferencesItsKey(t *testing.T) {
	// Without the mapping watch, a rule fixed by adding a mapping would keep its
	// problem in the status until something else touched the policy.
	reconciler, fakeClient := newReconciler(t, testPolicy(1, ratelimitv1alpha1.Rule{
		Name:  "per-tenant",
		When:  []ratelimitv1alpha1.Predicate{{Key: "tenant", Operator: ratelimitv1alpha1.OperatorExists}},
		Rates: []ratelimitv1alpha1.Rate{{Requests: 10, Period: "1m"}},
	}))
	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	require.Len(t, fetch(t, fakeClient).Status.RuleProblems, 1)

	mapping := &ratelimitv1alpha1.RateLimitMapping{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testDomain},
		Spec: ratelimitv1alpha1.RateLimitMappingSpec{
			Domain:   testDomain,
			Mappings: []ratelimitv1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}},
		},
	}
	require.NoError(t, fakeClient.Create(context.Background(), mapping))

	requests := reconciler.policiesOfDomain(context.Background(), mapping)
	require.Equal(t, []ctrl.Request{testRequest()}, requests,
		"a changed mapping has to enqueue the policies of its domain")

	_, err = reconciler.Reconcile(context.Background(), requests[0])
	require.NoError(t, err)

	assert.Empty(t, fetch(t, fakeClient).Status.RuleProblems)
	assert.Zero(t, fetch(t, fakeClient).Status.Problems)
}

func TestPoliciesOfDomain_ignoresAnotherDomain(t *testing.T) {
	reconciler, _ := newReconciler(t, testPolicy(1))

	requests := reconciler.policiesOfDomain(context.Background(), &ratelimitv1alpha1.RateLimitMapping{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "gateway.private"},
		Spec:       ratelimitv1alpha1.RateLimitMappingSpec{Domain: "gateway.private"},
	})

	assert.Empty(t, requests)
}

func TestReconcile_ignoresADeletedPolicy(t *testing.T) {
	// There are no finalizers, and the store updater drops the policy on the same
	// informer event, so a missing object needs no cleanup and no requeue.
	reconciler, _ := newReconciler(t)

	result, err := reconciler.Reconcile(context.Background(), testRequest())

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestTruncateMessage_staysWithinWhatTheAPIServerAccepts(t *testing.T) {
	long := make([]byte, maxMessageLength+100)
	for i := range long {
		long[i] = 'a'
	}

	got := truncateMessage(string(long))

	assert.Len(t, got, maxMessageLength)
	assert.True(t, len(got) > 3 && got[len(got)-3:] == "...")
}

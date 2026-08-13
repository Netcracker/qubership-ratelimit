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

func newReconciler(t *testing.T, objects ...client.Object) (*RateLimitPolicyReconciler, client.Client) {
	t.Helper()
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&ratelimitv1alpha1.RateLimitPolicy{}).
		Build()
	return &RateLimitPolicyReconciler{Client: fakeClient, Scheme: scheme}, fakeClient
}

func testPolicy(generation int64) *ratelimitv1alpha1.RateLimitPolicy {
	return &ratelimitv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       testName,
			Generation: generation,
		},
		Spec: ratelimitv1alpha1.RateLimitPolicySpec{Domain: testDomain},
	}
}

func testRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testName}}
}

func fetch(t *testing.T, c client.Client) *ratelimitv1alpha1.RateLimitPolicy {
	t.Helper()
	var policy ratelimitv1alpha1.RateLimitPolicy
	require.NoError(t, c.Get(context.Background(), testRequest().NamespacedName, &policy))
	return &policy
}

func TestReconcile_acceptsThePolicy(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, testPolicy(3))

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	policy := fetch(t, fakeClient)
	assert.Equal(t, int64(3), policy.Status.ObservedGeneration)

	accepted := meta.FindStatusCondition(policy.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	require.NotNil(t, accepted)
	assert.Equal(t, metav1.ConditionTrue, accepted.Status)
	assert.Equal(t, "Accepted", accepted.Reason)
	assert.Equal(t, int64(3), accepted.ObservedGeneration)
	assert.Contains(t, accepted.Message, testDomain)
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

	policy := fetch(t, fakeClient)
	policy.Generation = 2
	policy.Spec.Domain = "gateway.private"
	require.NoError(t, fakeClient.Update(context.Background(), policy))

	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	updated := fetch(t, fakeClient)
	assert.Equal(t, int64(2), updated.Status.ObservedGeneration)
	accepted := meta.FindStatusCondition(updated.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	require.NotNil(t, accepted)
	assert.Equal(t, int64(2), accepted.ObservedGeneration)
	assert.Contains(t, accepted.Message, "gateway.private")
}

func TestReconcile_ignoresADeletedPolicy(t *testing.T) {
	// There are no finalizers, and the store updater drops the policy on the same
	// informer event, so a missing object needs no cleanup and no requeue.
	reconciler, _ := newReconciler(t)

	result, err := reconciler.Reconcile(context.Background(), testRequest())

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

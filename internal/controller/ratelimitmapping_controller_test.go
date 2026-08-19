package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

func newMappingReconciler(t *testing.T, objects ...client.Object) (*RateLimitMappingReconciler, client.Client) {
	t.Helper()
	fakeClient, scheme := fakeClientWith(t, objects...)
	return &RateLimitMappingReconciler{Client: fakeClient, Scheme: scheme}, fakeClient
}

func testMapping(entries ...ratelimitv1alpha1.ClaimMapping) *ratelimitv1alpha1.RateLimitMapping {
	return &ratelimitv1alpha1.RateLimitMapping{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: testDomain, Generation: 1},
		Spec: ratelimitv1alpha1.RateLimitMappingSpec{
			Domain:   testDomain,
			Mappings: entries,
		},
	}
}

func mappingRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testDomain}}
}

func fetchMapping(t *testing.T, c client.Client) *ratelimitv1alpha1.RateLimitMapping {
	t.Helper()
	var mapping ratelimitv1alpha1.RateLimitMapping
	require.NoError(t, c.Get(context.Background(), mappingRequest().NamespacedName, &mapping))
	return &mapping
}

func TestMappingReconcile_publishesTheEffectiveKeys(t *testing.T) {
	// The status is the one place a rule author can look up what a predicate may
	// reference.
	reconciler, fakeClient := newMappingReconciler(t, testMapping(
		ratelimitv1alpha1.ClaimMapping{
			Key:   "roles",
			Claim: "realm_access.roles",
			Type:  ratelimitv1alpha1.ClaimTypeStringArray,
		},
		ratelimitv1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"},
	))

	_, err := reconciler.Reconcile(context.Background(), mappingRequest())
	require.NoError(t, err)

	mapping := fetchMapping(t, fakeClient)
	assert.Equal(t, []string{"client", "method", "path", "roles", "tenant"}, mapping.Status.EffectiveKeys)
	assert.Equal(t, int64(1), mapping.Status.ObservedGeneration)

	accepted := condition(t, mapping.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, metav1.ConditionTrue, accepted.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonKeysResolved, accepted.Reason)
	assert.Contains(t, accepted.Message, "roles")

	ready := condition(t, mapping.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
}

func TestMappingReconcile_reportsAMappingWhoseNameIsNotItsDomain(t *testing.T) {
	// The CEL rule on the object rejects this at apply time, so it only happens
	// through a client that bypassed validation. Reporting it beats serving a
	// singleton that is not one.
	mapping := testMapping(ratelimitv1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"})
	mapping.Spec.Domain = "gateway.private"
	reconciler, fakeClient := newMappingReconciler(t, mapping)

	_, err := reconciler.Reconcile(context.Background(), mappingRequest())
	require.NoError(t, err)

	stored := fetchMapping(t, fakeClient)
	accepted := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, metav1.ConditionFalse, accepted.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonInvalidSpec, accepted.Reason)
}

func TestMappingReconcile_isIdempotent(t *testing.T) {
	reconciler, fakeClient := newMappingReconciler(t,
		testMapping(ratelimitv1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"}))

	_, err := reconciler.Reconcile(context.Background(), mappingRequest())
	require.NoError(t, err)
	first := fetchMapping(t, fakeClient).ResourceVersion

	_, err = reconciler.Reconcile(context.Background(), mappingRequest())
	require.NoError(t, err)

	assert.Equal(t, first, fetchMapping(t, fakeClient).ResourceVersion)
}

func TestMappingReconcile_ignoresADeletedMapping(t *testing.T) {
	// The domain falls back to the built-in keys on the same informer event.
	reconciler, _ := newMappingReconciler(t)

	result, err := reconciler.Reconcile(context.Background(), mappingRequest())

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

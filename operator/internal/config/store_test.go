package config

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/operator/internal/policy"
)

// The store's reading of an object somebody else wrote, or damaged. The
// envtest suite covers the round trip through a real API server; what is
// here is every way a stored object can be wrong and what Load does about
// each: skip the entry, keep the rest, say so in the log, never fail the
// namespace.

const unitNamespace = "unit"

func unitScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	return s
}

func storeOver(t *testing.T, objects ...client.Object) *Store {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(objects...).Build()
	return New(c, unitNamespace, nil, "0.0.0-unit", logr.Discard())
}

func goodSpec(domain string) v1alpha1.RateLimitPolicySpec {
	return v1alpha1.RateLimitPolicySpec{Domain: domain, Limits: []v1alpha1.LimitBlock{{
		Name: "a", Rules: []v1alpha1.Rule{{Name: "total", Rates: []v1alpha1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}}
}

// written renders an object the way Save would, then lets a test damage it.
func written(t *testing.T, state map[string]policy.Bundle) *corev1.ConfigMap {
	t.Helper()
	s := New(nil, unitNamespace, nil, "0.0.0-unit", logr.Discard())
	data, binaryData, err := s.render(state, policy.ConfigMapLimit)
	require.NoError(t, err)
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: contract.ConfigMapName},
		Data:       data,
		BinaryData: binaryData,
	}
}

func TestLoad_anAbsentObjectIsAColdStart(t *testing.T) {
	bundles, err := storeOver(t).Load(context.Background(), []string{"gateway.public"})
	require.NoError(t, err)
	assert.Empty(t, bundles)
}

func TestLoad_aManifestThatDoesNotDecodeStartsFromNothing(t *testing.T) {
	object := written(t, map[string]policy.Bundle{"gateway.public": {UID: "u", GoodGeneration: 1, GoodSpec: goodSpec("gateway.public")}})
	object.Data[contract.ManifestKey] = `{"formatVersion": 99, "domains": {}}`

	bundles, err := storeOver(t, object).Load(context.Background(), []string{"gateway.public"})
	require.NoError(t, err, "a manifest nobody here can read is not an outage; the next write replaces it")
	assert.Empty(t, bundles)
}

func TestLoad_skipsTheDamagedEntryAndKeepsTheRest(t *testing.T) {
	state := map[string]policy.Bundle{
		"gateway.a": {UID: "ua", GoodGeneration: 1, GoodSpec: goodSpec("gateway.a")},
		"gateway.b": {UID: "ub", GoodGeneration: 2, GoodSpec: goodSpec("gateway.b")},
		"gateway.c": {UID: "uc", GoodGeneration: 3, GoodSpec: goodSpec("gateway.c")},
		"gateway.d": {UID: "ud", GoodGeneration: 4, GoodSpec: goodSpec("gateway.d")},
	}
	object := written(t, state)
	// a: the payload is gone; b: the payload is not gzip; c: the payload is
	// somebody else's, so the hash disagrees; d: intact.
	delete(object.BinaryData, manifest.PayloadKey("gateway.a"))
	object.BinaryData[manifest.PayloadKey("gateway.b")] = []byte("not gzip")
	object.BinaryData[manifest.PayloadKey("gateway.c")] = object.BinaryData[manifest.PayloadKey("gateway.d")]

	bundles, err := storeOver(t, object).Load(context.Background(),
		[]string{"gateway.a", "gateway.b", "gateway.c", "gateway.d", "gateway.absent"})
	require.NoError(t, err)
	assert.Equal(t, []string{"gateway.d"}, keysOf(bundles),
		"one corrupt entry costs its own domain the fallback, not the namespace")
	assert.Equal(t, int64(4), bundles["gateway.d"].GoodGeneration)
	assert.Equal(t, "ud", bundles["gateway.d"].UID)
}

func TestLoad_reportsAReadThatFails(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("api server unreachable")
		}}).Build()
	_, err := New(c, unitNamespace, nil, "v", logr.Discard()).Load(context.Background(), []string{"gateway.public"})
	require.Error(t, err, "an outage is not an empty state: the caller must not compile from nothing")
}

func TestSave_replacesTheObjectWholeAndKeepsTheOwner(t *testing.T) {
	stale := written(t, map[string]policy.Bundle{"gateway.old": {UID: "uo", GoodGeneration: 1, GoodSpec: goodSpec("gateway.old")}})
	stale.Labels = map[string]string{"stale": "label"}
	store := storeOver(t, stale)
	store.SetOwner(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "op", UID: "op-uid"}}, "apps/v1", "Deployment")

	require.NoError(t, store.Save(context.Background(),
		map[string]policy.Bundle{"gateway.new": {UID: "un", GoodGeneration: 1, GoodSpec: goodSpec("gateway.new")}},
		policy.ConfigMapLimit))

	var object corev1.ConfigMap
	require.NoError(t, store.client.Get(context.Background(), store.key(), &object))
	assert.Equal(t, []string{manifest.PayloadKey("gateway.new")}, keysOf(object.BinaryData),
		"a retired domain's payload does not linger: the object is replaced, not merged")
	assert.NotContains(t, object.Labels, "stale")
	require.Len(t, object.OwnerReferences, 1)
	assert.Equal(t, "op", object.OwnerReferences[0].Name)
}

func TestSave_sparesTheWriteWhenTheObjectAlreadyHoldsIt(t *testing.T) {
	state := map[string]policy.Bundle{"gateway.same": {UID: "us", GoodGeneration: 1, GoodSpec: goodSpec("gateway.same")}}
	updates := 0
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.UpdateOption) error {
			updates++
			return c.Update(ctx, object, opts...)
		}}).Build()
	store := New(c, unitNamespace, map[string]string{"managed": "yes"}, "0.0.0-unit", logr.Discard())
	owner := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "op", UID: "op-uid"}}
	store.SetOwner(owner, "apps/v1", "Deployment")

	// The first write creates; the second, of the same state, finds the
	// object as it would write it and does not touch it. Every status write
	// of the probe cycle reaches Save this way.
	require.NoError(t, store.Save(context.Background(), state, policy.ConfigMapLimit))
	require.NoError(t, store.Save(context.Background(), state, policy.ConfigMapLimit))
	assert.Equal(t, 0, updates, "an identical write is spared, not sent to be a no-op at the API server")

	// Anything Save owns that differs is written: a payload, a label, the owner.
	state["gateway.more"] = policy.Bundle{UID: "um", GoodGeneration: 1, GoodSpec: goodSpec("gateway.more")}
	require.NoError(t, store.Save(context.Background(), state, policy.ConfigMapLimit))
	assert.Equal(t, 1, updates)
	store.labels = map[string]string{"managed": "still"}
	require.NoError(t, store.Save(context.Background(), state, policy.ConfigMapLimit))
	assert.Equal(t, 2, updates)
	store.SetOwner(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "op", UID: "op-reborn"}}, "apps/v1", "Deployment")
	require.NoError(t, store.Save(context.Background(), state, policy.ConfigMapLimit))
	assert.Equal(t, 3, updates, "a Deployment recreated under a new UID takes the object over")
	require.NoError(t, store.Save(context.Background(), state, policy.ConfigMapLimit))
	assert.Equal(t, 3, updates)
}

func TestSave_refusesAStateTheObjectCannotHold(t *testing.T) {
	store := storeOver(t)
	err := store.Save(context.Background(),
		map[string]policy.Bundle{"gateway.big": {UID: "ub", GoodGeneration: 1, GoodSpec: goodSpec("gateway.big")}}, 16)
	require.ErrorIs(t, err, ErrTooLarge)
	assert.Contains(t, err.Error(), "the limit is 16")
}

func TestSave_reportsAWriteThatFails(t *testing.T) {
	boom := errors.New("write refused")
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error { return boom },
	}).Build()
	err := New(c, unitNamespace, nil, "v", logr.Discard()).Save(context.Background(), nil, policy.ConfigMapLimit)
	require.ErrorIs(t, err, boom)
}

func TestAdoptDeployment_namesTheOwnerOrSaysWhyNot(t *testing.T) {
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "ratelimit-operator", UID: "d-uid"}}
	store := storeOver(t, deployment)

	require.NoError(t, store.AdoptDeployment(context.Background(), store.client, "ratelimit-operator"))
	require.NotNil(t, store.owner)
	assert.Equal(t, "Deployment", store.owner.Kind)
	assert.Equal(t, "d-uid", string(store.owner.UID))

	// A Deployment the operator cannot read: no owner, and the error names
	// the consequence so the log line does.
	other := storeOver(t)
	err := other.AdoptDeployment(context.Background(), other.client, "ratelimit-operator")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "written without an owner")
	assert.Nil(t, other.owner)
}

func TestCacheOptions_watchTheOneConfigMapByName(t *testing.T) {
	options := CacheOptions("biz")
	// ByObject is keyed by object pointer, so the entry is found by type.
	var entry cache.ByObject
	ok := false
	for object, byObject := range options.ByObject {
		if _, isConfigMap := object.(*corev1.ConfigMap); isConfigMap {
			entry, ok = byObject, true
		}
	}
	require.True(t, ok, "the ConfigMap informer has to be scoped, or it caches every ConfigMap of the namespace")
	config, ok := entry.Namespaces["biz"]
	require.True(t, ok, "and scoped to the namespace, or the Role is not enough")
	require.NotNil(t, config.FieldSelector)
	assert.Equal(t, "metadata.name="+contract.ConfigMapName, config.FieldSelector.String())
	assert.True(t, options.ReaderFailOnMissingInformer, "the controller's cache rules still hold")
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The reconciler's error paths: a read that fails and a write that fails
// both come back as errors, so controller-runtime retries them with backoff
// rather than the object staying as it was in silence.
func TestReconcile_returnsAReadFailure(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("api server unreachable")
		}}).Build()
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: New(c, unitNamespace, nil, "v", logr.Discard())}

	_, err := r.Reconcile(context.Background(), reconcileRequest())
	require.Error(t, err)
}

func TestReconcile_returnsAWriteFailure(t *testing.T) {
	object := &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "gateway.public", UID: "u", Generation: 1},
		Spec:       goodSpec("gateway.public"),
	}
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(object).Build()
	// A limit nothing fits, so the fit sets the generation back to an empty
	// bundle and the write still carries a manifest the limit refuses.
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: New(c, unitNamespace, nil, "v", logr.Discard()), Limit: 8}

	_, err := r.Reconcile(context.Background(), reconcileRequest())
	require.ErrorIs(t, err, ErrTooLarge)
}

func TestReconcile_writesTheNamespace(t *testing.T) {
	object := &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "gateway.public", UID: "u", Generation: 1},
		Spec:       goodSpec("gateway.public"),
	}
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(object).Build()
	store := New(c, unitNamespace, nil, "v", logr.Discard())
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: store}

	_, err := r.Reconcile(context.Background(), reconcileRequest())
	require.NoError(t, err)
	bundles, err := store.Load(context.Background(), []string{"gateway.public"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), bundles["gateway.public"].GoodGeneration)
}

func reconcileRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: unitNamespace, Name: contract.ConfigMapName}}
}

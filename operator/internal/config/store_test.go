package config

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
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
	require.NoError(t, v1.AddToScheme(s))
	return s
}

func fakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(objects...).Build()
}

func storeOver(t *testing.T, objects ...client.Object) *Store {
	t.Helper()
	return New(fakeClient(t, objects...), unitNamespace, nil, "0.0.0-unit", logr.Discard())
}

func goodSpec(domain string) v1.RateLimitPolicySpec {
	return v1.RateLimitPolicySpec{Domain: domain, Limits: []v1.LimitBlock{{
		Name: "a", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}}
}

// readConfigMap reads the namespace's ConfigMap through c.
func readConfigMap(t *testing.T, c client.Client) *corev1.ConfigMap {
	t.Helper()
	var object corev1.ConfigMap
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Namespace: unitNamespace, Name: contract.ConfigMapName},
		&object))
	return &object
}

// written is the object Save writes for the state, ready to be put in
// another client, or damaged first.
func written(t *testing.T, state map[string]policy.Bundle) *corev1.ConfigMap {
	t.Helper()
	c := fakeClient(t)
	require.NoError(t, New(c, unitNamespace, nil, "0.0.0-unit", logr.Discard()).
		Save(t.Context(), state, policy.ConfigMapLimit))
	object := readConfigMap(t, c)
	object.ResourceVersion = ""
	return object
}

func TestLoad_anAbsentObjectIsAColdStart(t *testing.T) {
	bundles, err := storeOver(t).Load(t.Context(), []string{"gateway.public"})

	assert.NoError(t, err)
	assert.Empty(t, bundles, "Load(gateway.public) with no ConfigMap")
}

// A manifest nobody here can read is not an outage: the next write replaces
// it, and until then nothing is last-good.
func TestLoad_aManifestThatDoesNotDecodeStartsFromNothing(t *testing.T) {
	object := written(t, map[string]policy.Bundle{
		"gateway.public": {UID: "u", GoodGeneration: 1, GoodSpec: goodSpec("gateway.public")}})
	object.Data[contract.ManifestKey] = `{"formatVersion": 99, "domains": {}}`

	bundles, err := storeOver(t, object).Load(t.Context(), []string{"gateway.public"})

	assert.NoError(t, err)
	assert.Empty(t, bundles, "Load(gateway.public) with formatVersion 99")
}

// One corrupt entry costs its own domain the fallback, not the namespace. Of
// the four domains the manifest names, gateway.a lost its payload, the payload
// of gateway.b is not gzip, gateway.c holds the payload of gateway.d, so the
// hash disagrees, and gateway.d is intact; gateway.absent is not in the
// manifest at all.
func TestLoad_aDamagedEntryCostsOnlyItsOwnDomain(t *testing.T) {
	object := written(t, map[string]policy.Bundle{
		"gateway.a": {UID: "ua", GoodGeneration: 1, GoodSpec: goodSpec("gateway.a")},
		"gateway.b": {UID: "ub", GoodGeneration: 2, GoodSpec: goodSpec("gateway.b")},
		"gateway.c": {UID: "uc", GoodGeneration: 3, GoodSpec: goodSpec("gateway.c")},
		"gateway.d": {UID: "ud", GoodGeneration: 4, GoodSpec: goodSpec("gateway.d")},
	})
	delete(object.BinaryData, "gateway.a.json.gz")
	object.BinaryData["gateway.b.json.gz"] = []byte("not gzip")
	object.BinaryData["gateway.c.json.gz"] = object.BinaryData["gateway.d.json.gz"]

	bundles, err := storeOver(t, object).Load(t.Context(),
		[]string{"gateway.a", "gateway.b", "gateway.c", "gateway.d", "gateway.absent"})

	assert.NoError(t, err)
	assert.Equal(t, map[string]policy.Bundle{
		"gateway.d": {UID: "ud", GoodGeneration: 4, GoodSpec: goodSpec("gateway.d")},
	}, bundles)
}

// An outage is not an empty state: the caller must not compile from nothing.
func TestLoad_reportsAReadThatFails(t *testing.T) {
	unreachable := errors.New("api server unreachable")
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return unreachable
		}}).Build()

	_, err := New(c, unitNamespace, nil, "v", logr.Discard()).Load(t.Context(), []string{"gateway.public"})

	assert.ErrorIs(t, err, unreachable)
}

// The object is replaced, not merged: a retired domain's payload and a label
// nobody set do not linger, and the owner is written onto the object.
func TestSave_replacesAnExistingObjectWhole(t *testing.T) {
	stale := written(t, map[string]policy.Bundle{
		"gateway.old": {UID: "uo", GoodGeneration: 1, GoodSpec: goodSpec("gateway.old")}})
	stale.Labels = map[string]string{"stale": "label"}
	c := fakeClient(t, stale)
	store := New(c, unitNamespace, nil, "0.0.0-unit", logr.Discard())
	store.SetOwner(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "op", UID: "op-uid"}}, "apps/v1", "Deployment")

	require.NoError(t, store.Save(t.Context(),
		map[string]policy.Bundle{"gateway.new": {UID: "un", GoodGeneration: 1, GoodSpec: goodSpec("gateway.new")}},
		policy.ConfigMapLimit))

	object := readConfigMap(t, c)
	assert.Equal(t, []string{"gateway.new.json.gz"}, slices.Sorted(maps.Keys(object.BinaryData)), "BinaryData keys")
	assert.Empty(t, object.Labels, "Labels")
	assert.Equal(t, []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "op", UID: "op-uid"}},
		object.OwnerReferences, "OwnerReferences")
}

// saveSettings is what one Save runs with: the store's labels, the UID of the
// Deployment "op" that owns the object, and the state.
type saveSettings struct {
	labels   map[string]string
	ownerUID types.UID
	state    map[string]policy.Bundle
}

// saveWith saves settings.state over c through a store with the settings'
// labels and owner.
func saveWith(t *testing.T, c client.Client, settings saveSettings) {
	t.Helper()
	store := New(c, unitNamespace, settings.labels, "0.0.0-unit", logr.Discard())
	store.SetOwner(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "op", UID: settings.ownerUID}},
		"apps/v1", "Deployment")
	require.NoError(t, store.Save(t.Context(), settings.state, policy.ConfigMapLimit))
}

// countingUpdates is a client that counts the updates sent through it.
func countingUpdates(t *testing.T) (c client.Client, updates *int) {
	t.Helper()
	updates = new(int)
	c = fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(
			ctx context.Context, inner client.WithWatch, object client.Object, opts ...client.UpdateOption,
		) error {
			*updates++
			return inner.Update(ctx, object, opts...)
		}}).Build()
	return c, updates
}

// An identical write is a no-op at the API server, and Save spares it the
// request; anything Save owns that differs is written. Every status write of
// the probe cycle reaches Save, so the identical case is the common one.
func TestSave_writesOnlyWhatDiffersFromTheObject(t *testing.T) {
	same := map[string]policy.Bundle{
		"gateway.same": {UID: "us", GoodGeneration: 1, GoodSpec: goodSpec("gateway.same")}}
	more := map[string]policy.Bundle{
		"gateway.same": {UID: "us", GoodGeneration: 1, GoodSpec: goodSpec("gateway.same")},
		"gateway.more": {UID: "um", GoodGeneration: 1, GoodSpec: goodSpec("gateway.more")}}
	first := saveSettings{labels: map[string]string{"managed": "yes"}, ownerUID: "op-uid", state: same}

	tests := []struct {
		name        string
		second      saveSettings
		wantUpdates int
	}{
		{"the state the object holds is spared",
			saveSettings{labels: map[string]string{"managed": "yes"}, ownerUID: "op-uid", state: same}, 0},
		{"a payload the object lacks is written",
			saveSettings{labels: map[string]string{"managed": "yes"}, ownerUID: "op-uid", state: more}, 1},
		{"a label the object lacks is written",
			saveSettings{labels: map[string]string{"managed": "still"}, ownerUID: "op-uid", state: same}, 1},
		{"an owner recreated under a new UID is written",
			saveSettings{labels: map[string]string{"managed": "yes"}, ownerUID: "op-reborn", state: same}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, updates := countingUpdates(t)
			saveWith(t, c, first)

			saveWith(t, c, tt.second)

			assert.Equal(t, tt.wantUpdates, *updates, "updates sent by the second Save")
		})
	}
}

// An update leaves the object as Save would write it, so the same state saved
// once more is spared.
func TestSave_sparesTheStateItsLastUpdateWrote(t *testing.T) {
	same := map[string]policy.Bundle{
		"gateway.same": {UID: "us", GoodGeneration: 1, GoodSpec: goodSpec("gateway.same")}}
	c, updates := countingUpdates(t)
	saveWith(t, c, saveSettings{labels: map[string]string{"managed": "yes"}, ownerUID: "op-uid", state: same})
	reborn := saveSettings{labels: map[string]string{"managed": "yes"}, ownerUID: "op-reborn", state: same}
	saveWith(t, c, reborn)
	require.Equal(t, 1, *updates, "updates sent by the Save under the new owner")

	saveWith(t, c, reborn)

	assert.Equal(t, 1, *updates, "updates sent after the same Save once more")
}

func TestSave_refusesAStateTheObjectCannotHold(t *testing.T) {
	err := storeOver(t).Save(t.Context(),
		map[string]policy.Bundle{"gateway.big": {UID: "ub", GoodGeneration: 1, GoodSpec: goodSpec("gateway.big")}}, 16)

	assert.ErrorIs(t, err, ErrTooLarge)
	assert.ErrorContains(t, err, "the limit is 16")
}

// A state the object cannot hold is refused before anything is written, so the
// object keeps the state of the last write, and the replicas keep the
// configuration they mounted.
func TestSave_leavesTheObjectAsItWasWhenTheStateDoesNotFit(t *testing.T) {
	kept := map[string]policy.Bundle{
		"gateway.kept": {UID: "uk", GoodGeneration: 1, GoodSpec: goodSpec("gateway.kept")}}
	store := storeOver(t, written(t, kept))

	err := store.Save(t.Context(),
		map[string]policy.Bundle{"gateway.big": {UID: "ub", GoodGeneration: 1, GoodSpec: goodSpec("gateway.big")}}, 16)

	assert.ErrorIs(t, err, ErrTooLarge)
	bundles, err := store.Load(t.Context(), []string{"gateway.kept", "gateway.big"})
	require.NoError(t, err)
	assert.Equal(t, kept, bundles, "Load after the refused Save")
}

func TestSave_reportsAWriteThatFails(t *testing.T) {
	refused := errors.New("write refused")
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error { return refused },
	}).Build()

	err := New(c, unitNamespace, nil, "v", logr.Discard()).Save(t.Context(), nil, policy.ConfigMapLimit)

	assert.ErrorIs(t, err, refused)
}

func TestAdoptDeployment_ownsTheObjectThroughTheDeployment(t *testing.T) {
	c := fakeClient(t, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "ratelimit-operator", UID: "d-uid"}})
	store := New(c, unitNamespace, nil, "0.0.0-unit", logr.Discard())

	require.NoError(t, store.AdoptDeployment(t.Context(), c, "ratelimit-operator"))
	require.NoError(t, store.Save(t.Context(), nil, policy.ConfigMapLimit))

	assert.Equal(t, []metav1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "Deployment", Name: "ratelimit-operator", UID: "d-uid"},
	}, readConfigMap(t, c).OwnerReferences)
}

// A Deployment the operator cannot read leaves the object without an owner
// rather than unwritten, and the error names that consequence, so the
// startup warning does.
func TestAdoptDeployment_leavesTheObjectUnownedWhenTheDeploymentIsMissing(t *testing.T) {
	c := fakeClient(t)
	store := New(c, unitNamespace, nil, "0.0.0-unit", logr.Discard())

	err := store.AdoptDeployment(t.Context(), c, "ratelimit-operator")
	require.NoError(t, store.Save(t.Context(), nil, policy.ConfigMapLimit))

	assert.ErrorContains(t, err, "written without an owner")
	assert.Empty(t, readConfigMap(t, c).OwnerReferences, "OwnerReferences")
}

// The ConfigMap informer is scoped to the one object by name, or it caches
// every ConfigMap of the namespace, and to the namespace, or the Role is not
// enough. The controller's own cache rules still hold.
func TestCacheOptions_watchTheOneConfigMapByName(t *testing.T) {
	options := CacheOptions("biz")

	// ByObject is keyed by object pointer, so the entry is found by type.
	var entry *cache.ByObject
	for object, byObject := range options.ByObject {
		if _, isConfigMap := object.(*corev1.ConfigMap); isConfigMap {
			entry = &byObject
		}
	}
	require.NotNil(t, entry, "CacheOptions(biz).ByObject has no ConfigMap entry")
	require.Contains(t, entry.Namespaces, "biz", "ByObject[ConfigMap].Namespaces")
	selector := entry.Namespaces["biz"].FieldSelector
	require.NotNil(t, selector, "ByObject[ConfigMap].Namespaces[biz].FieldSelector")
	assert.Equal(t, "metadata.name=ratelimit-config", selector.String(), "FieldSelector")
	assert.True(t, options.ReaderFailOnMissingInformer, "ReaderFailOnMissingInformer")
}

// The reconciler's error paths: a read that fails and a write that fails
// both come back as errors, so controller-runtime retries them with backoff
// rather than the object staying as it was in silence.

func TestReconcile_returnsAReadFailure(t *testing.T) {
	unreachable := errors.New("api server unreachable")
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return unreachable
		}}).Build()
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: New(c, unitNamespace, nil, "v", logr.Discard())}

	_, err := r.Reconcile(t.Context(), reconcileRequest())

	assert.ErrorIs(t, err, unreachable)
}

// Policies that cannot be listed are not an empty namespace: Reconcile returns
// the error and writes nothing, so the object keeps every domain it holds
// rather than a configuration compiled from no policy at all.
func TestReconcile_writesNothingWhenThePoliciesCannotBeListed(t *testing.T) {
	unreachable := errors.New("api server unreachable")
	kept := map[string]policy.Bundle{
		"gateway.public": {UID: "u", GoodGeneration: 1, GoodSpec: goodSpec("gateway.public")}}
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(written(t, kept)).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return unreachable
			}}).Build()
	store := New(c, unitNamespace, nil, "v", logr.Discard())
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: store}

	_, err := r.Reconcile(t.Context(), reconcileRequest())

	assert.ErrorIs(t, err, unreachable)
	bundles, err := store.Load(t.Context(), []string{"gateway.public"})
	require.NoError(t, err)
	assert.Equal(t, kept, bundles, "Load after the failed Reconcile")
}

// A write the size refused is counted under its reason, which is what the
// dashboard's panel watches. A limit nothing fits makes the fit set the
// generation back to an empty bundle, and the write still carries a manifest
// the limit refuses.
func TestReconcile_returnsAWriteFailureCountedUnderItsReason(t *testing.T) {
	object := &v1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "gateway.public", UID: "u", Generation: 1},
		Spec:       goodSpec("gateway.public"),
	}
	c := fakeClient(t, object)
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: New(c, unitNamespace, nil, "v", logr.Discard()), Limit: 8}
	before := testutil.ToFloat64(metrics.ConfigWriteErrors.WithLabelValues("size"))

	_, err := r.Reconcile(t.Context(), reconcileRequest())

	assert.ErrorIs(t, err, ErrTooLarge)
	assert.Equal(t, before+1, testutil.ToFloat64(metrics.ConfigWriteErrors.WithLabelValues("size")),
		`ratelimit_config_write_errors_total{reason="size"}`)
}

// An update of the existing object that the API server refuses comes back as
// the error and is counted under api, the reason for an answer of the API
// server. The object holds no domain yet, so the write is not spared.
func TestReconcile_countsAnUpdateTheAPIServerRefusedUnderAPI(t *testing.T) {
	object := &v1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "gateway.public", UID: "u", Generation: 1},
		Spec:       goodSpec("gateway.public"),
	}
	refused := apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, contract.ConfigMapName,
		errors.New("the object has been modified"))
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(written(t, nil), object).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
				return refused
			}}).Build()
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: New(c, unitNamespace, nil, "v", logr.Discard())}
	before := testutil.ToFloat64(metrics.ConfigWriteErrors.WithLabelValues("api"))

	_, err := r.Reconcile(t.Context(), reconcileRequest())

	assert.ErrorIs(t, err, refused)
	assert.Equal(t, before+1, testutil.ToFloat64(metrics.ConfigWriteErrors.WithLabelValues("api")),
		`ratelimit_config_write_errors_total{reason="api"}`)
}

func TestWriteErrorReason_namesTheCause(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"a state the object cannot hold", fmt.Errorf("wrapped: %w", ErrTooLarge), "size"},
		{"an answer of the API server", fmt.Errorf("update: %w",
			apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "ratelimit-config", errors.New("no"))),
			"api"},
		{"a client that could not reach the API server", errors.New("connection refused"), "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, writeErrorReason(tt.err), "writeErrorReason(%v)", tt.err)
		})
	}
}

func TestReconcile_writesTheNamespace(t *testing.T) {
	object := &v1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "gateway.public", UID: "u", Generation: 1},
		Spec:       goodSpec("gateway.public"),
	}
	c := fakeClient(t, object)
	store := New(c, unitNamespace, nil, "v", logr.Discard())
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: store}

	_, err := r.Reconcile(t.Context(), reconcileRequest())

	require.NoError(t, err)
	bundles, err := store.Load(t.Context(), []string{"gateway.public"})
	require.NoError(t, err)
	assert.Equal(t, map[string]policy.Bundle{
		"gateway.public": {UID: "u", GoodGeneration: 1, GoodSpec: goodSpec("gateway.public")},
	}, bundles)
}

func reconcileRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: unitNamespace, Name: contract.ConfigMapName}}
}

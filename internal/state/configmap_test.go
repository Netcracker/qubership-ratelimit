package state

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

const (
	testNamespace = "biz"
	testDomain    = "gateway.public"
)

func newStore(t *testing.T, objects ...client.Object) (*Store, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	return New(fakeClient, testNamespace,
		map[string]string{"app.kubernetes.io/managed-by": "ratelimit"}), fakeClient
}

func testBundle() policy.Bundle {
	return policy.Bundle{
		Mapping: &policy.MappingState{
			UID:            "uid-mapping",
			GoodGeneration: 3,
			GoodSpec:       v1alpha1.RateLimitMappingSpec{Domain: testDomain},
		},
		Policies: []policy.PolicyState{{
			Name:           "orders",
			UID:            "uid-orders",
			GoodGeneration: 7,
			GoodSpec: v1alpha1.RateLimitPolicySpec{
				Domain: testDomain,
				Limits: []v1alpha1.LimitBlock{{
					Name:  "api",
					Rules: []v1alpha1.Rule{{Name: "total", Rates: []v1alpha1.Rate{{Requests: 10, Period: "1m"}}}},
				}},
			},
		}},
	}
}

func TestSaveAndLoad_roundTripsTheState(t *testing.T) {
	store, _ := newStore(t)

	require.NoError(t, store.Save(context.Background(), testDomain, testBundle()))
	loaded, err := store.Load(context.Background(), []string{testDomain})
	require.NoError(t, err)

	assert.Equal(t, testBundle(), loaded[testDomain])
}

func TestSave_writesOneConfigMapPerDomain(t *testing.T) {
	store, fakeClient := newStore(t)

	require.NoError(t, store.Save(context.Background(), testDomain, testBundle()))

	var configMap corev1.ConfigMap
	key := client.ObjectKey{Namespace: testNamespace, Name: "ratelimit-state-gateway.public"}
	require.NoError(t, fakeClient.Get(context.Background(), key, &configMap))

	assert.Contains(t, configMap.BinaryData, DataKey,
		"the bundle is gzipped, and a gzip stream is not valid UTF-8")
	assert.Equal(t, testDomain, configMap.Labels["ratelimit.netcracker.com/domain"])
	assert.Equal(t, "ratelimit", configMap.Labels["app.kubernetes.io/managed-by"])
}

func TestSave_overwritesAnExistingState(t *testing.T) {
	store, _ := newStore(t)
	require.NoError(t, store.Save(context.Background(), testDomain, testBundle()))

	updated := testBundle()
	updated.Policies[0].GoodGeneration = 9
	require.NoError(t, store.Save(context.Background(), testDomain, updated))

	loaded, err := store.Load(context.Background(), []string{testDomain})
	require.NoError(t, err)
	assert.Equal(t, int64(9), loaded[testDomain].Policies[0].GoodGeneration)
}

func TestLoad_aDomainWithNoStateIsAColdStart(t *testing.T) {
	// The latest specs are validated and there is nothing to fall back to, which is
	// a valid state rather than an error.
	store, _ := newStore(t)

	loaded, err := store.Load(context.Background(), []string{testDomain, "gateway.private"})

	require.NoError(t, err)
	assert.Empty(t, loaded)
}

func TestLoad_reportsAConfigMapThatIsNotABundle(t *testing.T) {
	store, _ := newStore(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: Name(testDomain)},
		BinaryData: map[string][]byte{DataKey: []byte("not gzip")},
	})

	_, err := store.Load(context.Background(), []string{testDomain})

	require.Error(t, err)
	assert.Contains(t, err.Error(), testDomain)
}

func TestLoad_skipsAConfigMapWithoutTheStateEntry(t *testing.T) {
	// Something else created the object, or a migration renamed the entry. Either
	// way there is no last-good spec to be had, and that is a cold start.
	store, _ := newStore(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: Name(testDomain)},
		Data:       map[string]string{"unrelated": "value"},
	})

	loaded, err := store.Load(context.Background(), []string{testDomain})

	require.NoError(t, err)
	assert.Empty(t, loaded)
}

func TestDelete_dropsTheStateOfARetiredDomain(t *testing.T) {
	// Without it the ConfigMap of a retired gateway would stay forever, and a
	// domain later recreated under the same name would inherit specs nobody wrote.
	store, fakeClient := newStore(t)
	require.NoError(t, store.Save(context.Background(), testDomain, testBundle()))

	require.NoError(t, store.Delete(context.Background(), testDomain))

	var configMap corev1.ConfigMap
	key := client.ObjectKey{Namespace: testNamespace, Name: Name(testDomain)}
	assert.Error(t, fakeClient.Get(context.Background(), key, &configMap))
}

func TestDelete_isIdempotent(t *testing.T) {
	store, _ := newStore(t)

	assert.NoError(t, store.Delete(context.Background(), testDomain))
}

func TestName_isDerivedFromTheDomain(t *testing.T) {
	// The name has to be derivable, because it is how a replica finds the state of
	// a domain without listing every ConfigMap of the namespace.
	assert.Equal(t, "ratelimit-state-gateway.public", Name("gateway.public"))
}

package audit

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testNamespace = "core"

func newStore(t *testing.T, objects ...client.Object) *Store {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	return &Store{
		Client:    fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(),
		Namespace: testNamespace,
		Labels:    map[string]string{"app.kubernetes.io/managed-by": "ratelimit"},
	}
}

func TestStoreLoad_aMissingConfigMapIsTheEmptySelection(t *testing.T) {
	// Nothing is selected until someone selects it, so the absence of the object
	// is the normal state rather than an error worth reporting.
	store := newStore(t)

	selection, err := store.Load(context.Background())

	require.NoError(t, err)
	assert.Empty(t, selection.Rules)
}

func TestStoreSave_roundTrips(t *testing.T) {
	store := newStore(t)
	want := Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "api/orders/per-client"}}}

	require.NoError(t, store.Save(context.Background(), want))

	got, err := store.Load(context.Background())
	require.NoError(t, err)
	assert.Equal(t, want.Rules, got.Rules)
}

func TestStoreSave_replacesAnExistingSelection(t *testing.T) {
	// The whole set is replaced rather than added to, so two people debugging at
	// once cannot leave a rule streaming that neither of them remembers.
	store := newStore(t)
	require.NoError(t, store.Save(context.Background(),
		Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "a/a/a"}}}))

	require.NoError(t, store.Save(context.Background(),
		Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "b/b/b"}}}))

	got, err := store.Load(context.Background())
	require.NoError(t, err)
	require.Len(t, got.Rules, 1)
	assert.Equal(t, "b/b/b", got.Rules[0].RuleID)
}

func TestStoreSave_carriesNoDomainLabel(t *testing.T) {
	// The last-good state ConfigMaps are labelled by domain, and a new leader
	// sweeps every object carrying that label whose domain no longer exists.
	// This ConfigMap belongs to no domain, so it must never be labelled that way
	// — a leader handover would otherwise delete the audit selection.
	//
	// The label is spelled out rather than imported because the point of the
	// test is that these two features stay unrelated.
	const domainLabel = "ratelimit.netcracker.com/domain"
	store := newStore(t)
	require.NoError(t, store.Save(context.Background(),
		Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "a/a/a"}}}))

	var configMap corev1.ConfigMap
	require.NoError(t, store.Client.Get(context.Background(),
		types.NamespacedName{Namespace: testNamespace, Name: ConfigMapName}, &configMap))

	assert.NotContains(t, configMap.Labels, domainLabel)
}

func TestStoreLoad_reportsUnreadableContent(t *testing.T) {
	// Silently treating a corrupt selection as "nothing selected" would leave an
	// operator watching a stream that will never carry anything.
	store := newStore(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ConfigMapName, Namespace: testNamespace},
		Data:       map[string]string{"selection.json": "{not json"},
	})

	_, err := store.Load(context.Background())

	require.Error(t, err)
}

func TestRefresher_bringsAReplicaUpToDate(t *testing.T) {
	// Every replica decides, so every replica has to converge on the selection
	// somebody set through one of them.
	store := newStore(t)
	require.NoError(t, store.Save(context.Background(),
		Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "api/orders/per-client"}}}))

	board := NewSwitchboard()
	refresher := &Refresher{Store: store, Switchboard: board, Interval: time.Hour, Log: logr.Discard()}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- refresher.Start(ctx) }()

	// Start refreshes once before it begins ticking, so the first read is what
	// this asserts on rather than a race with the interval.
	require.Eventually(t, func() bool {
		return board.Enabled("gateway.public", "api", "orders", "per-client")
	}, 5*time.Second, 20*time.Millisecond)

	cancel()
	require.NoError(t, <-done)
}

func TestRefresher_keepsTheCurrentSelectionWhenTheStoreFails(t *testing.T) {
	// Losing the audit stream is not worth a restart, and the next tick tries
	// again.
	board := NewSwitchboard()
	board.Set(Selection{Rules: []RuleRef{{Domain: "gateway.public", RuleID: "api/orders/per-client"}}})

	store := newStore(t, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ConfigMapName, Namespace: testNamespace},
		Data:       map[string]string{"selection.json": "{not json"},
	})
	refresher := &Refresher{Store: store, Switchboard: board, Interval: time.Hour, Log: logr.Discard()}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = refresher.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	assert.True(t, board.Enabled("gateway.public", "api", "orders", "per-client"))
}

func TestNeedLeaderElection_everyReplicaRefreshes(t *testing.T) {
	// The selection drives what each replica streams, and every replica decides.
	assert.False(t, (&Refresher{}).NeedLeaderElection())
}

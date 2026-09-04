package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// fakeReader builds a reader over the given objects.
func fakeReader(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objects...).Build()
}

// readerOnly satisfies InformerSource for tests that drive rebuild directly:
// rebuild reads, it never subscribes.
type readerOnly struct {
	client.Reader
}

func (readerOnly) GetInformer(context.Context, client.Object, ...cache.InformerGetOption) (cache.Informer, error) {
	return nil, fmt.Errorf("rebuild does not subscribe")
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	return s
}

// testNamespace is the single business namespace an installation serves.
const testNamespace = "biz"

// policyObject builds the one policy of a domain. Its name is its domain: the
// API server rejects any other name, so a fixture that used one would be
// testing a state the cluster cannot produce.
func policyObject(domain string) *v1alpha1.RateLimitPolicy {
	return &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: domain, Generation: 1, UID: types.UID("uid-" + domain),
		},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain:   domain,
			Mappings: []v1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}},
			Limits: []v1alpha1.LimitBlock{{
				Name: "api",
				Rules: []v1alpha1.Rule{{
					Name:  "total",
					Rates: []v1alpha1.Rate{{Requests: 100, PeriodSeconds: 60}},
				}},
			}},
		},
	}
}

func TestRuleSet_reusesTheEngineOfAnUnchangedDomain(t *testing.T) {
	// The snapshot is a pure function of the bundle, so an unchanged bundle must
	// keep its engine — and with it the warm token cache — while a changed one
	// must get a fresh engine compiled from the new rules.
	updater := &Updater{Counters: memory.New()}
	compile := func(moving int32) *policy.Result {
		return policy.Compile(policy.Input{
			Namespace: testNamespace,
			Policies: []v1alpha1.RateLimitPolicy{
				policyWith("gateway.private", 10),
				policyWith("gateway.public", moving),
			},
		})
	}

	first, second, third := compile(10), compile(20), compile(20)

	firstSet := updater.ruleSet(first, nil)
	secondSet := updater.ruleSet(second, first.State)

	require.NotNil(t, firstSet.Engine("gateway.public"))
	assert.NotSame(t, firstSet.Engine("gateway.public"), secondSet.Engine("gateway.public"),
		"a changed bundle must produce a fresh engine")
	assert.Same(t, firstSet.Engine("gateway.private"), secondSet.Engine("gateway.private"),
		"the untouched domain keeps its engine, and with it its warm token cache")

	thirdSet := updater.ruleSet(third, second.State)
	assert.Same(t, secondSet.Engine("gateway.public"), thirdSet.Engine("gateway.public"),
		"an unchanged bundle must keep its engine")
}

// policyWith is a one-rule policy whose limit is its only moving part.
func policyWith(domain string, requests int32) v1alpha1.RateLimitPolicy {
	return v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: domain, Generation: 1, UID: types.UID("uid-" + domain),
		},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain:   domain,
			Mappings: []v1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}},
			Limits: []v1alpha1.LimitBlock{{Name: "b", Rules: []v1alpha1.Rule{{
				Name:  "all",
				Rates: []v1alpha1.Rate{{Requests: requests, PeriodSeconds: 60}},
			}}}},
		},
	}
}

func TestRebuild_aBudgetBlockedGenerationKeepsTheLastGoodOne(t *testing.T) {
	// The budget is blocking, so an edit over it never becomes the active
	// generation. What must not happen is the domain losing its limits: the
	// last-good generation keeps serving, and the rebuild says so.
	good := policyObject("gateway.public")

	oversized := *good.DeepCopy()
	oversized.Generation = 2
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
	oversized.Spec.Limits = []v1alpha1.LimitBlock{{Name: "b", Rules: rules}}

	var logged []string
	sink := funcr.New(func(prefix, args string) {
		logged = append(logged, prefix+args)
	}, funcr.Options{})

	fakeClient := fakeReader(t, &oversized)
	updater := &Updater{
		Cache:     readerOnly{fakeClient},
		Store:     New(),
		Namespace: testNamespace,
		Counters:  memory.New(),
		Log:       sink,
		bundles: map[string]policy.Bundle{"gateway.public": {
			UID:            string(good.UID),
			GoodGeneration: 1,
			GoodSpec:       *good.Spec.DeepCopy(),
		}},
	}

	updater.rebuild(context.Background())

	require.True(t, updater.Store.Load().Has("gateway.public"),
		"the domain keeps its last-good limits rather than losing them to a bad edit")
	assert.Equal(t, 1, len(updater.Store.Load().Snapshot("gateway.public").Blocks))
	assert.Contains(t, strings.Join(logged, "\n"), "policiesOnLastGood")
}

func TestPersist_sweepsTheStateOfADomainRetiredBeforeTheLease(t *testing.T) {
	// The regular delete loop only sees what this process persisted itself, so a
	// domain retired under the previous leader would keep its ConfigMap forever
	// without the sweep.
	state := newStubState()
	state.saved["gateway.retired"] = policy.Bundle{}
	updater := &Updater{State: state}

	updater.persist(context.Background(), map[string]policy.Bundle{})

	assert.Contains(t, state.deletedDomains(), "gateway.retired")
	assert.True(t, updater.reconciledStale, "a clean sweep does not repeat")
}

func TestPersist_retriesTheSweepWhenListingFails(t *testing.T) {
	state := newStubState()
	state.listFailing = true
	updater := &Updater{State: state}

	updater.persist(context.Background(), map[string]policy.Bundle{})

	assert.False(t, updater.reconciledStale, "a failed listing leaves the sweep to the next rebuild")
	assert.Empty(t, state.deletedDomains())
}

func TestPersist_retriesTheSweepWhenADeleteFails(t *testing.T) {
	state := newStubState()
	state.saved["gateway.retired"] = policy.Bundle{}
	state.deleteFailing = true
	updater := &Updater{State: state}

	updater.persist(context.Background(), map[string]policy.Bundle{})

	assert.False(t, updater.reconciledStale, "a failed delete leaves the sweep to the next rebuild")
}

func TestReady_isFalseUntilTheStoreHasRules(t *testing.T) {
	// The gRPC listener comes up before the first rebuild, and an empty store
	// admits everything. A replica that reported ready in that state would join
	// the Service endpoints with no limits at all.
	updater := &Updater{}

	assert.False(t, updater.Ready())
}

func TestReady_isTrueOnceTheStoreHasBeenBuilt(t *testing.T) {
	// One rebuild is enough: the store then reflects the namespace, whether or
	// not any policy in it compiled.
	source := newStubSource(t, policyObject("gateway.public"))
	updater := &Updater{Cache: source, Store: New(), Log: logr.Discard(), Counters: memory.New()}
	require.False(t, updater.Ready())

	updater.rebuild(context.Background())

	assert.True(t, updater.Ready())
}

func TestReady_staysFalseWhenTheNamespaceCannotBeRead(t *testing.T) {
	// A rebuild that could not list the objects leaves the previous snapshot in
	// place — which on the first one is an empty store, and an empty store
	// admits everything. Reporting ready there is what would put a replica with
	// no rules into the Service endpoints.
	source := newStubSource(t)
	source.Reader = failingReader{}
	updater := &Updater{Cache: source, Store: New(), Log: logr.Discard(), Counters: memory.New()}

	updater.rebuild(context.Background())

	assert.False(t, updater.Ready())
}

// failingReader is a client.Reader whose List always fails, standing in for an
// API server this replica cannot reach.
type failingReader struct{ client.Reader }

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("the API server is unavailable")
}

func TestStateView_distillsTheCompilation(t *testing.T) {
	healthy := policyWith("gateway.public", 10)
	broken := policyWith("gateway.private", 10)
	broken.Spec.Limits[0].Rules[0].Rates[0].PeriodSeconds = 0

	result := policy.Compile(policy.Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{healthy, broken},
	})
	view := stateView(result)

	domains := map[string]metrics.DomainView{}
	for _, d := range view.Domains {
		domains[d.Domain] = d
	}
	require.Len(t, domains, 2)
	assert.Equal(t, 1, domains["gateway.public"].Blocks)
	assert.Equal(t, 1, domains["gateway.public"].DecisionBuckets)
	assert.Equal(t, int64(1), domains["gateway.public"].AppliedGeneration)
	assert.Zero(t, domains["gateway.private"].AppliedGeneration,
		"a domain with nothing enforced reports generation zero")

	policies := map[string]metrics.PolicyView{}
	for _, p := range view.Policies {
		policies[p.Policy] = p
	}
	require.Len(t, policies, 2)

	ok := policies["biz/gateway.public"]
	assert.True(t, ok.Ready)
	assert.True(t, ok.Enforced)
	assert.Empty(t, ok.Reason)
	assert.Zero(t, ok.GenerationLag)

	bad := policies["biz/gateway.private"]
	assert.False(t, bad.Ready)
	assert.False(t, bad.Enforced, "an invalid spec with no last-good enforces nothing")
	assert.Equal(t, v1alpha1.ReasonNotCompiled, bad.Reason)
	assert.Equal(t, int64(1), bad.GenerationLag, "with nothing enforced the whole generation trails")
}

func TestPersist_countsAFailedDelete(t *testing.T) {
	state := newStubState()
	state.saved["gateway.retired"] = policy.Bundle{}
	state.deleteFailing = true
	updater := &Updater{State: state}

	before := testutil.ToFloat64(metrics.StatePersistErrors.WithLabelValues("delete"))
	updater.persist(context.Background(), map[string]policy.Bundle{})

	got := testutil.ToFloat64(metrics.StatePersistErrors.WithLabelValues("delete"))
	assert.Equal(t, before+1, got,
		"a ConfigMap that cannot be dropped retries forever and must be visible")
}

func TestRebuild_prunesTheSeriesOfARenamedRule(t *testing.T) {
	// The rebuild is where the pruner learns the active set: a series left by
	// a renamed rule must not survive the swap.
	metrics.Decisions.WithLabelValues("gateway.public", "b/old", "ok").Inc()

	fakeClient := fakeReader(t, policyObject("gateway.public"))
	updater := &Updater{
		Cache:     readerOnly{fakeClient},
		Store:     New(),
		Namespace: testNamespace,
		Counters:  memory.New(),
	}
	updater.rebuild(context.Background())

	assert.Zero(t, testutil.ToFloat64(
		metrics.Decisions.WithLabelValues("gateway.public", "b/old", "ok")))
}

func TestExtractionKeys_listsTokenExtractedKeysOnce(t *testing.T) {
	result := policy.Compile(policy.Input{
		Namespace: testNamespace,
		Policies:  []v1alpha1.RateLimitPolicy{policyWith("gateway.public", 10)},
	})

	assert.ElementsMatch(t, []string{"client", "tenant"}, extractionKeys(result),
		"the built-in client and the mapped tenant are extracted from the token; path and method are resolved from the request and stay out")
}

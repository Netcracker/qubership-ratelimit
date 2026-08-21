package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// fakeReader builds a reader over the given objects.
func fakeReader(t *testing.T, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := testScheme(t)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(), scheme
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

func policyObject(name, domain string) *v1alpha1.RateLimitPolicy {
	return &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain: domain,
			Limits: []v1alpha1.LimitBlock{{
				Name: "api",
				Rules: []v1alpha1.Rule{{
					Name:  "total",
					Rates: []v1alpha1.Rate{{Requests: 100, Period: "1m"}},
				}},
			}},
		},
	}
}

func mappingObject(domain string) *v1alpha1.RateLimitMapping {
	return &v1alpha1.RateLimitMapping{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: domain},
		Spec: v1alpha1.RateLimitMappingSpec{
			Domain:   domain,
			Mappings: []v1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}},
		},
	}
}

func TestRuleSet_reusesTheEngineOfAnUnchangedDomain(t *testing.T) {
	// The snapshot is a pure function of the bundle, so an unchanged bundle must
	// keep its engine — and with it the warm token cache — while a changed one
	// must get a fresh engine compiled from the new rules.
	updater := &Updater{Counters: memory.New()}

	first := policy.Compile(policy.Input{Policies: []v1alpha1.RateLimitPolicy{
		policyWith("stable", 10), policyWith("moving", 10),
	}})
	// Both objects bind to one domain, so both live in one bundle: reuse is per
	// domain. A second domain gives the test its unchanged half.
	second := policy.Compile(policy.Input{Policies: []v1alpha1.RateLimitPolicy{
		policyWith("stable", 10), policyWith("moving", 20),
	}})

	firstSet := updater.ruleSet(first, nil)
	secondSet := updater.ruleSet(second, first.State)

	require.NotNil(t, firstSet.Engine("gateway.public"))
	assert.NotSame(t, firstSet.Engine("gateway.public"), secondSet.Engine("gateway.public"),
		"a changed bundle must produce a fresh engine")

	third := policy.Compile(policy.Input{Policies: []v1alpha1.RateLimitPolicy{
		policyWith("stable", 10), policyWith("moving", 20),
	}})
	thirdSet := updater.ruleSet(third, second.State)
	assert.Same(t, secondSet.Engine("gateway.public"), thirdSet.Engine("gateway.public"),
		"an unchanged bundle must keep its engine")
}

// policyWith is a one-rule policy whose limit is its only moving part.
func policyWith(name string, requests int32) v1alpha1.RateLimitPolicy {
	return v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "biz", Name: name, Generation: 1},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain: "gateway.public",
			Limits: []v1alpha1.LimitBlock{{Name: "b", Rules: []v1alpha1.Rule{{
				Name:  "all",
				Rates: []v1alpha1.Rate{{Requests: requests, Period: "1m"}},
			}}}},
		},
	}
}

func TestRebuild_logsTheDomainBudgetWarning(t *testing.T) {
	// The informational domain record is the early warning that the runtime
	// backstop is within reach; a rebuild that swallowed it would leave refused
	// requests as the first symptom.
	wide := func(name string) *v1alpha1.RateLimitPolicy {
		rules := make([]v1alpha1.Rule, 0, 16)
		for i := range 16 {
			rules = append(rules, v1alpha1.Rule{
				Name: fmt.Sprintf("r%d", i),
				Rates: []v1alpha1.Rate{
					{Requests: 100, Period: "1m"},
					{Requests: 100, Period: "1h"},
					{Requests: 100, Period: "30s"},
					{Requests: 100, Period: "10s"},
				},
			})
		}
		object := policyObject(name, "gateway.public")
		object.Spec.Limits = []v1alpha1.LimitBlock{{Name: "b", Rules: rules}}
		return object
	}

	var logged []string
	sink := funcr.New(func(prefix, args string) {
		logged = append(logged, prefix+args)
	}, funcr.Options{})

	// The seats are inherited from the persisted state: the domain gate never
	// evicts a running policy, so the oversized set survives into the snapshot
	// and the warning is its only trace.
	objects := []*v1alpha1.RateLimitPolicy{wide("p1"), wide("p2"), wide("p3")}
	bundle := policy.Bundle{}
	for _, object := range objects {
		bundle.Policies = append(bundle.Policies, policy.PolicyState{
			Name:           object.Name,
			GoodGeneration: object.Generation,
			GoodSpec:       *object.Spec.DeepCopy(),
		})
	}

	fakeClient, _ := fakeReader(t, objects[0], objects[1], objects[2])
	updater := &Updater{
		Cache:    readerOnly{fakeClient},
		Store:    New(),
		Counters: memory.New(),
		Log:      sink,
		bundles:  map[string]policy.Bundle{"gateway.public": bundle},
	}

	updater.rebuild(context.Background())

	require.True(t, updater.Store.Load().Has("gateway.public"),
		"the oversized domain still serves: the record excludes nobody")
	joined := strings.Join(logged, "\n")
	assert.Contains(t, joined, "domain over its reference bounds")
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
	source := newStubSource(t, policyObject("public", "gateway.public"))
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

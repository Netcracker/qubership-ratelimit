package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

const (
	testNamespace = "biz"
	testDomain    = "gateway.public"
	testUID       = types.UID("uid-1")
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, ratelimitv1alpha1.AddToScheme(s))
	return s
}

// fakeClientWith builds a client that gives the policy a status subresource.
// Without that the fake client writes status into the object itself, and a
// reconciler that only meant to touch status would come back having rewritten
// the spec.
func fakeClientWith(t *testing.T, objects ...client.Object) (client.Client, *runtime.Scheme) {
	t.Helper()
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&ratelimitv1alpha1.RateLimitPolicy{}).
		Build()
	return fakeClient, scheme
}

// stubProbe answers for the fleet without a network.
type stubProbe struct {
	view FleetView
	err  error

	asked []store.Applied
}

func (s *stubProbe) Observe(_ context.Context, _ string, want store.Applied) (FleetView, error) {
	s.asked = append(s.asked, want)
	if s.err != nil {
		return FleetView{}, s.err
	}
	return s.view, nil
}

// unanimous is the healthy fleet: every ready replica on the asked-for
// generation.
func unanimous(replicas int32) *stubProbe {
	return &stubProbe{view: FleetView{Total: replicas, Applied: replicas}}
}

func newReconciler(t *testing.T, probe FleetProbe, objects ...client.Object) (
	*RateLimitPolicyReconciler, client.Client,
) {
	t.Helper()
	fakeClient, scheme := fakeClientWith(t, objects...)
	return &RateLimitPolicyReconciler{
		Client:    fakeClient,
		Scheme:    scheme,
		Namespace: testNamespace,
		Probe:     probe,
	}, fakeClient
}

func testPolicy(generation int64, rules ...ratelimitv1alpha1.Rule) *ratelimitv1alpha1.RateLimitPolicy {
	if len(rules) == 0 {
		rules = []ratelimitv1alpha1.Rule{{
			Name:  "total",
			Rates: []ratelimitv1alpha1.Rate{{Requests: 100, PeriodSeconds: 60}},
		}}
	}
	return &ratelimitv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       testDomain,
			Generation: generation,
			UID:        testUID,
		},
		Spec: ratelimitv1alpha1.RateLimitPolicySpec{
			Domain: testDomain,
			Limits: []ratelimitv1alpha1.LimitBlock{{Name: "api", Rules: rules}},
		},
	}
}

func testRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testDomain}}
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

func TestReconcile_reportsAHealthyGeneration(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, unanimous(3), testPolicy(3))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	assert.Equal(t, int64(3), stored.Status.ObservedGeneration)
	assert.Equal(t, int64(3), stored.Status.ActiveGeneration)
	assert.Equal(t, int32(1), stored.Status.Rules)
	assert.Zero(t, stored.Status.Problems)
	assert.Subset(t, stored.Status.EffectiveKeys, []string{"client", "method", "path"})

	accepted := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, metav1.ConditionTrue, accepted.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonRulesCompiled, accepted.Reason)

	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonAllReplicas, ready.Reason)

	stalled := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionStalled)
	assert.Equal(t, metav1.ConditionFalse, stalled.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonProgressing, stalled.Reason)

	assert.Equal(t, int32(3), stored.Status.Replicas.Total)
	assert.Equal(t, int32(3), stored.Status.Replicas.Applied)
	require.NotNil(t, stored.Status.Replicas.LastCheckTime)
}

// TestReconcile_asksTheFleetForTheGenerationThatRuns pins what the probe
// compares against: the generation actually enforced and the object's UID, not
// the latest generation and not a number alone.
func TestReconcile_asksTheFleetForTheGenerationThatRuns(t *testing.T) {
	probe := unanimous(1)
	reconciler, _ := newReconciler(t, probe, testPolicy(4))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	require.Len(t, probe.asked, 1)
	assert.Equal(t, int64(4), probe.asked[0].Generation)
	assert.Equal(t, string(testUID), probe.asked[0].UID)
}

func TestReconcile_isIdempotent(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, unanimous(1), testPolicy(1))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	first := fetch(t, fakeClient).ResourceVersion

	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	assert.Equal(t, first, fetch(t, fakeClient).ResourceVersion,
		"an unchanged status must not be written: the update would reconcile the object again, forever")
}

func TestReconcile_aBlockingProblemStallsTheGeneration(t *testing.T) {
	broken := testPolicy(1, ratelimitv1alpha1.Rule{
		Name:    "per-plan",
		Matches: []ratelimitv1alpha1.Predicate{{Key: "plan", Operator: ratelimitv1alpha1.OperatorExists}},
		Rates:   []ratelimitv1alpha1.Rate{{Requests: 10, PeriodSeconds: 60}},
	})
	reconciler, fakeClient := newReconciler(t, unanimous(1), broken)

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	require.Len(t, stored.Status.RuleProblems, 1)
	assert.Equal(t, ratelimitv1alpha1.ProblemUnresolvedKeyReference, stored.Status.RuleProblems[0].Reason)
	assert.Equal(t, int32(1), stored.Status.Problems)
	assert.Zero(t, stored.Status.ActiveGeneration)

	accepted := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
	assert.Equal(t, metav1.ConditionFalse, accepted.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonCompilationFailed, accepted.Reason)
	assert.Contains(t, accepted.Message, ratelimitv1alpha1.ProblemUnresolvedKeyReference,
		"the summary names the reasons; the addresses stay in ruleProblems")

	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonNotCompiled, ready.Reason)
	assert.Contains(t, ready.Message, "domain is unprotected")

	stalled := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionStalled)
	assert.Equal(t, metav1.ConditionTrue, stalled.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonNotCompiled, stalled.Reason)
}

// fakeState hands the reconciler a persisted last-good spec.
type fakeState struct {
	bundle policy.Bundle
}

func (f fakeState) Load(_ context.Context, domains []string) (map[string]policy.Bundle, error) {
	out := make(map[string]policy.Bundle, len(domains))
	for _, domain := range domains {
		out[domain] = f.bundle
	}
	return out, nil
}

func TestReconcile_reportsTheGenerationThatKeepsRunning(t *testing.T) {
	// A rejected edit costs the author an answer, never the gateway its limits:
	// the divergence of the two generations is what says so.
	good := testPolicy(1)
	broken := testPolicy(2, ratelimitv1alpha1.Rule{
		Name:    "per-plan",
		Matches: []ratelimitv1alpha1.Predicate{{Key: "plan", Operator: ratelimitv1alpha1.OperatorExists}},
		Rates:   []ratelimitv1alpha1.Rate{{Requests: 10, PeriodSeconds: 60}},
	})

	reconciler, fakeClient := newReconciler(t, unanimous(2), broken)
	reconciler.State = fakeState{bundle: policy.Bundle{
		UID: string(testUID), GoodGeneration: 1, GoodSpec: good.Spec,
	}}

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	assert.Equal(t, int64(2), stored.Status.ObservedGeneration)
	assert.Equal(t, int64(1), stored.Status.ActiveGeneration)
	assert.Equal(t, int32(1), stored.Status.Rules, "the last-good generation is the one counted")

	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, ratelimitv1alpha1.ReasonNotCompiled, ready.Reason)
	assert.Contains(t, ready.Message, "generation 1 remains enforced")
}

// TestReconcile_aFleetThatCannotBeObservedIsUnknown pins the one case where
// Ready is neither true nor false: a guess would be worse than saying so.
func TestReconcile_aFleetThatCannotBeObservedIsUnknown(t *testing.T) {
	probe := &stubProbe{err: errors.New("the EndpointSlice is unavailable")}
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(1))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stored := fetch(t, fakeClient)
	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionUnknown, ready.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonProbeFailed, ready.Reason)

	stalled := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionStalled)
	assert.Equal(t, metav1.ConditionFalse, stalled.Status,
		"a leader that cannot see the fleet has not established that anything is stuck")
	assert.Nil(t, stored.Status.Replicas.LastCheckTime,
		"a failed probe leaves the previous observation rather than inventing one")
}

// TestReconcile_withoutAProbeTheFleetIsUnobserved pins the default: a
// reconciler with nothing to ask reports ProbeFailed rather than claiming
// unanimity it never checked.
func TestReconcile_withoutAProbeTheFleetIsUnobserved(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, nil, testPolicy(1))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	ready := condition(t, fetch(t, fakeClient).Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionUnknown, ready.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonProbeFailed, ready.Reason)
}

func TestReconcile_requeuesWhileTheGenerationSpreads(t *testing.T) {
	probe := &stubProbe{view: FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-7c9d-x2k1"}}}
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(7))

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, probeInterval, result.RequeueAfter,
		"a fleet still taking up a generation converges without an event")

	stored := fetch(t, fakeClient)
	ready := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionFalse, ready.Status)
	assert.Equal(t, ratelimitv1alpha1.ReasonPropagating, ready.Reason)
	assert.Contains(t, ready.Message, "2 of 3 replicas enforce generation 7")
	assert.Contains(t, ready.Message, "ratelimit-7c9d-x2k1")

	stalled := condition(t, stored.Status.Conditions, ratelimitv1alpha1.ConditionStalled)
	assert.Equal(t, metav1.ConditionFalse, stalled.Status, "a rollout is not a breakage")
}

func TestReconcile_aHealthyGenerationNeedsNoRequeue(t *testing.T) {
	reconciler, _ := newReconciler(t, unanimous(1), testPolicy(1))

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)
}

func TestReconcile_ignoresADeletedPolicy(t *testing.T) {
	reconciler, _ := newReconciler(t, unanimous(1))

	result, err := reconciler.Reconcile(context.Background(), testRequest())

	require.NoError(t, err, "a deleted policy needs no cleanup: there are no finalizers")
	assert.Zero(t, result.RequeueAfter)
}

func TestReconcile_returnsTheErrorOfAFailedStatusWrite(t *testing.T) {
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testPolicy(1)).
		WithStatusSubresource(&ratelimitv1alpha1.RateLimitPolicy{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(
				context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption,
			) error {
				return errors.New("the API server rejected the write")
			},
		}).
		Build()
	reconciler := &RateLimitPolicyReconciler{
		Client: fakeClient, Scheme: scheme, Namespace: testNamespace, Probe: unanimous(1),
	}

	_, err := reconciler.Reconcile(context.Background(), testRequest())

	require.Error(t, err, "a lost status write must be retried, not swallowed")
	assert.Contains(t, err.Error(), "RateLimitPolicy status")
}

func TestTruncateMessage_staysWithinWhatTheAPIServerAccepts(t *testing.T) {
	message := strings.Repeat("x", maxMessageLength+100)

	truncated := truncateMessage(message)

	assert.Len(t, truncated, maxMessageLength)
	assert.True(t, strings.HasSuffix(truncated, "..."))
	assert.Equal(t, "short", truncateMessage("short"))
}

// TestJudge_walksTheReadyTable pins the whole condition table in one place: it
// is the contract Argo CD and the alert rules read.
func TestJudge_walksTheReadyTable(t *testing.T) {
	compiled := policy.Outcome{Generation: 7, ActiveGeneration: 7}
	notCompiled := policy.Outcome{
		Generation: 8, ActiveGeneration: 7, Err: errors.New("2 blocking problems"),
	}

	cases := []struct {
		name          string
		outcome       policy.Outcome
		view          FleetView
		probeErr      error
		since         time.Duration
		ready         metav1.ConditionStatus
		readyReason   string
		stalled       metav1.ConditionStatus
		stalledReason string
	}{
		{
			name:    "all ready replicas enforce the latest generation",
			outcome: compiled, view: FleetView{Total: 3, Applied: 3},
			ready: metav1.ConditionTrue, readyReason: ratelimitv1alpha1.ReasonAllReplicas,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1alpha1.ReasonProgressing,
		},
		{
			name:    "no replica has it yet",
			outcome: compiled, view: FleetView{Total: 3},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1alpha1.ReasonReconciling,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1alpha1.ReasonProgressing,
		},
		{
			name:    "some replicas have it, within the deadline",
			outcome: compiled, view: FleetView{Total: 3, Applied: 2}, since: 5 * time.Second,
			ready: metav1.ConditionFalse, readyReason: ratelimitv1alpha1.ReasonPropagating,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1alpha1.ReasonProgressing,
		},
		{
			name:    "no ready endpoint at all",
			outcome: compiled, view: FleetView{},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1alpha1.ReasonNoReplicas,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1alpha1.ReasonProgressing,
		},
		{
			name:    "a replica lags past the deadline",
			outcome: compiled, view: FleetView{Total: 3, Applied: 2}, since: propagationDeadline + time.Second,
			ready: metav1.ConditionFalse, readyReason: ratelimitv1alpha1.ReasonReplicaStale,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1alpha1.ReasonReplicaStale,
		},
		{
			name:    "the latest generation does not compile",
			outcome: notCompiled, view: FleetView{Total: 3, Applied: 3},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1alpha1.ReasonNotCompiled,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1alpha1.ReasonNotCompiled,
		},
		{
			name:    "the fleet could not be probed",
			outcome: compiled, probeErr: errors.New("unavailable"),
			ready: metav1.ConditionUnknown, readyReason: ratelimitv1alpha1.ReasonProbeFailed,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1alpha1.ReasonProgressing,
		},
		{
			name:    "a generation that does not compile outranks an unobservable fleet",
			outcome: notCompiled, probeErr: errors.New("unavailable"),
			ready: metav1.ConditionFalse, readyReason: ratelimitv1alpha1.ReasonNotCompiled,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1alpha1.ReasonNotCompiled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := judge(tc.outcome, tc.view, tc.probeErr, tc.since)

			assert.Equal(t, tc.ready, got.ready)
			assert.Equal(t, tc.readyReason, got.readyReason)
			assert.Equal(t, tc.stalled, got.stalled)
			assert.Equal(t, tc.stalledReason, got.stalledReason)
		})
	}
}

// TestJudge_notCompiledOutranksTheFleet pins the precedence: a generation that
// does not compile is stuck no matter how unanimous the replicas are about the
// one that does.
func TestJudge_notCompiledOutranksTheFleet(t *testing.T) {
	outcome := policy.Outcome{Generation: 8, ActiveGeneration: 7, Err: errors.New("1 blocking problem")}

	got := judge(outcome, FleetView{Total: 3, Applied: 3}, nil, 0)

	assert.Equal(t, ratelimitv1alpha1.ReasonNotCompiled, got.readyReason)
	assert.Equal(t, metav1.ConditionTrue, got.stalled)
}

// TestBehindMessage_namesOnlyAFewReplicas keeps the condition message a pointer
// to the pods worth looking at rather than an inventory.
func TestBehindMessage_namesOnlyAFewReplicas(t *testing.T) {
	view := FleetView{Total: 9, Applied: 4, Behind: []string{"a", "b", "c", "d", "e"}}

	message := behindMessage(policy.Outcome{ActiveGeneration: 7}, view)

	assert.Contains(t, message, "4 of 9 replicas enforce generation 7")
	assert.Contains(t, message, "a, b, c and 2 more")
	assert.NotContains(t, message, "d,")
}

// TestReadyAge_restartsTheClockOnANewGeneration pins what separates a rollout
// from a stuck one: each edit gets its own deadline.
func TestReadyAge_restartsTheClockOnANewGeneration(t *testing.T) {
	now := time.Now()
	object := testPolicy(5)
	object.Status.Conditions = []metav1.Condition{{
		Type:               ratelimitv1alpha1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             ratelimitv1alpha1.ReasonPropagating,
		LastTransitionTime: metav1.Time{Time: now.Add(-time.Hour)},
		ObservedGeneration: 5,
	}}

	assert.InDelta(t, time.Hour, readyAge(object, now), float64(time.Second))

	object.Generation = 6
	assert.Zero(t, readyAge(object, now),
		"a condition observed against an older generation restarts the clock")

	object.Status.Conditions = nil
	assert.Zero(t, readyAge(object, now))
}

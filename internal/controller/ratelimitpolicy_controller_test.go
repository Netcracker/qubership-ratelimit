package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	discoveryv1 "k8s.io/api/discovery/v1"
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

// stubProbe answers for the fleet without a network, and records what each
// observation asked for and whether it asked for a fresh round. observing,
// when set, runs inside each observation, the way a real probe spends time
// there.
type stubProbe struct {
	view FleetView
	err  error

	asked     []store.Applied
	fresh     []bool
	observing func()
}

func (s *stubProbe) Observe(_ context.Context, _ string, want store.Applied, fresh bool) (FleetView, error) {
	s.asked = append(s.asked, want)
	s.fresh = append(s.fresh, fresh)
	if s.observing != nil {
		s.observing()
	}
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
	// A stopped clock: the requeue is the whole interval only when no time
	// passed between the round and the return.
	reconciler.Now = (&fakeClock{base: time.Now()}).now

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, ProbeInterval, result.RequeueAfter,
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

// A green status is not a finished job. A replica can fall behind long after
// Ready went true — a node drains and the pod comes back on an image that
// cannot compile the current generation — and that transition touches no
// policy, so no event announces it. Only the interval catches it.
func TestReconcile_re_checksTheFleetWhileTheGenerationIsHealthy(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, unanimous(1), testPolicy(1))
	reconciler.Now = (&fakeClock{base: time.Now()}).now

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, ProbeInterval, result.RequeueAfter,
		"a replica that falls behind after the status went green produces no event")

	ready := condition(t, fetch(t, fakeClient).Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
}

func TestReconcile_ignoresADeletedPolicy(t *testing.T) {
	reconciler, _ := newReconciler(t, unanimous(1))

	result, err := reconciler.Reconcile(context.Background(), testRequest())

	require.NoError(t, err, "a deleted policy needs no cleanup: there are no finalizers")
	assert.Zero(t, result.RequeueAfter, "there is no object left to re-check")
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
			outcome: compiled, view: FleetView{Total: 3, Applied: 2}, since: DefaultPropagationDeadline + time.Second,
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
			got := judge(tc.outcome, tc.view, tc.probeErr, tc.since, 0)

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

	got := judge(outcome, FleetView{Total: 3, Applied: 3}, nil, 0, 0)

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

// The propagation clock only counts time spent propagating. LastTransitionTime
// moves when the condition's status changes, not when its reason does, so a
// deployment that sat at NoReplicas overnight carries an hours-old stamp into
// its first probe. Counting that as propagation would report ReplicaStale, and
// Stalled with it, on a perfectly ordinary start.
func TestReadyAge_restartsTheClockWhenPropagationBegins(t *testing.T) {
	now := time.Now()
	object := testPolicy(5)
	stampedAnHourAgo := func(reason string) {
		object.Status.Conditions = []metav1.Condition{{
			Type:               ratelimitv1alpha1.ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			LastTransitionTime: metav1.Time{Time: now.Add(-time.Hour)},
			ObservedGeneration: 5,
		}}
	}

	for _, reason := range []string{
		ratelimitv1alpha1.ReasonNoReplicas,
		ratelimitv1alpha1.ReasonProbeFailed,
		ratelimitv1alpha1.ReasonAllReplicas,
		ratelimitv1alpha1.ReasonNotCompiled,
	} {
		stampedAnHourAgo(reason)
		assert.Zero(t, readyAge(object, now), "%s is not time spent propagating", reason)
	}

	for _, reason := range []string{
		ratelimitv1alpha1.ReasonReconciling,
		ratelimitv1alpha1.ReasonPropagating,
		ratelimitv1alpha1.ReasonReplicaStale,
	} {
		stampedAnHourAgo(reason)
		assert.InDelta(t, time.Hour, readyAge(object, now), float64(time.Second),
			"%s is time this generation spent spreading", reason)
	}
}

// A replica that says nothing is a different diagnosis from one that answers
// with an old generation, and the message has to keep them apart: the first
// points at the metrics port, the second at a rollout in flight.
func TestReconcile_namesSilentReplicasApartFromLaggingOnes(t *testing.T) {
	probe := &stubProbe{view: FleetView{
		Total: 4, Applied: 2,
		Behind: []string{"ratelimit-lagging"},
		Silent: []string{"ratelimit-quiet"},
	}}
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(7))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	ready := condition(t, fetch(t, fakeClient).Status.Conditions, ratelimitv1alpha1.ConditionReady)
	assert.Contains(t, ready.Message, "ratelimit-lagging report another")
	assert.Contains(t, ready.Message, "ratelimit-quiet did not answer")
}

// LastCheckTime documents the freshness of the probe, and an operator reads a
// stale one as a dead leader. A steady green status changes nothing else, so
// without a coarse refresh the field would stand still while the leader kept
// probing.
func TestReconcile_refreshesTheProbeTimeOnceItLooksStale(t *testing.T) {
	object := testPolicy(1)
	reconciler, fakeClient := newReconciler(t, unanimous(1), object)

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	first := fetch(t, fakeClient).Status.Replicas.LastCheckTime
	require.NotNil(t, first)

	// Nothing moved, so the second pass leaves the stamp alone rather than
	// writing the object on every probe.
	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.Equal(t, first, fetch(t, fakeClient).Status.Replicas.LastCheckTime,
		"an unchanged status must not write once per probe")

	// Aged past the bound, the stamp is refreshed even though nothing else did.
	stored := fetch(t, fakeClient)
	stored.Status.Replicas.LastCheckTime = &metav1.Time{Time: time.Now().Add(-2 * lastCheckMaxAge)}
	require.NoError(t, fakeClient.Status().Update(context.Background(), stored))

	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), fetch(t, fakeClient).Status.Replicas.LastCheckTime.Time, time.Minute,
		"a leader that keeps probing keeps the field it publishes honest")
}

// The watch is what makes scaling visible: a pod joining or leaving changes the
// denominator of Ready without touching any policy.
func TestPoliciesBehind_mapsTheFleetsOwnSliceToEveryPolicy(t *testing.T) {
	reconciler, _ := newReconciler(t, unanimous(1), testPolicy(1))
	reconciler.Service = "ratelimit"

	slice := func(service string) client.Object {
		return &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      service + "-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: service},
		}}
	}

	requests := reconciler.policiesBehind(context.Background(), slice("ratelimit"))
	require.Len(t, requests, 1)
	assert.Equal(t, testRequest().NamespacedName, requests[0].NamespacedName)

	assert.Empty(t, reconciler.policiesBehind(context.Background(), slice("some-other-service")),
		"another Service's endpoints say nothing about who enforces these rules")

	reconciler.Service = ""
	assert.Empty(t, reconciler.policiesBehind(context.Background(), slice("ratelimit")),
		"without a Service name there is no fleet to recognize")
}

// The propagation clock has to survive a second probe. meta.SetStatusCondition
// moves LastTransitionTime only when the status changes, and both ways into a
// rollout hold Ready at False — so without setReadyCondition rewinding it, the
// probe after the first one reads a stamp as old as whatever came before and
// reports ReplicaStale with Stalled true.
//
// The status write of the first probe is itself an event on the policy, so the
// second probe arrives at once rather than in ProbeInterval. That is what makes
// this reachable rather than theoretical.
func TestReconcile_aSecondProbeStaysPropagatingAfterAnOutage(t *testing.T) {
	object := testPolicy(7)
	object.Status.Conditions = []metav1.Condition{{
		Type:               ratelimitv1alpha1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             ratelimitv1alpha1.ReasonNoReplicas,
		LastTransitionTime: metav1.Time{Time: time.Now().Add(-time.Hour)},
		ObservedGeneration: 7,
	}}
	probe := &stubProbe{view: FleetView{Total: 2, Applied: 1, Behind: []string{"ratelimit-b"}}}
	reconciler, fakeClient := newReconciler(t, probe, object)

	requireProbeReports(t, reconciler, fakeClient, ratelimitv1alpha1.ReasonPropagating,
		"the first probe after an outage is the start of a rollout, not an hour into one")
	requireProbeReports(t, reconciler, fakeClient, ratelimitv1alpha1.ReasonPropagating,
		"the second probe read a stamp from before this rollout began")
}

// The reconciler asks the fleet afresh only when it reacts to a generation it
// has not observed: a round taken before the edit would report the replicas
// behind a change they may have applied since, and a round reused between
// edits keeps the fleet's cost at one round per cycle.
func TestReconcile_asksForAFreshRoundOnANewGenerationOnly(t *testing.T) {
	cases := []struct {
		name     string
		observed int64
		fresh    bool
	}{
		{"a generation not yet observed", 6, true},
		{"the generation already observed", 7, false},
		{"a policy never reconciled", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			object := testPolicy(7)
			object.Status.ObservedGeneration = tc.observed
			probe := unanimous(2)
			reconciler, _ := newReconciler(t, probe, object)

			_, err := reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)

			require.Len(t, probe.fresh, 1)
			assert.Equal(t, tc.fresh, probe.fresh[0], "fresh for generation 7 with %d observed", tc.observed)
		})
	}
}

// A reconcile requeues for the moment the probe stops answering from the
// round it used, not for one interval after the round was taken: a round
// that completed late is reused past that mark, and a look scheduled by the
// round's age alone would be answered from the same round again, once a
// second, until it expired. A view that names no expiry is treated as
// expiring one interval after the fleet was asked; a round about to expire
// waits one second rather than nothing.
func TestReconcile_requeuesForWhenTheRoundStopsBeingReused(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		view FleetView
		wait time.Duration
	}{
		{"a round reused for four more seconds", FleetView{At: now, RefreshAt: now.Add(4 * time.Second)}, 4 * time.Second},
		{"a round taken ten seconds ago and reused for two more",
			FleetView{At: now.Add(-10 * time.Second), RefreshAt: now.Add(2 * time.Second)}, 2 * time.Second},
		{"a view without an expiry, taken now", FleetView{At: now}, ProbeInterval},
		{"a view without an expiry, taken four seconds ago", FleetView{At: now.Add(-4 * time.Second)}, ProbeInterval - 4*time.Second},
		{"a round about to expire", FleetView{At: now, RefreshAt: now.Add(200 * time.Millisecond)}, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := unanimous(2)
			probe.view.At, probe.view.RefreshAt = tc.view.At, tc.view.RefreshAt
			reconciler, _ := newReconciler(t, probe, testPolicy(7))
			reconciler.Now = (&fakeClock{base: now}).now

			result, err := reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)

			assert.Equal(t, tc.wait, result.RequeueAfter, "RequeueAfter for %s", tc.name)
		})
	}
}

// The requeue counts from the return of the reconcile, so the wait until the
// round turns one interval old is measured after the probe, not before it: a
// probe that spent four seconds waiting for a round leaves six, not ten.
func TestReconcile_countsTheRequeueFromAfterTheProbe(t *testing.T) {
	clock := &fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	probe := unanimous(2)
	probe.observing = func() { clock.advance(4 * time.Second) }
	reconciler, _ := newReconciler(t, probe, testPolicy(7))
	reconciler.Now = clock.now

	result, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	assert.Equal(t, ProbeInterval-4*time.Second, result.RequeueAfter,
		"RequeueAfter after a probe that took four seconds of a round taken at its start")
}

// lastCheckTime is the time the fleet was asked, which for a status built
// from a reused round is earlier than the write: the field is the freshness
// of the answers.
func TestReconcile_stampsTheTimeTheFleetWasAsked(t *testing.T) {
	probe := unanimous(2)
	asked := time.Now().Add(-4 * time.Second)
	probe.view.At = asked
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(7))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stamped := fetch(t, fakeClient).Status.Replicas.LastCheckTime
	require.NotNil(t, stamped)
	assert.WithinDuration(t, asked, stamped.Time, time.Second, "lastCheckTime against the time the fleet was asked")
}

// The everyday path: a broken policy is fixed, and one replica lags by a
// second. Ready goes NotCompiled to Propagating, False to False again, so the
// day-old stamp of the breakage would carry into the rollout that repairs it.
func TestReconcile_aSecondProbeStaysPropagatingAfterAFixedGeneration(t *testing.T) {
	object := testPolicy(6)
	object.Status.Conditions = []metav1.Condition{{
		Type:               ratelimitv1alpha1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             ratelimitv1alpha1.ReasonNotCompiled,
		LastTransitionTime: metav1.Time{Time: time.Now().Add(-24 * time.Hour)},
		ObservedGeneration: 5,
	}}
	probe := &stubProbe{view: FleetView{Total: 2, Applied: 1, Behind: []string{"ratelimit-b"}}}
	reconciler, fakeClient := newReconciler(t, probe, object)

	requireProbeReports(t, reconciler, fakeClient, ratelimitv1alpha1.ReasonPropagating,
		"a generation that now compiles starts its own rollout")
	requireProbeReports(t, reconciler, fakeClient, ratelimitv1alpha1.ReasonPropagating,
		"the second probe inherited the stamp of the generation that was broken")
}

// Time genuinely spent propagating still ends in ReplicaStale, which is what
// the deadline is for: the rewind must not make the condition unreachable.
func TestReconcile_aRolloutPastTheDeadlineIsStale(t *testing.T) {
	object := testPolicy(7)
	object.Status.Conditions = []metav1.Condition{{
		Type:               ratelimitv1alpha1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             ratelimitv1alpha1.ReasonPropagating,
		LastTransitionTime: metav1.Time{Time: time.Now().Add(-DefaultPropagationDeadline - time.Minute)},
		ObservedGeneration: 7,
	}}
	probe := &stubProbe{view: FleetView{Total: 2, Applied: 1, Behind: []string{"ratelimit-b"}}}
	reconciler, fakeClient := newReconciler(t, probe, object)

	requireProbeReports(t, reconciler, fakeClient, ratelimitv1alpha1.ReasonReplicaStale,
		"a replica lagging past the deadline is what Stalled exists to page on")
	stalled := condition(t, fetch(t, fakeClient).Status.Conditions, ratelimitv1alpha1.ConditionStalled)
	assert.Equal(t, metav1.ConditionTrue, stalled.Status)
}

// requireProbeReports runs one reconcile and asserts the Ready reason it wrote.
func requireProbeReports(
	t *testing.T,
	reconciler *RateLimitPolicyReconciler,
	fakeClient client.Client,
	reason, because string,
) {
	t.Helper()

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	ready := condition(t, fetch(t, fakeClient).Status.Conditions, ratelimitv1alpha1.ConditionReady)
	require.Equal(t, reason, ready.Reason, because)
}

// The two reasons of the split.
func TestJudge_aRefusingReplicaIsFormatUnsupportedNotStale(t *testing.T) {
	compiled := policy.Outcome{Generation: 7, ActiveGeneration: 7}
	view := FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-c"}, Refusing: []string{"ratelimit-c"}}

	// Well past the deadline, which would otherwise be ReplicaStale: the
	// refusal is the cause and gets named, the lag is the symptom.
	got := judge(compiled, view, nil, time.Hour, 0)
	assert.Equal(t, metav1.ConditionFalse, got.ready)
	assert.Equal(t, ratelimitv1alpha1.ReasonReplicaFormatUnsupported, got.readyReason)
	assert.Equal(t, metav1.ConditionTrue, got.stalled)
	assert.Equal(t, ratelimitv1alpha1.ReasonReplicaFormatUnsupported, got.stalledReason)
	assert.Contains(t, got.readyMessage, "ratelimit-c")
	assert.Contains(t, got.readyMessage, "upgrade the service before the operator")
}

func TestJudge_aGenerationThatDoesNotFitIsTooLargeNotNotCompiled(t *testing.T) {
	// It compiles: Err is nil. It does not fit: the last-good generation is
	// the active one. The reason has to say the second, because the fix is
	// not the spec.
	outcome := policy.Outcome{Generation: 8, ActiveGeneration: 7, TooLarge: true,
		TooLargeReason: "the namespace's configuration would be 1100000 bytes compressed, over the limit of 1048576"}

	got := judge(outcome, FleetView{Total: 3, Applied: 3}, nil, 0, 0)
	assert.Equal(t, metav1.ConditionFalse, got.ready)
	assert.Equal(t, ratelimitv1alpha1.ReasonConfigMapTooLarge, got.readyReason)
	assert.Equal(t, metav1.ConditionTrue, got.stalled)
	assert.Equal(t, ratelimitv1alpha1.ReasonConfigMapTooLarge, got.stalledReason)
	assert.Contains(t, got.readyMessage, "generation 7 keeps serving")

	// And a generation that does not compile stays NotCompiled whatever its
	// size: the spec is the fix there.
	broken := outcome
	broken.Err = errors.New("1 blocking problem (InvalidWindow)")
	got = judge(broken, FleetView{Total: 3, Applied: 3}, nil, 0, 0)
	assert.Equal(t, ratelimitv1alpha1.ReasonNotCompiled, got.readyReason)
}

func TestJudge_honorsTheConfiguredDeadline(t *testing.T) {
	compiled := policy.Outcome{Generation: 7, ActiveGeneration: 7}
	lagging := FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-c"}}

	// 45 s: stale under the one-binary deadline, propagating under the
	// split's, where the kubelet takes up to a minute to project a change.
	got := judge(compiled, lagging, nil, 45*time.Second, 0)
	assert.Equal(t, ratelimitv1alpha1.ReasonReplicaStale, got.readyReason)
	got = judge(compiled, lagging, nil, 45*time.Second, SplitPropagationDeadline)
	assert.Equal(t, ratelimitv1alpha1.ReasonPropagating, got.readyReason)
	got = judge(compiled, lagging, nil, SplitPropagationDeadline+time.Second, SplitPropagationDeadline)
	assert.Equal(t, ratelimitv1alpha1.ReasonReplicaStale, got.readyReason)
}

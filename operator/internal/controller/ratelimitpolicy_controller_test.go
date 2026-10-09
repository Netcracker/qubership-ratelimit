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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	ratelimitv1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/operator/internal/policy"
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
	require.NoError(t, ratelimitv1.AddToScheme(s))
	return s
}

// fakeClientWith builds a client that gives the policy a status subresource.
// Without that the fake client writes status into the object itself, and a
// reconciler that only meant to touch status would come back having rewritten
// the spec.
func fakeClientWith(t *testing.T, objects ...client.Object) (client.WithWatch, *runtime.Scheme) {
	t.Helper()
	scheme := testScheme(t)
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objects...).
		WithStatusSubresource(&ratelimitv1.RateLimitPolicy{}).
		Build()
	return fakeClient, scheme
}

// stubProbe answers every observation with view, or fails it with err, and
// records whether each observation asked for a fresh round. observing, when
// set, runs inside each observation, the way a real probe spends time there.
type stubProbe struct {
	view FleetView
	err  error

	fresh     []bool
	observing func()
}

func (s *stubProbe) Observe(_ context.Context, _ string, _ applied.Domain, fresh bool) (FleetView, error) {
	s.fresh = append(s.fresh, fresh)
	if s.observing != nil {
		s.observing()
	}
	if s.err != nil {
		return FleetView{}, s.err
	}
	return s.view, nil
}

// unanimous is the healthy fleet: every ready replica on whatever generation
// it is asked about.
func unanimous(replicas int32) *stubProbe {
	return &stubProbe{view: FleetView{Total: replicas, Applied: replicas}}
}

// enforcingFleet is a fleet whose every replica enforces one generation of
// one object. An observation that asks about another generation, or about the
// same generation of another object, finds every replica behind.
type enforcingFleet struct {
	replicas int32
	enforced applied.Domain
}

func (f enforcingFleet) Observe(_ context.Context, _ string, want applied.Domain, _ bool) (FleetView, error) {
	if want.Generation == f.enforced.Generation && want.UID == f.enforced.UID {
		return FleetView{Total: f.replicas, Applied: f.replicas}, nil
	}
	return FleetView{Total: f.replicas}, nil
}

// newReconciler builds a reconciler of testNamespace over a fake client that
// holds objects. A reconcile publishes the series of its domain into the
// process-wide metrics, so the series of testDomain are dropped when the test
// ends.
func newReconciler(t *testing.T, probe FleetObserver, objects ...client.Object) (
	*RateLimitPolicyReconciler, client.WithWatch,
) {
	t.Helper()
	t.Cleanup(func() {
		metrics.DropFleet(testDomain)
		metrics.DropPolicy(testDomain)
	})
	fakeClient, scheme := fakeClientWith(t, objects...)
	return &RateLimitPolicyReconciler{
		Client:    fakeClient,
		Scheme:    scheme,
		Namespace: testNamespace,
		Probe:     probe,
	}, fakeClient
}

func testPolicy(generation int64, rules ...ratelimitv1.Rule) *ratelimitv1.RateLimitPolicy {
	if len(rules) == 0 {
		rules = []ratelimitv1.Rule{{
			Name:  "total",
			Rates: []ratelimitv1.Rate{{Requests: 100, PeriodSeconds: 60}},
		}}
	}
	return &ratelimitv1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       testDomain,
			Generation: generation,
			UID:        testUID,
		},
		Spec: ratelimitv1.RateLimitPolicySpec{
			Domain: testDomain,
			Limits: []ratelimitv1.LimitBlock{{Name: "api", Rules: rules}},
		},
	}
}

// withReady gives object a False Ready condition of reason, observed for
// observedGeneration and last moved at transition.
func withReady(
	object *ratelimitv1.RateLimitPolicy, reason string, transition time.Time, observedGeneration int64,
) *ratelimitv1.RateLimitPolicy {
	object.Status.Conditions = []metav1.Condition{{
		Type:               ratelimitv1.ConditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		LastTransitionTime: metav1.Time{Time: transition},
		ObservedGeneration: observedGeneration,
	}}
	return object
}

func testRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testDomain}}
}

func fetch(t *testing.T, c client.Client) *ratelimitv1.RateLimitPolicy {
	t.Helper()
	var object ratelimitv1.RateLimitPolicy
	require.NoError(t, c.Get(context.Background(), testRequest().NamespacedName, &object))
	return &object
}

// verdict is what a condition states: its status and its reason.
type verdict struct {
	Status metav1.ConditionStatus
	Reason string
}

// verdicts maps the type of each condition to its verdict. A type with no
// condition maps to the zero verdict.
func verdicts(conditions []metav1.Condition) map[string]verdict {
	out := make(map[string]verdict, len(conditions))
	for _, c := range conditions {
		out[c.Type] = verdict{Status: c.Status, Reason: c.Reason}
	}
	return out
}

// condition returns the condition of conditionType, and fails the test when
// there is none.
func condition(t *testing.T, conditions []metav1.Condition, conditionType string) *metav1.Condition {
	t.Helper()
	found := meta.FindStatusCondition(conditions, conditionType)
	require.NotNil(t, found, "condition %s is missing", conditionType)
	return found
}

// readyReasonAfterReconcile runs one reconcile and returns the reason of the
// Ready condition it wrote.
func readyReasonAfterReconcile(t *testing.T, reconciler *RateLimitPolicyReconciler, c client.Client) string {
	t.Helper()
	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	return condition(t, fetch(t, c).Status.Conditions, ratelimitv1.ConditionReady).Reason
}

func TestReconcile_reportsAHealthyGeneration(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, unanimous(3), testPolicy(3))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	status := fetch(t, fakeClient).Status
	assert.Equal(t, int64(3), status.ObservedGeneration, "status.observedGeneration")
	assert.Equal(t, int64(3), status.ActiveGeneration, "status.activeGeneration")
	assert.Equal(t, int32(1), status.Rules, "status.rules")
	assert.Zero(t, status.Problems, "status.problems")
	assert.Subset(t, status.EffectiveKeys, []string{"method", "path", "sub"}, "status.effectiveKeys")
	conditions := verdicts(status.Conditions)
	assert.Equal(t, verdict{metav1.ConditionTrue, ratelimitv1.ReasonRulesCompiled},
		conditions[ratelimitv1.ConditionAccepted], "Accepted")
	assert.Equal(t, verdict{metav1.ConditionTrue, ratelimitv1.ReasonAllReplicas},
		conditions[ratelimitv1.ConditionReady], "Ready")
	assert.Equal(t, verdict{metav1.ConditionFalse, ratelimitv1.ReasonProgressing},
		conditions[ratelimitv1.ConditionStalled], "Stalled")
	assert.Equal(t, int32(3), status.Replicas.Total, "status.replicas.total")
	assert.Equal(t, int32(3), status.Replicas.Applied, "status.replicas.applied")
	assert.NotNil(t, status.Replicas.LastCheckTime, "status.replicas.lastCheckTime")
}

// The fleet is asked about the enforced generation together with the object's
// UID, because a generation number alone is ambiguous across a delete and
// recreate: a fresh object starts at generation 1 too. While a last-good
// generation serves, the enforced generation is that one, not the latest.
func TestReconcile_asksTheFleetForTheGenerationThatRuns(t *testing.T) {
	brokenLatest := testPolicy(5, ratelimitv1.Rule{
		Name:    "per-plan",
		Matches: []ratelimitv1.Predicate{{Key: "plan", Operator: ratelimitv1.OperatorExists}},
		Rates:   []ratelimitv1.Rate{{Requests: 10, PeriodSeconds: 60}},
	})
	tests := []struct {
		name   string
		object *ratelimitv1.RateLimitPolicy
		state  StateReader
	}{
		{"the latest generation 4, which compiles", testPolicy(4), nil},
		{
			"the last-good generation 4 under a latest generation 5 that does not compile", brokenLatest,
			fakeState{bundle: policy.Bundle{UID: string(testUID), GoodGeneration: 4, GoodSpec: testPolicy(4).Spec}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcing := enforcingFleet{replicas: 2, enforced: applied.Domain{Generation: 4, UID: string(testUID)}}
			reconciler, fakeClient := newReconciler(t, enforcing, tt.object)
			reconciler.State = tt.state

			_, err := reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)

			assert.Equal(t, int32(2), fetch(t, fakeClient).Status.Replicas.Applied,
				"status.replicas.applied of a fleet that enforces generation 4 of %s", testUID)
		})
	}
}

// A status write comes back as an event on the policy, so writing an
// unchanged status would reconcile the object again, forever. The probe time
// is part of what stays: stamping it on every probe would write the object
// once per interval.
func TestReconcile_aSecondReconcileOfAnUnchangedPolicyWritesNothing(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, unanimous(1), testPolicy(1))
	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	first := fetch(t, fakeClient)

	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	second := fetch(t, fakeClient)
	assert.Equal(t, first.ResourceVersion, second.ResourceVersion, "resourceVersion after the second Reconcile")
	assert.Equal(t, first.Status.Replicas.LastCheckTime, second.Status.Replicas.LastCheckTime,
		"status.replicas.lastCheckTime after the second Reconcile")
}

func TestReconcile_aBlockingProblemStallsTheGeneration(t *testing.T) {
	broken := testPolicy(1, ratelimitv1.Rule{
		Name:    "per-plan",
		Matches: []ratelimitv1.Predicate{{Key: "plan", Operator: ratelimitv1.OperatorExists}},
		Rates:   []ratelimitv1.Rate{{Requests: 10, PeriodSeconds: 60}},
	})
	reconciler, fakeClient := newReconciler(t, unanimous(1), broken)

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	status := fetch(t, fakeClient).Status
	require.Len(t, status.RuleProblems, 1, "status.ruleProblems")
	assert.Equal(t, ratelimitv1.ProblemUnresolvedKeyReference, status.RuleProblems[0].Reason,
		"status.ruleProblems[0].reason")
	assert.Equal(t, int32(1), status.Problems, "status.problems")
	assert.Zero(t, status.ActiveGeneration, "status.activeGeneration")
	conditions := verdicts(status.Conditions)
	assert.Equal(t, verdict{metav1.ConditionFalse, ratelimitv1.ReasonCompilationFailed},
		conditions[ratelimitv1.ConditionAccepted], "Accepted")
	assert.Equal(t, verdict{metav1.ConditionFalse, ratelimitv1.ReasonNotCompiled},
		conditions[ratelimitv1.ConditionReady], "Ready")
	assert.Equal(t, verdict{metav1.ConditionTrue, ratelimitv1.ReasonNotCompiled},
		conditions[ratelimitv1.ConditionStalled], "Stalled")
	assert.Contains(t, condition(t, status.Conditions, ratelimitv1.ConditionAccepted).Message,
		ratelimitv1.ProblemUnresolvedKeyReference, "the message of Accepted")
	assert.Equal(t, "no generation is enforced: domain is unprotected",
		condition(t, status.Conditions, ratelimitv1.ConditionReady).Message, "the message of Ready")
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

// A rejected edit costs the author an answer, never the gateway its limits:
// the status reports the last-good generation as the active one, and counts
// its rules. The two generations carry a different number of rules, so the
// count shows which one it was taken from.
func TestReconcile_reportsTheGenerationThatKeepsRunning(t *testing.T) {
	good := testPolicy(1,
		ratelimitv1.Rule{Name: "total", Rates: []ratelimitv1.Rate{{Requests: 100, PeriodSeconds: 60}}},
		ratelimitv1.Rule{Name: "burst", Rates: []ratelimitv1.Rate{{Requests: 10, PeriodSeconds: 1}}},
	)
	broken := testPolicy(2, ratelimitv1.Rule{
		Name:    "per-plan",
		Matches: []ratelimitv1.Predicate{{Key: "plan", Operator: ratelimitv1.OperatorExists}},
		Rates:   []ratelimitv1.Rate{{Requests: 10, PeriodSeconds: 60}},
	})
	reconciler, fakeClient := newReconciler(t, unanimous(2), broken)
	reconciler.State = fakeState{bundle: policy.Bundle{
		UID: string(testUID), GoodGeneration: 1, GoodSpec: good.Spec,
	}}

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	status := fetch(t, fakeClient).Status
	assert.Equal(t, int64(2), status.ObservedGeneration, "status.observedGeneration")
	assert.Equal(t, int64(1), status.ActiveGeneration, "status.activeGeneration")
	assert.Equal(t, int32(2), status.Rules, "status.rules")
	ready := condition(t, status.Conditions, ratelimitv1.ConditionReady)
	assert.Equal(t, ratelimitv1.ReasonNotCompiled, ready.Reason, "the reason of Ready")
	assert.Contains(t, ready.Message, "generation 1 remains enforced", "the message of Ready")
}

// A leader that cannot see the fleet knows neither that the domain is stuck
// nor that it is not, so both conditions are Unknown, the one case where Ready
// is neither true nor false. It leaves lastCheckTime unset rather than stamp
// an observation it never made.
func TestReconcile_aFleetThatCannotBeObservedIsUnknown(t *testing.T) {
	probe := &stubProbe{err: errors.New("the EndpointSlice is unavailable")}
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(1))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	status := fetch(t, fakeClient).Status
	conditions := verdicts(status.Conditions)
	assert.Equal(t, verdict{metav1.ConditionUnknown, ratelimitv1.ReasonProbeFailed},
		conditions[ratelimitv1.ConditionReady], "Ready")
	assert.Equal(t, verdict{metav1.ConditionUnknown, ratelimitv1.ReasonProbeFailed},
		conditions[ratelimitv1.ConditionStalled], "Stalled")
	assert.Nil(t, status.Replicas.LastCheckTime, "status.replicas.lastCheckTime")
}

// A domain that was stuck stays stuck in ratelimit_policy_stalled while the
// fleet cannot be observed, across more than one failed probe, so the alert on
// it does not clear.
func TestReconcile_anUnobservableFleetKeepsTheLastStalledSample(t *testing.T) {
	probe := &stubProbe{err: errors.New("the EndpointSlice is unavailable")}
	reconciler, _ := newReconciler(t, probe, testPolicy(1))
	metrics.PublishFleet(testDomain, metrics.FleetSample{Total: 3, Applied: 2, Stalled: true,
		Reason: ratelimitv1.ReasonReplicaStale})

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)
	_, err = reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	sample, ok := metrics.PublishedFleet(testDomain)
	require.True(t, ok, "PublishedFleet(%q)", testDomain)
	assert.True(t, sample.Stalled, "the stalled sample after two failed probes")
	assert.Equal(t, ratelimitv1.ReasonReplicaStale, sample.Reason, "the reason of the sample after two failed probes")
}

// A domain whose first probe fails has no sample to keep, and publishes
// Progressing at 0: a fleet nobody has seen stuck does not raise the alert.
func TestReconcile_aFirstFailedProbePublishesProgressing(t *testing.T) {
	probe := &stubProbe{err: errors.New("the EndpointSlice is unavailable")}
	reconciler, _ := newReconciler(t, probe, testPolicy(1))
	metrics.DropFleet(testDomain)

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	sample, ok := metrics.PublishedFleet(testDomain)
	require.True(t, ok, "PublishedFleet(%q)", testDomain)
	assert.False(t, sample.Stalled, "the stalled sample")
	assert.Equal(t, ratelimitv1.ReasonProgressing, sample.Reason, "the reason of the sample")
}

// A reconciler with nothing to ask reports ProbeFailed rather than claiming
// unanimity it never checked.
func TestReconcile_withoutAProbeTheFleetIsUnobserved(t *testing.T) {
	reconciler, fakeClient := newReconciler(t, nil, testPolicy(1))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	assert.Equal(t, verdict{metav1.ConditionUnknown, ratelimitv1.ReasonProbeFailed},
		verdicts(fetch(t, fakeClient).Status.Conditions)[ratelimitv1.ConditionReady], "Ready")
}

// A reconcile requeues for its next look at the fleet whatever it found. A
// replica can fall behind long after Ready went true, when a node drains and
// the pod comes back on an image that cannot compile the current generation,
// and that transition touches no policy, so no event announces it. The clock
// stands still, so the round the stub answers from is a whole interval away
// from expiring.
func TestReconcile_requeuesForTheNextProbeWhateverTheVerdict(t *testing.T) {
	cases := []struct {
		name   string
		view   FleetView
		reason string
	}{
		{
			name:   "a generation still spreading",
			view:   FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-7c9d-x2k1"}},
			reason: ratelimitv1.ReasonPropagating,
		},
		{
			name:   "a healthy generation",
			view:   FleetView{Total: 1, Applied: 1},
			reason: ratelimitv1.ReasonAllReplicas,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler, fakeClient := newReconciler(t, &stubProbe{view: tc.view}, testPolicy(7))
			reconciler.Now = (&fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}).now

			result, err := reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)

			ready := verdicts(fetch(t, fakeClient).Status.Conditions)[ratelimitv1.ConditionReady]
			assert.Equal(t, tc.reason, ready.Reason, "the reason of Ready for %+v", tc.view)
			assert.Equal(t, ProbeInterval, result.RequeueAfter, "RequeueAfter for %+v", tc.view)
		})
	}
}

// A rollout in progress is not a breakage: Ready is False with Propagating and
// names the replica that is behind, and Stalled stays False.
func TestReconcile_reportsAGenerationStillSpreadingAsPropagating(t *testing.T) {
	probe := &stubProbe{view: FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-7c9d-x2k1"}}}
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(7))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	status := fetch(t, fakeClient).Status
	conditions := verdicts(status.Conditions)
	assert.Equal(t, verdict{metav1.ConditionFalse, ratelimitv1.ReasonPropagating},
		conditions[ratelimitv1.ConditionReady], "Ready")
	assert.Equal(t, verdict{metav1.ConditionFalse, ratelimitv1.ReasonProgressing},
		conditions[ratelimitv1.ConditionStalled], "Stalled")
	ready := condition(t, status.Conditions, ratelimitv1.ConditionReady)
	assert.Contains(t, ready.Message, "2 of 3 replicas enforce generation 7", "the message of Ready")
	assert.Contains(t, ready.Message, "ratelimit-7c9d-x2k1", "the message of Ready")
}

// A deleted policy needs no cleanup, since there are no finalizers, and there
// is no object left to look at again.
func TestReconcile_aDeletedPolicyIsNotRequeued(t *testing.T) {
	reconciler, _ := newReconciler(t, unanimous(1))

	result, err := reconciler.Reconcile(context.Background(), testRequest())

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

// A status write that fails is returned, so the workqueue retries it with
// backoff rather than losing it.
func TestReconcile_returnsTheErrorOfAFailedStatusWrite(t *testing.T) {
	rejected := errors.New("the API server rejected the write")
	reconciler, fakeClient := newReconciler(t, unanimous(1), testPolicy(1))
	reconciler.Client = interceptor.NewClient(fakeClient, interceptor.Funcs{
		SubResourceUpdate: func(
			context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption,
		) error {
			return rejected
		},
	})

	_, err := reconciler.Reconcile(context.Background(), testRequest())

	assert.ErrorIs(t, err, rejected)
}

// A condition message past the limit of the API server, by one byte or more, is
// cut to the limit and ends with an ellipsis.
func TestTruncateMessage_cutsAMessagePastTheAPIServerLimit(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"a hundred bytes past the limit", maxMessageLength + 100},
		{"one byte past the limit", maxMessageLength + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncated := truncateMessage(strings.Repeat("x", tt.length))

			require.Equal(t, maxMessageLength, len(truncated), "length of truncateMessage(%d bytes)", tt.length)
			assert.Equal(t, "...", truncated[maxMessageLength-3:], "the end of the cut message of %d bytes", tt.length)
		})
	}
}

func TestTruncateMessage_leavesAMessageWithinTheLimitWhole(t *testing.T) {
	assert.Equal(t, "short", truncateMessage("short"))
}

// A message of exactly the limit is one the API server accepts, and it reaches
// the condition whole. It ends in "end", which a cut would replace with the
// ellipsis.
func TestTruncateMessage_leavesAMessageOfExactlyTheLimitWhole(t *testing.T) {
	message := strings.Repeat("x", maxMessageLength-3) + "end"

	kept := truncateMessage(message)

	require.Equal(t, maxMessageLength, len(kept), "length of truncateMessage(%d bytes)", len(message))
	assert.Equal(t, "end", kept[maxMessageLength-3:], "the end of truncateMessage(%d bytes)", len(message))
}

// The message of a domain with nothing enforced says why its last-good
// generation is not in effect either, when it had one.
func TestNotCompiledMessage_namesALostLastGood(t *testing.T) {
	cases := []struct {
		name    string
		outcome policy.Outcome
		want    string
	}{
		{
			name: "a last-good generation this build does not compile",
			outcome: policy.Outcome{Generation: 3, Err: errors.New("1 blocking problem"),
				LastGoodLost: "last-good generation 2 does not compile with this operator build: " +
					"1 blocking problem (InvalidWindow)"},
			want: "no generation is enforced: domain is unprotected; " +
				"last-good generation 2 does not compile with this operator build: 1 blocking problem (InvalidWindow)",
		},
		{
			name:    "no last-good generation",
			outcome: policy.Outcome{Generation: 1, Err: errors.New("1 blocking problem")},
			want:    "no generation is enforced: domain is unprotected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, notCompiledMessage(tc.outcome))
		})
	}
}

// A generation that does not fit leaves the domain unprotected the same way,
// and its message names a lost last-good generation too.
func TestTooLargeMessage_namesALostLastGood(t *testing.T) {
	cases := []struct {
		name    string
		outcome policy.Outcome
		want    string
	}{
		{
			name: "a last-good generation this build does not compile",
			outcome: policy.Outcome{Generation: 3, TooLarge: true,
				TooLargeReason: "the namespace's configuration would be 1100000 bytes compressed, " +
					"over the limit of 1048576",
				LastGoodLost: "last-good generation 2 does not compile with this operator build: " +
					"1 blocking problem (InvalidWindow)"},
			want: "generation 3 does not fit the namespace's ConfigMap and nothing is enforced: " +
				"the namespace's configuration would be 1100000 bytes compressed, over the limit of 1048576; " +
				"last-good generation 2 does not compile with this operator build: 1 blocking problem (InvalidWindow)",
		},
		{
			name: "no last-good generation",
			outcome: policy.Outcome{Generation: 3, TooLarge: true,
				TooLargeReason: "the namespace's configuration would be 1100000 bytes compressed, " +
					"over the limit of 1048576"},
			want: "generation 3 does not fit the namespace's ConfigMap and nothing is enforced: " +
				"the namespace's configuration would be 1100000 bytes compressed, over the limit of 1048576",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tooLargeMessage(tc.outcome))
		})
	}
}

// The view the policy series are published from counts the problems of the
// latest generation by severity, CaptureShadowsMappedKey as informational and
// every other reason as blocking. It carries how far the enforced generation
// trails the latest one, and the reason Ready is not true.
func TestPolicyView_reportsThePolicyAsJudged(t *testing.T) {
	cases := []struct {
		name    string
		outcome policy.Outcome
		judged  fleetStatus
		want    metrics.PolicyView
	}{
		{
			name: "two blocking and two informational problems, generation 3 of 5 enforced",
			outcome: policy.Outcome{Generation: 5, ActiveGeneration: 3, Err: errors.New("2 blocking problems"),
				Problems: []ratelimitv1.RuleProblem{
					{Reason: ratelimitv1.ProblemCaptureShadowsMappedKey},
					{Reason: ratelimitv1.ProblemUnresolvedKeyReference},
					{Reason: ratelimitv1.ProblemInvalidWindow},
					{Reason: ratelimitv1.ProblemCaptureShadowsMappedKey},
				}},
			judged: fleetStatus{ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonNotCompiled},
			want: metrics.PolicyView{Domain: testDomain, Ready: false, Reason: ratelimitv1.ReasonNotCompiled,
				Enforced: true, GenerationLag: 2, BlockingProblems: 2, InfoProblems: 2},
		},
		{
			name: "an informational problem alone, generation 5 enforced and ready",
			outcome: policy.Outcome{Generation: 5, ActiveGeneration: 5,
				Problems: []ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemCaptureShadowsMappedKey}}},
			judged: fleetStatus{ready: metav1.ConditionTrue, readyReason: ratelimitv1.ReasonAllReplicas},
			want: metrics.PolicyView{Domain: testDomain, Ready: true, Reason: "",
				Enforced: true, GenerationLag: 0, BlockingProblems: 0, InfoProblems: 1},
		},
		{
			name:    "nothing enforced",
			outcome: policy.Outcome{Generation: 5, Err: errors.New("x")},
			judged:  fleetStatus{},
			want: metrics.PolicyView{Domain: testDomain, Ready: false, Reason: "",
				Enforced: false, GenerationLag: 5, BlockingProblems: 0, InfoProblems: 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, policyView(testPolicy(5), tc.outcome, tc.judged))
		})
	}
}

// The rows are the condition table of docs/ratelimitpolicy-cr-spec.md, which
// Argo CD and the alert rules read.
func TestJudge_followsTheConditionTable(t *testing.T) {
	compiled := policy.Outcome{Generation: 7, ActiveGeneration: 7}
	notCompiled := policy.Outcome{
		Generation: 8, ActiveGeneration: 7, Err: errors.New("2 blocking problems"),
	}
	notCompiledTooLarge := policy.Outcome{
		Generation: 8, ActiveGeneration: 7, Err: errors.New("1 blocking problem (InvalidWindow)"),
		TooLarge:       true,
		TooLargeReason: "the namespace's configuration would be 1100000 bytes compressed, over the limit of 1048576",
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
			ready: metav1.ConditionTrue, readyReason: ratelimitv1.ReasonAllReplicas,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1.ReasonProgressing,
		},
		{
			name:    "no replica has it yet",
			outcome: compiled, view: FleetView{Total: 3},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonReconciling,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1.ReasonProgressing,
		},
		{
			name:    "some replicas have it, within the deadline",
			outcome: compiled, view: FleetView{Total: 3, Applied: 2}, since: 5 * time.Second,
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonPropagating,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1.ReasonProgressing,
		},
		{
			name:    "no ready endpoint at all",
			outcome: compiled, view: FleetView{},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonNoReplicas,
			stalled: metav1.ConditionFalse, stalledReason: ratelimitv1.ReasonProgressing,
		},
		{
			name:    "a replica lags past the deadline",
			outcome: compiled, view: FleetView{Total: 3, Applied: 2}, since: DefaultPropagationDeadline + time.Second,
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonReplicaStale,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1.ReasonReplicaStale,
		},
		{
			name:    "the latest generation does not compile",
			outcome: notCompiled, view: FleetView{Total: 3, Applied: 3},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonNotCompiled,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1.ReasonNotCompiled,
		},
		{
			name:    "the fleet could not be probed",
			outcome: compiled, probeErr: errors.New("unavailable"),
			ready: metav1.ConditionUnknown, readyReason: ratelimitv1.ReasonProbeFailed,
			stalled: metav1.ConditionUnknown, stalledReason: ratelimitv1.ReasonProbeFailed,
		},
		{
			name:    "a generation that does not compile outranks an unobservable fleet",
			outcome: notCompiled, probeErr: errors.New("unavailable"),
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonNotCompiled,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1.ReasonNotCompiled,
		},
		{
			name:    "a generation that does not compile outranks its size",
			outcome: notCompiledTooLarge, view: FleetView{Total: 3, Applied: 3},
			ready: metav1.ConditionFalse, readyReason: ratelimitv1.ReasonNotCompiled,
			stalled: metav1.ConditionTrue, stalledReason: ratelimitv1.ReasonNotCompiled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := judge(tc.outcome, tc.view, tc.probeErr, tc.since, 0)

			assert.Equal(t, tc.ready, got.ready, "the status of Ready")
			assert.Equal(t, tc.readyReason, got.readyReason, "the reason of Ready")
			assert.Equal(t, tc.stalled, got.stalled, "the status of Stalled")
			assert.Equal(t, tc.stalledReason, got.stalledReason, "the reason of Stalled")
		})
	}
}

// The condition message points at the pods worth looking at rather than
// listing every one of them.
func TestBehindMessage_namesOnlyAFewReplicas(t *testing.T) {
	view := FleetView{Total: 9, Applied: 4, Behind: []string{"a", "b", "c", "d", "e"}}

	message := behindMessage(policy.Outcome{ActiveGeneration: 7}, view)

	assert.Contains(t, message, "4 of 9 replicas enforce generation 7", "behindMessage of five replicas behind")
	assert.Contains(t, message, "a, b, c and 2 more", "behindMessage of five replicas behind")
	assert.NotContains(t, message, "d,", "behindMessage of five replicas behind")
}

// readyAge counts the time since Ready last moved only while the condition
// belongs to this generation and its reason is one of propagation. The age
// separates a rollout from a stuck one, and each edit gets its own deadline.
// LastTransitionTime moves when the condition's status changes, not when its
// reason does, so a deployment that sat at NoReplicas overnight carries an
// hours-old stamp into its first probe. Counting that stamp would report
// ReplicaStale, and Stalled with it, on an ordinary start.
func TestReadyAge_countsOnlyTheTimeThisGenerationSpentPropagating(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	anHourAgo := now.Add(-time.Hour)
	cases := []struct {
		name   string
		object *ratelimitv1.RateLimitPolicy
		want   time.Duration
	}{
		{"Reconciling for an hour", withReady(testPolicy(5), ratelimitv1.ReasonReconciling, anHourAgo, 5), time.Hour},
		{"Propagating for an hour", withReady(testPolicy(5), ratelimitv1.ReasonPropagating, anHourAgo, 5), time.Hour},
		{"ReplicaStale for an hour", withReady(testPolicy(5), ratelimitv1.ReasonReplicaStale, anHourAgo, 5), time.Hour},
		{"NoReplicas for an hour", withReady(testPolicy(5), ratelimitv1.ReasonNoReplicas, anHourAgo, 5), 0},
		{"ProbeFailed for an hour", withReady(testPolicy(5), ratelimitv1.ReasonProbeFailed, anHourAgo, 5), 0},
		{"AllReplicas for an hour", withReady(testPolicy(5), ratelimitv1.ReasonAllReplicas, anHourAgo, 5), 0},
		{"NotCompiled for an hour", withReady(testPolicy(5), ratelimitv1.ReasonNotCompiled, anHourAgo, 5), 0},
		{
			"Propagating for an hour, observed for the generation before",
			withReady(testPolicy(6), ratelimitv1.ReasonPropagating, anHourAgo, 5), 0,
		},
		{"no Ready condition", testPolicy(5), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, readyAge(tc.object, now))
		})
	}
}

// A replica that says nothing is a different diagnosis from one that answers
// with an old generation, and the message keeps them apart: the first points
// at the metrics port, the second at a rollout in flight.
func TestReconcile_namesSilentReplicasApartFromLaggingOnes(t *testing.T) {
	probe := &stubProbe{view: FleetView{
		Total: 4, Applied: 2,
		Behind: []string{"ratelimit-lagging"},
		Silent: []string{"ratelimit-quiet"},
	}}
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(7))

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	ready := condition(t, fetch(t, fakeClient).Status.Conditions, ratelimitv1.ConditionReady)
	assert.Contains(t, ready.Message, "ratelimit-lagging report another", "the message of Ready")
	assert.Contains(t, ready.Message, "ratelimit-quiet did not answer", "the message of Ready")
}

// lastCheckTime is the freshness of the probe, and an operator reads a stale
// one as a dead leader. A status that does not otherwise change is written
// once the stamp is lastCheckMaxAge old, so the field keeps moving while the
// leader keeps probing. A younger stamp stays as it is.
func TestReconcile_refreshesAnUnchangedProbeTimeOnceItIsTheBoundOld(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		stamp time.Time
		want  time.Time
	}{
		{"a stamp twice the bound old", now.Add(-2 * lastCheckMaxAge), now},
		{"a stamp exactly the bound old", now.Add(-lastCheckMaxAge), now},
		{
			"a stamp a second younger than the bound",
			now.Add(-lastCheckMaxAge + time.Second), now.Add(-lastCheckMaxAge + time.Second),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reconciler, fakeClient := newReconciler(t, unanimous(1), testPolicy(1))
			reconciler.Now = (&fakeClock{base: now}).now
			_, err := reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)
			stored := fetch(t, fakeClient)
			stored.Status.Replicas.LastCheckTime = &metav1.Time{Time: tt.stamp}
			require.NoError(t, fakeClient.Status().Update(context.Background(), stored))

			_, err = reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)

			stamped := fetch(t, fakeClient).Status.Replicas.LastCheckTime
			require.NotNil(t, stamped, "status.replicas.lastCheckTime")
			assert.Equal(t, tt.want, stamped.UTC(),
				"status.replicas.lastCheckTime after a Reconcile at %v over a stamp of %v", now, tt.stamp)
		})
	}
}

// An EndpointSlice change reconciles every policy of the namespace, because a
// pod joining or leaving changes the denominator of Ready without touching any
// policy. Only the slices of the fleet's own Service count: another Service's
// endpoints say nothing about who enforces these rules.
func TestPoliciesBehind_mapsOnlyTheFleetsOwnSliceToEveryPolicy(t *testing.T) {
	cases := []struct {
		name         string
		service      string
		sliceService string
		want         []reconcile.Request
	}{
		{"a slice of the fleet's Service", "ratelimit", "ratelimit", []reconcile.Request{testRequest()}},
		{"a slice of another Service", "ratelimit", "some-other-service", nil},
		{"a slice of the fleet, with no Service configured", "", "ratelimit", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reconciler, _ := newReconciler(t, unanimous(1), testPolicy(1))
			reconciler.Service = tc.service
			slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{
				Namespace: testNamespace,
				Name:      tc.sliceService + "-abc",
				Labels:    map[string]string{discoveryv1.LabelServiceName: tc.sliceService},
			}}

			assert.ElementsMatch(t, tc.want, reconciler.policiesBehind(context.Background(), slice),
				"the requests for a slice of service %q, with service %q configured", tc.sliceService, tc.service)
		})
	}
}

// setReadyCondition restarts the propagation clock when a rollout begins, so
// the second probe of a rollout stays Propagating. Both ways into a rollout
// hold Ready at False, and meta.SetStatusCondition moves LastTransitionTime
// only when the status changes: without the restart, the probe after the
// first reads a stamp as old as what came before and reports ReplicaStale
// with Stalled true. The status write of the first probe is itself an event
// on the policy, so the second probe arrives at once rather than one interval
// later.
func TestReconcile_aSecondProbeOfANewRolloutStaysPropagating(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		object *ratelimitv1.RateLimitPolicy
	}{
		{
			name:   "after an hour without a ready replica",
			object: withReady(testPolicy(7), ratelimitv1.ReasonNoReplicas, now.Add(-time.Hour), 7),
		},
		{
			name:   "after a day of a previous generation that did not compile",
			object: withReady(testPolicy(6), ratelimitv1.ReasonNotCompiled, now.Add(-24*time.Hour), 5),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &stubProbe{view: FleetView{Total: 2, Applied: 1, Behind: []string{"ratelimit-b"}}}
			reconciler, fakeClient := newReconciler(t, probe, tc.object)
			reconciler.Now = (&fakeClock{base: now}).now

			first := readyReasonAfterReconcile(t, reconciler, fakeClient)
			second := readyReasonAfterReconcile(t, reconciler, fakeClient)

			assert.Equal(t, ratelimitv1.ReasonPropagating, first, "the reason of Ready after the first probe")
			assert.Equal(t, ratelimitv1.ReasonPropagating, second, "the reason of Ready after the second probe")
		})
	}
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

			assert.Equal(t, []bool{tc.fresh}, probe.fresh,
				"the fresh argument of each Observe, generation 7 with %d observed", tc.observed)
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
		{"a round reused for four more seconds",
			FleetView{At: now, RefreshAt: now.Add(4 * time.Second)}, 4 * time.Second},
		{"a round taken ten seconds ago and reused for two more",
			FleetView{At: now.Add(-10 * time.Second), RefreshAt: now.Add(2 * time.Second)}, 2 * time.Second},
		{"a view without an expiry, taken now",
			FleetView{At: now}, ProbeInterval},
		{"a view without an expiry, taken four seconds ago",
			FleetView{At: now.Add(-4 * time.Second)}, ProbeInterval - 4*time.Second},
		{"a round about to expire",
			FleetView{At: now, RefreshAt: now.Add(200 * time.Millisecond)}, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := unanimous(2)
			probe.view.At, probe.view.RefreshAt = tc.view.At, tc.view.RefreshAt
			reconciler, _ := newReconciler(t, probe, testPolicy(7))
			reconciler.Now = (&fakeClock{base: now}).now

			result, err := reconciler.Reconcile(context.Background(), testRequest())
			require.NoError(t, err)

			assert.Equal(t, tc.wait, result.RequeueAfter,
				"RequeueAfter at %v of a view taken at %v and refreshed at %v", now, tc.view.At, tc.view.RefreshAt)
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
		"RequeueAfter of a probe that took four seconds over a round taken at its start")
}

// lastCheckTime is the time the fleet was asked, which for a status built
// from a reused round is earlier than the write: the field is the freshness
// of the answers.
func TestReconcile_stampsTheTimeTheFleetWasAsked(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	asked := now.Add(-4 * time.Second)
	probe := unanimous(2)
	probe.view.At = asked
	reconciler, fakeClient := newReconciler(t, probe, testPolicy(7))
	reconciler.Now = (&fakeClock{base: now}).now

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	stamped := fetch(t, fakeClient).Status.Replicas.LastCheckTime
	require.NotNil(t, stamped, "status.replicas.lastCheckTime")
	assert.Equal(t, asked, stamped.UTC(),
		"status.replicas.lastCheckTime of a round asked at %v and reconciled at %v", asked, now)
}

// Time genuinely spent propagating still ends in ReplicaStale: the restart of
// the propagation clock leaves the deadline reachable.
func TestReconcile_aRolloutPastTheDeadlineIsStale(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	object := withReady(testPolicy(7), ratelimitv1.ReasonPropagating,
		now.Add(-DefaultPropagationDeadline-time.Minute), 7)
	probe := &stubProbe{view: FleetView{Total: 2, Applied: 1, Behind: []string{"ratelimit-b"}}}
	reconciler, fakeClient := newReconciler(t, probe, object)
	reconciler.Now = (&fakeClock{base: now}).now

	_, err := reconciler.Reconcile(context.Background(), testRequest())
	require.NoError(t, err)

	conditions := verdicts(fetch(t, fakeClient).Status.Conditions)
	assert.Equal(t, verdict{metav1.ConditionFalse, ratelimitv1.ReasonReplicaStale},
		conditions[ratelimitv1.ConditionReady], "Ready")
	assert.Equal(t, verdict{metav1.ConditionTrue, ratelimitv1.ReasonReplicaStale},
		conditions[ratelimitv1.ConditionStalled], "Stalled")
}

// A replica that refused the manifest will never take the generation up,
// whatever the deadline, so even well past it the refusal is named instead of
// the lag.
func TestJudge_aRefusingReplicaIsFormatUnsupportedNotStale(t *testing.T) {
	compiled := policy.Outcome{Generation: 7, ActiveGeneration: 7}
	view := FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-c"}, Refusing: []string{"ratelimit-c"}}

	got := judge(compiled, view, nil, time.Hour, 0)

	assert.Equal(t, metav1.ConditionFalse, got.ready, "the status of Ready")
	assert.Equal(t, ratelimitv1.ReasonReplicaFormatUnsupported, got.readyReason, "the reason of Ready")
	assert.Equal(t, metav1.ConditionTrue, got.stalled, "the status of Stalled")
	assert.Equal(t, ratelimitv1.ReasonReplicaFormatUnsupported, got.stalledReason, "the reason of Stalled")
	assert.Contains(t, got.readyMessage, "ratelimit-c", "the message of Ready")
	assert.Contains(t, got.readyMessage, "upgrade the service before the operator", "the message of Ready")
}

// A generation that compiles and does not fit the namespace's ConfigMap is
// ConfigMapTooLarge, because the fix is not in the spec, and the last-good
// generation keeps serving.
func TestJudge_aGenerationThatDoesNotFitIsTooLarge(t *testing.T) {
	outcome := policy.Outcome{Generation: 8, ActiveGeneration: 7, TooLarge: true,
		TooLargeReason: "the namespace's configuration would be 1100000 bytes compressed, over the limit of 1048576"}

	got := judge(outcome, FleetView{Total: 3, Applied: 3}, nil, 0, 0)

	assert.Equal(t, metav1.ConditionFalse, got.ready, "the status of Ready")
	assert.Equal(t, ratelimitv1.ReasonConfigMapTooLarge, got.readyReason, "the reason of Ready")
	assert.Equal(t, metav1.ConditionTrue, got.stalled, "the status of Stalled")
	assert.Equal(t, ratelimitv1.ReasonConfigMapTooLarge, got.stalledReason, "the reason of Stalled")
	assert.Contains(t, got.readyMessage, "generation 7 keeps serving", "the message of Ready")
}

// The deadline separates Propagating from ReplicaStale, and a lag of exactly
// the deadline is still Propagating. A zero deadline means the default of 90
// s, under which a 45 s lag is propagating: the kubelet takes up to a minute
// to project a change.
func TestJudge_honorsTheConfiguredDeadline(t *testing.T) {
	compiled := policy.Outcome{Generation: 7, ActiveGeneration: 7}
	lagging := FleetView{Total: 3, Applied: 2, Behind: []string{"ratelimit-c"}}
	cases := []struct {
		name     string
		since    time.Duration
		deadline time.Duration
		want     string
	}{
		{"45 s under the default deadline", 45 * time.Second, 0, ratelimitv1.ReasonPropagating},
		{"45 s under a deadline of 30 s", 45 * time.Second, 30 * time.Second, ratelimitv1.ReasonReplicaStale},
		{"exactly a deadline of 90 s", 90 * time.Second, 90 * time.Second, ratelimitv1.ReasonPropagating},
		{"a second past a deadline of 90 s", 91 * time.Second, 90 * time.Second, ratelimitv1.ReasonReplicaStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := judge(compiled, lagging, nil, tc.since, tc.deadline)

			assert.Equal(t, tc.want, got.readyReason, "the reason of Ready after %v under a deadline of %v",
				tc.since, tc.deadline)
		})
	}
}

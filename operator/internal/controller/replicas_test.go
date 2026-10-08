package controller

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
)

// The probe is the only part of the operator that talks to another replica, and
// the URL it builds is the whole feature: a leader that cannot reach
// /debug/applied reports a fleet it never saw. These tests drive it against a
// real HTTP server and EndpointSlice fixtures rather than stubbing it out.

const probeService = "ratelimit"

// fleet starts a server answering for every replica and returns a probe wired
// to it. The handler decides what each caller is told, keyed by nothing: every
// endpoint address in these tests is the loopback, so the server stands in for
// the whole fleet at once.
func fleet(t *testing.T, handler http.HandlerFunc, endpoints ...discoveryv1.Endpoint) *ReplicaProbe {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	number, err := strconv.Atoi(port)
	require.NoError(t, err)

	// The slice publishes the port under the contract's name, as the
	// Service of the service chart does; the probe reads the number there.
	metricsPort := int32(number)
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      probeService + "-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: probeService},
		},
		Endpoints: endpoints,
		Ports:     []discoveryv1.EndpointPort{{Name: new(contract.MetricsPortName), Port: &metricsPort}},
	}
	reader := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(slice).Build()

	return &ReplicaProbe{
		Reader:    reader,
		Namespace: testNamespace,
		Service:   probeService,
	}
}

// ready is one endpoint that receives traffic, named by its pod.
func ready(pod string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{"127.0.0.1"},
		Conditions: discoveryv1.EndpointConditions{Ready: new(true)},
		TargetRef:  &corev1.ObjectReference{Kind: "Pod", Name: pod},
	}
}

// draining is an endpoint of a pod that is shutting down and is still reported
// ready. A default Service does not produce this - it drops ready and keeps
// serving - but one with publishNotReadyAddresses does, and that is the shape
// the terminating check exists for.
func draining(pod string) discoveryv1.Endpoint {
	e := ready(pod)
	e.Conditions.Terminating = new(true)
	return e
}

// answers replies with one generation for every caller.
func answers(t *testing.T, domains map[string]applied.Domain) http.HandlerFunc {
	return reports(t, applied.Report{Domains: domains})
}

// reports replies with a whole report: the domains, and whatever else the
// replica says about itself. It runs on the server's goroutine, so it reports
// a mismatch with assert and never stops the test.
func reports(t *testing.T, report applied.Report) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, contract.AppliedPath, r.URL.Path, "the path the probe requested")
		assert.NoError(t, json.NewEncoder(w).Encode(report), "encoding the report")
	}
}

func want(generation int64) applied.Domain {
	return applied.Domain{Generation: generation, UID: string(testUID)}
}

func appliedBy(generation int64) map[string]applied.Domain {
	return map[string]applied.Domain{testDomain: want(generation)}
}

func TestObserve_countsTheReplicasOnTheGenerationAsked(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"), ready("ratelimit-b"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(2), view.Total, "view.Total")
	assert.Equal(t, int32(2), view.Applied, "view.Applied")
	assert.Empty(t, view.Behind, "view.Behind")
	assert.Empty(t, view.Silent, "view.Silent")
}

// The UID travels with the generation because the number alone is ambiguous
// across a delete and recreate: a fresh object starts at generation 1 too.
func TestObserve_aMatchingGenerationOfAnotherObjectIsNotApplied(t *testing.T) {
	probe := fleet(t, answers(t, map[string]applied.Domain{
		testDomain: {Generation: 7, UID: "some-older-object"},
	}), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Applied, "view.Applied")
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind, "view.Behind")
}

func TestObserve_aReplicaOnAnotherGenerationIsBehind(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(6)), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(1), view.Total, "view.Total")
	assert.Zero(t, view.Applied, "view.Applied")
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind, "view.Behind")
}

// A replica that has never compiled this domain answers without it, which is
// the honest answer for a pod that is not ready either.
func TestObserve_aReplicaThatDoesNotKnowTheDomainIsBehind(t *testing.T) {
	probe := fleet(t, answers(t, map[string]applied.Domain{"gateway.private": want(7)}), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Applied, "view.Applied")
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind, "view.Behind")
}

// One silent replica among answering ones is a fact about that pod: it is
// counted silent, not behind, and the observation still succeeds. The handler
// refuses whichever request arrives first, so the test does not name the
// silent replica.
func TestObserve_oneSilentReplicaAmongAnsweringOnesIsCountedSilent(t *testing.T) {
	var once sync.Once
	answer := answers(t, appliedBy(7))
	probe := fleet(t, func(w http.ResponseWriter, r *http.Request) {
		refused := false
		once.Do(func() { refused = true })
		if refused {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		answer(w, r)
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(2), view.Total, "view.Total")
	assert.Equal(t, int32(1), view.Applied, "view.Applied")
	assert.Empty(t, view.Behind, "view.Behind")
	assert.Len(t, view.Silent, 1, "view.Silent")
}

// When nobody answers, the statement is about the leader's reach rather than
// about the fleet. A network policy that admits only Prometheus to the metrics
// port silences every probe, and reporting that as a stale replica would mark a
// working domain Degraded. The error names the path that went unanswered, the
// only part of it an operator can act on; there is no sentinel to match.
func TestObserve_aFleetThatAnswersNothingIsAnError(t *testing.T) {
	probe := fleet(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), contract.AppliedPath)
}

// A reply that does not decode counts as no answer, so a fleet whose every
// reply is garbage fails the observation with the error of a fleet that
// answers nothing, the one that names the unanswered path, and the decoding
// error is in its chain.
func TestObserve_repliesThatDoNotDecodeCountAsNoAnswer(t *testing.T) {
	probe := fleet(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)

	assert.ErrorContains(t, err, contract.AppliedPath, "the error of a fleet that answers nothing")
	var syntax *json.SyntaxError
	assert.ErrorAs(t, err, &syntax)
}

// An empty fleet is not an error: it is the NoReplicas case, and the leader
// reports it rather than failing.
func TestObserve_anEmptyFleetIsObservedAsEmpty(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Total, "view.Total")
	assert.Zero(t, view.Applied, "view.Applied")
}

// The denominator is the ready endpoints: a pod that is not ready receives no
// traffic, so it enforces nothing and belongs in no fraction. A nil Ready
// means ready, per the EndpointSlice API. Every replica answers another
// generation, so the ones counted are named as behind.
func TestObserve_countsOnlyTheEndpointsReceivingTraffic(t *testing.T) {
	notReady := ready("ratelimit-draining")
	notReady.Conditions.Ready = new(false)
	unstated := ready("ratelimit-unstated")
	unstated.Conditions.Ready = nil
	addressless := ready("ratelimit-addressless")
	addressless.Addresses = nil
	probe := fleet(t, answers(t, appliedBy(6)), notReady, unstated, addressless, ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(2), view.Total, "view.Total")
	assert.Equal(t, []string{"ratelimit-a", "ratelimit-unstated"}, view.Behind, "view.Behind")
}

// Without a target reference the address is all the message can name, which is
// still enough to find the pod.
func TestObserve_namesAnEndpointWithoutAPodByItsAddress(t *testing.T) {
	anonymous := ready("")
	anonymous.TargetRef = nil
	probe := fleet(t, answers(t, appliedBy(6)), anonymous)

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1"}, view.Behind, "view.Behind")
}

// The slices of other Services carry other pods, and counting them would put
// somebody else's rollout in this policy's status.
func TestObserve_ignoresTheSlicesOfOtherServices(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	probe.Service = "some-other-service"

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Total, "view.Total")
}

// A fleet whose EndpointSlices cannot be listed is unobservable, not empty.
func TestObserve_aFleetThatCannotBeListedIsAnError(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	probe.Reader = failingReader{}

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)

	assert.ErrorIs(t, err, assert.AnError)
}

// failingReader stands in for an API server that will not answer.
type failingReader struct{ client.Reader }

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return assert.AnError
}

// A draining pod that is still reported ready answers the probe with whatever
// it enforces, so counting it would drag applied below total for the length of
// a rollout and flicker Ready on a change nobody made to the rules.
func TestObserve_aTerminatingReplicaLeavesTheFraction(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)),
		ready("ratelimit-new"), draining("ratelimit-old"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(1), view.Total, "view.Total")
	assert.Equal(t, int32(1), view.Applied, "view.Applied")
	assert.Empty(t, view.Behind, "view.Behind")
}

// A draining pod reports a generation that will never advance, and it is not
// a propagation problem: the ready replica on the same old generation is
// behind, the draining one is not.
func TestObserve_aTerminatingReplicaOnAnOldGenerationIsNotBehind(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(6)), ready("ratelimit-a"), draining("ratelimit-old"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(1), view.Total, "view.Total")
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind, "view.Behind")
}

// counting wraps a handler and counts the requests it served, which is the
// cost of a probe as the fleet sees it: one request per replica per round.
func counting(calls *atomic.Int32, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		next(w, r)
	}
}

// The observations of one cycle share one round: three domains asked within
// the freshness cost the fleet one request per replica, and each domain is
// still judged on its own out of the same answers.
func TestObserve_theDomainsOfACycleShareOneRound(t *testing.T) {
	var calls atomic.Int32
	enforced := map[string]applied.Domain{
		"gateway.a": want(7),
		"gateway.b": want(3),
		"gateway.c": {Generation: 2, UID: "another-object"},
	}
	probe := fleet(t, counting(&calls, answers(t, enforced)), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = time.Minute

	a, err := probe.Observe(context.Background(), "gateway.a", want(7), false)
	require.NoError(t, err)
	b, err := probe.Observe(context.Background(), "gateway.b", want(3), false)
	require.NoError(t, err)
	c, err := probe.Observe(context.Background(), "gateway.c", want(2), false)
	require.NoError(t, err)

	assert.Equal(t, int32(2), a.Applied, "gateway.a applied of %d", a.Total)
	assert.Equal(t, int32(2), b.Applied, "gateway.b applied of %d", b.Total)
	assert.Zero(t, c.Applied, "gateway.c applied, on the generation asked of another object")
	assert.Equal(t, []string{"ratelimit-a", "ratelimit-b"}, c.Behind, "gateway.c behind")
	assert.Equal(t, int32(2), calls.Load(), "requests for three domains over two replicas")
}

// A fresh observation retakes the round whatever its age: the reconciler asks
// for one when it reacts to a new generation, so the status never rests on
// answers from before the change.
func TestObserve_aFreshObservationRetakesTheRound(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, answers(t, appliedBy(7))), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = time.Minute

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "requests for two observations within the freshness over two replicas")

	_, err = probe.Observe(context.Background(), testDomain, want(7), true)
	require.NoError(t, err)
	assert.Equal(t, int32(4), calls.Load(), "requests after a fresh observation over two replicas")
}

// A round is reused while it is younger than the freshness and retaken from
// the moment it is that old: one request per replica just under the
// freshness, another round at it.
func TestObserve_aRoundIsRetakenAtItsFreshness(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, answers(t, appliedBy(7))), ready("ratelimit-a"))
	probe.Freshness = time.Minute
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	probe.Now = func() time.Time { return now }

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)

	now = now.Add(time.Minute - time.Millisecond)
	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "requests over one replica, the second observation just under the freshness")

	now = now.Add(time.Millisecond)
	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "requests over one replica, the third observation at the freshness")
}

// A round is reused only for the fleet it was taken from. The reconciles an
// EndpointSlice change fans out exist to update the denominator, so a pod
// that joined since the round was taken retakes it, and a fleet that did not
// change keeps it.
func TestObserve_aRoundIsRetakenWhenTheFleetChanges(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, answers(t, appliedBy(7))), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = time.Minute

	first, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	require.Equal(t, int32(2), first.Total, "the replicas of the first round")

	var slice discoveryv1.EndpointSlice
	writer := probe.Reader.(client.Client)
	require.NoError(t, writer.Get(context.Background(),
		client.ObjectKey{Namespace: testNamespace, Name: probeService + "-abc"}, &slice))
	slice.Endpoints = append(slice.Endpoints, ready("ratelimit-c"))
	require.NoError(t, writer.Update(context.Background(), &slice))

	second, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(3), second.Total, "the replicas once a pod joined")
	assert.Equal(t, int32(5), calls.Load(), "two requests for the first fleet, three for the changed one")

	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(5), calls.Load(), "requests after a third observation of the unchanged fleet")
}

// A fleet that answers nothing is an error for every domain of the cycle, and
// it costs one round: the leader does not ask a silent fleet again for each
// domain.
func TestObserve_aSilentFleetIsOneRoundOfErrors(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = time.Minute

	_, errA := probe.Observe(context.Background(), "gateway.a", want(7), false)
	_, errB := probe.Observe(context.Background(), "gateway.b", want(7), false)

	assert.Error(t, errA, "Observe of gateway.a")
	assert.Error(t, errB, "Observe of gateway.b")
	assert.Equal(t, int32(2), calls.Load(), "requests for two domains over two replicas")
}

// Without a freshness every observation is a round of its own.
func TestObserve_withoutAFreshnessEveryObservationIsARound(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, answers(t, appliedBy(7))), ready("ratelimit-a"))

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)

	assert.Equal(t, int32(2), calls.Load(), "requests for two observations over one replica")
}

// A view carries the time its round was taken, so a reader of the status
// knows how fresh the answers are: an observation answered from a reused
// round reports the round's time, not its own.
func TestObserve_aViewCarriesTheTimeOfItsRound(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	probe.Freshness = time.Minute
	taken := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	now := taken
	probe.Now = func() time.Time { return now }

	first, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	now = taken.Add(4 * time.Second)
	second, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)

	assert.Equal(t, taken, first.At, "the time of the first view")
	assert.Equal(t, taken, second.At, "the time of a view from the reused round, observed at %v", now)
}

// fakeClock is a clock the test and the fleet's handlers advance from their
// own goroutines.
type fakeClock struct {
	base   time.Time
	offset atomic.Int64
}

func (c *fakeClock) now() time.Time { return c.base.Add(time.Duration(c.offset.Load())) }

func (c *fakeClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// slowAnswers answers for every replica with generation 7 of the test domain
// after advancing clock by six seconds, the way a slow replica spends the
// time of a round.
func slowAnswers(t *testing.T, clock *fakeClock) http.HandlerFunc {
	answer := answers(t, appliedBy(7))
	return func(w http.ResponseWriter, r *http.Request) {
		clock.advance(6 * time.Second)
		answer(w, r)
	}
}

// The freshness counts from the end of a round, not from its start: a round
// whose replicas took twelve seconds of the clock to answer is still reused
// by the next domain under a freshness of ten, where a round aged from its
// start would have expired before it completed and the cycle would fall
// back to one round per domain.
func TestObserve_aSlowRoundIsStillReusedAfterItCompletes(t *testing.T) {
	var calls atomic.Int32
	clock := &fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	probe := fleet(t, counting(&calls, slowAnswers(t, clock)), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = 10 * time.Second
	probe.Now = clock.now

	a, err := probe.Observe(context.Background(), "gateway.a", want(7), false)
	require.NoError(t, err)
	_, err = probe.Observe(context.Background(), "gateway.b", want(7), false)
	require.NoError(t, err)

	assert.Equal(t, clock.base, a.At, "the time of the view of gateway.a")
	assert.Equal(t, int32(2), calls.Load(), "requests for two domains over two replicas, the second from the round")
}

// The replicas are asked together, so a round lasts one probe timeout at most
// rather than one per replica. The handler answers only once every replica's
// request is in flight, which a round that asked them one at a time could
// never reach: its first request would time out alone.
func TestObserve_asksTheReplicasTogether(t *testing.T) {
	const replicas = 3
	var arrived atomic.Int32
	allInFlight := make(chan struct{})
	answer := answers(t, appliedBy(7))
	together := func(w http.ResponseWriter, r *http.Request) {
		if arrived.Add(1) == replicas {
			close(allInFlight)
		}
		select {
		case <-allInFlight:
		case <-time.After(3 * time.Second):
			t.Errorf("waited 3s for %d requests in flight together; %d arrived", replicas, arrived.Load())
		}
		answer(w, r)
	}
	probe := fleet(t, together, ready("ratelimit-a"), ready("ratelimit-b"), ready("ratelimit-c"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(replicas), view.Applied, "view.Applied")
	assert.Empty(t, view.Silent, "view.Silent")
}

// A view says when the probe stops answering from its round: the round's
// completion plus the freshness, so a reconciler that requeues for that
// moment takes a new round rather than the same one again.
func TestObserve_aReusableRoundExpiresAFreshnessAfterItCompletes(t *testing.T) {
	clock := &fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	probe := fleet(t, slowAnswers(t, clock), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = 10 * time.Second
	probe.Now = clock.now

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, clock.base.Add(22*time.Second), view.RefreshAt,
		"the expiry of a round taken at %v, completed twelve seconds later, and reused for ten", clock.base)
}

// A probe that reuses nothing names the next look one interval after the
// fleet was asked.
func TestObserve_aRoundWithoutAFreshnessExpiresAnIntervalAfterTheAsk(t *testing.T) {
	clock := &fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	probe.Now = clock.now

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, clock.base.Add(ProbeInterval), view.RefreshAt, "the expiry of a round taken at %v", clock.base)
}

// The port is there, under another name: a misnamed Service. Its endpoints
// cannot be asked, and they are not counted silent: a stale replica is a
// replica the probe could reach and found behind, and this one it could not
// address at all.
func TestObserve_aSliceWithoutTheNamedPortHasNoReplicas(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	number := slicePort(t, probe)
	requireSlicePorts(t, probe, discoveryv1.EndpointPort{Name: new("http-metrics"), Port: &number})

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Total, "view.Total")
	assert.Empty(t, view.Silent, "view.Silent")
}

// slicePort reads the number the probe's one slice publishes.
func slicePort(t *testing.T, probe *ReplicaProbe) int32 {
	t.Helper()
	var slice discoveryv1.EndpointSlice
	require.NoError(t, probe.Reader.(client.Client).Get(context.Background(),
		client.ObjectKey{Namespace: testNamespace, Name: probeService + "-abc"}, &slice))
	require.NotEmpty(t, slice.Ports)
	return *slice.Ports[0].Port
}

// requireSlicePorts rewrites the ports of the probe's one slice.
func requireSlicePorts(t *testing.T, probe *ReplicaProbe, ports ...discoveryv1.EndpointPort) {
	t.Helper()
	var slice discoveryv1.EndpointSlice
	require.NoError(t, probe.Reader.(client.Client).Get(context.Background(),
		client.ObjectKey{Namespace: testNamespace, Name: probeService + "-abc"}, &slice))
	slice.Ports = ports
	require.NoError(t, probe.Reader.(client.Client).Update(context.Background(), &slice))
}

// A replica that refused the manifest is named apart from one that lags: it
// will never take the generation up, whatever the threshold. It kept the
// snapshot from before the manifest, so it is behind as well.
func TestObserve_namesAReplicaThatRefusedTheManifest(t *testing.T) {
	probe := fleet(t, reports(t, applied.Report{
		Domains:        map[string]applied.Domain{testDomain: want(6)},
		FormatVersions: []int{1},
		Refusal:        &applied.Refusal{FormatVersion: 2, Reason: "manifest: unsupported format version: 2"},
	}), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, []string{"ratelimit-a"}, view.Refusing, "view.Refusing")
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind, "view.Behind")
	assert.Zero(t, view.Applied, "view.Applied")
}

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

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/internal/store"
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

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      probeService + "-abc",
			Labels:    map[string]string{discoveryv1.LabelServiceName: probeService},
		},
		Endpoints: endpoints,
	}
	reader := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(slice).Build()

	return &ReplicaProbe{
		Reader:    reader,
		Namespace: testNamespace,
		Service:   probeService,
		Port:      number,
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
func answers(t *testing.T, applied map[string]store.Applied) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, contract.AppliedPath, r.URL.Path, "the probe reads the documented path")
		require.NoError(t, json.NewEncoder(w).Encode(applied))
	}
}

func want(generation int64) store.Applied {
	return store.Applied{Generation: generation, UID: string(testUID)}
}

func appliedBy(generation int64) map[string]store.Applied {
	return map[string]store.Applied{testDomain: want(generation)}
}

func TestObserve_countsTheReplicasOnTheGenerationAsked(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"), ready("ratelimit-b"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(2), view.Total)
	assert.Equal(t, int32(2), view.Applied)
	assert.Empty(t, view.Behind)
	assert.Empty(t, view.Silent)
}

// The UID travels with the generation because the number alone is ambiguous
// across a delete and recreate: a fresh object starts at generation 1 too.
func TestObserve_aMatchingGenerationOfAnotherObjectIsNotApplied(t *testing.T) {
	probe := fleet(t, answers(t, map[string]store.Applied{
		testDomain: {Generation: 7, UID: "some-older-object"},
	}), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Applied)
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind)
}

func TestObserve_aReplicaOnAnotherGenerationIsBehind(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(6)), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(1), view.Total)
	assert.Zero(t, view.Applied)
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind)
}

// A replica that has never compiled this domain answers without it, which is
// the honest answer for a pod that is not ready either.
func TestObserve_aReplicaThatDoesNotKnowTheDomainIsBehind(t *testing.T) {
	probe := fleet(t, answers(t, map[string]store.Applied{"gateway.private": want(7)}), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Applied)
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind)
}

// One silent replica among answering ones is a fact about that pod, and it stays
// out of Applied without turning the whole observation into a failure.
func TestObserve_oneSilentReplicaIsNamedButDoesNotBlindTheLeader(t *testing.T) {
	var once sync.Once
	probe := fleet(t, func(w http.ResponseWriter, r *http.Request) {
		refused := false
		once.Do(func() { refused = true })
		if refused {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(appliedBy(7)))
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(2), view.Total)
	assert.Equal(t, int32(1), view.Applied)
	assert.Empty(t, view.Behind, "a silent replica is not one that reported another generation")
	assert.Len(t, view.Silent, 1)
}

// When nobody answers, the statement is about the leader's reach rather than
// about the fleet. A network policy that admits only Prometheus to the metrics
// port silences every probe, and reporting that as a stale replica would mark a
// working domain Degraded.
func TestObserve_aFleetThatAnswersNothingIsAnError(t *testing.T) {
	probe := fleet(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.Error(t, err, "no answer at all is ProbeFailed, not a fleet of stale replicas")
	assert.Contains(t, err.Error(), contract.AppliedPath)
}

func TestObserve_aBodyThatDoesNotDecodeIsSilence(t *testing.T) {
	probe := fleet(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

// An empty fleet is not an error: it is the NoReplicas case, and the leader
// reports it rather than failing.
func TestObserve_anEmptyFleetIsObservedAsEmpty(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Total)
	assert.Zero(t, view.Applied)
}

// The denominator is the ready endpoints: a pod that is not ready receives no
// traffic, so it enforces nothing and belongs in no fraction.
func TestEndpoints_countsOnlyTheOnesReceivingTraffic(t *testing.T) {
	notReady := ready("ratelimit-draining")
	notReady.Conditions.Ready = new(false)

	// A nil Ready means ready, per the EndpointSlice API.
	unstated := ready("ratelimit-unstated")
	unstated.Conditions.Ready = nil

	addressless := ready("ratelimit-addressless")
	addressless.Addresses = nil

	probe := fleet(t, answers(t, appliedBy(7)), notReady, unstated, addressless, ready("ratelimit-a"))

	endpoints, err := probe.endpoints(context.Background())

	require.NoError(t, err)
	names := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		names = append(names, e.name)
	}
	assert.Equal(t, []string{"ratelimit-a", "ratelimit-unstated"}, names)
}

// Without a target reference the address is all the message can name, which is
// still enough to find the pod.
func TestEndpoints_fallsBackToTheAddressWhenNoPodIsNamed(t *testing.T) {
	anonymous := ready("")
	anonymous.TargetRef = nil

	probe := fleet(t, answers(t, appliedBy(7)), anonymous)

	endpoints, err := probe.endpoints(context.Background())

	require.NoError(t, err)
	require.Len(t, endpoints, 1)
	assert.Equal(t, "127.0.0.1", endpoints[0].name)
}

// The slices of other Services carry other pods, and counting them would put
// somebody else's rollout in this policy's status.
func TestEndpoints_ignoresTheSlicesOfOtherServices(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	probe.Service = "some-other-service"

	endpoints, err := probe.endpoints(context.Background())

	require.NoError(t, err)
	assert.Empty(t, endpoints)
}

func TestEndpoints_reportsAListThatFailed(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	probe.Reader = failingReader{}

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.Error(t, err, "a fleet that cannot be listed is unobservable, not empty")
	assert.Contains(t, err.Error(), "EndpointSlice")
}

// failingReader stands in for an API server that will not answer.
type failingReader struct{ client.Reader }

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return assert.AnError
}

// TestObserve_aTerminatingReplicaLeavesTheFraction pins the guard. A draining
// pod that is still reported ready answers the probe with whatever it
// enforces, so counting it would drag applied below total for the length of a
// rollout and flicker Ready on a change nobody made to the rules.
func TestObserve_aTerminatingReplicaLeavesTheFraction(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)),
		ready("ratelimit-new"), draining("ratelimit-old"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(1), view.Total, "a terminating pod is not part of the fleet")
	assert.Equal(t, int32(1), view.Applied)
	assert.Empty(t, view.Behind)
}

// The same pod on an older generation: without the terminating check this is
// the flicker, because it reports a generation that will never advance.
func TestObserve_aTerminatingReplicaOnAnOldGenerationIsNotBehind(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(6)), draining("ratelimit-old"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Zero(t, view.Total)
	assert.Empty(t, view.Behind, "a pod on its way out is not a propagation problem")
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
	applied := map[string]store.Applied{
		"gateway.a": want(7),
		"gateway.b": want(3),
		"gateway.c": {Generation: 2, UID: "another-object"},
	}
	probe := fleet(t, counting(&calls, answers(t, applied)), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = time.Minute

	a, err := probe.Observe(context.Background(), "gateway.a", want(7), false)
	require.NoError(t, err)
	b, err := probe.Observe(context.Background(), "gateway.b", want(3), false)
	require.NoError(t, err)
	c, err := probe.Observe(context.Background(), "gateway.c", want(2), false)
	require.NoError(t, err)

	assert.Equal(t, int32(2), a.Applied, "gateway.a applied of %d", a.Total)
	assert.Equal(t, int32(2), b.Applied, "gateway.b applied of %d", b.Total)
	assert.Zero(t, c.Applied, "gateway.c: the generation matches but the object does not")
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
	assert.Equal(t, int32(2), calls.Load(), "an observation within the freshness reused the round")

	_, err = probe.Observe(context.Background(), testDomain, want(7), true)
	require.NoError(t, err)
	assert.Equal(t, int32(4), calls.Load(), "the fresh observation took a round of its own")
}

// A round is reused while it is younger than the freshness and retaken from
// the moment it is that old: one request per replica just under the
// freshness, another round at it.
func TestObserve_aRoundIsRetakenAtItsFreshness(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, answers(t, appliedBy(7))), ready("ratelimit-a"))
	probe.Freshness = time.Minute
	now := time.Now()
	probe.Now = func() time.Time { return now }

	_, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)

	now = now.Add(time.Minute - time.Millisecond)
	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load(), "just under the freshness the round is reused")

	now = now.Add(time.Millisecond)
	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "at the freshness a round is taken")
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
	require.Equal(t, int32(2), first.Total)

	var slice discoveryv1.EndpointSlice
	writer := probe.Reader.(client.Client)
	require.NoError(t, writer.Get(context.Background(),
		client.ObjectKey{Namespace: testNamespace, Name: probeService + "-abc"}, &slice))
	slice.Endpoints = append(slice.Endpoints, ready("ratelimit-c"))
	require.NoError(t, writer.Update(context.Background(), &slice))

	second, err := probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(3), second.Total, "the joined pod is in the denominator at once")
	assert.Equal(t, int32(5), calls.Load(), "two requests for the first fleet, three for the changed one")

	_, err = probe.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(5), calls.Load(), "an unchanged fleet keeps the round")
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

	_, err := probe.Observe(context.Background(), "gateway.a", want(7), false)
	require.Error(t, err)
	_, err = probe.Observe(context.Background(), "gateway.b", want(7), false)
	require.Error(t, err)
	assert.Equal(t, int32(2), calls.Load(), "requests for two domains over two replicas")
}

// Without a freshness every observation is a round of its own; the older
// tests of this file leave the freshness at zero and count on it.
func TestObserve_withoutAFreshnessEveryObservationIsARound(t *testing.T) {
	var calls atomic.Int32
	probe := fleet(t, counting(&calls, answers(t, appliedBy(7))), ready("ratelimit-a"))

	for range 2 {
		_, err := probe.Observe(context.Background(), testDomain, want(7), false)
		require.NoError(t, err)
	}
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

	assert.Equal(t, taken, first.At)
	assert.Equal(t, taken, second.At, "a reused round keeps the time it was taken")
}

// fakeClock is a clock the test and the fleet's handlers advance from their
// own goroutines.
type fakeClock struct {
	base   time.Time
	offset atomic.Int64
}

func (c *fakeClock) now() time.Time { return c.base.Add(time.Duration(c.offset.Load())) }

func (c *fakeClock) advance(d time.Duration) { c.offset.Add(int64(d)) }

// The freshness counts from the end of a round, not from its start: a round
// whose replicas took twelve seconds of the clock to answer is still reused
// by the next domain under a freshness of ten, where a round aged from its
// start would have expired before it completed and the cycle would fall
// back to one round per domain.
func TestObserve_aSlowRoundIsStillReusedAfterItCompletes(t *testing.T) {
	var calls atomic.Int32
	clock := &fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	slow := func(w http.ResponseWriter, r *http.Request) {
		clock.advance(6 * time.Second)
		answers(t, appliedBy(7))(w, r)
	}
	probe := fleet(t, counting(&calls, slow), ready("ratelimit-a"), ready("ratelimit-b"))
	probe.Freshness = 10 * time.Second
	probe.Now = clock.now

	a, err := probe.Observe(context.Background(), "gateway.a", want(7), false)
	require.NoError(t, err)
	require.Equal(t, clock.base, a.At, "the view carries the start of the round")

	_, err = probe.Observe(context.Background(), "gateway.b", want(7), false)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "requests for two domains over two replicas, the second from the round")
}

// The replicas are asked together, so a round lasts one probe timeout at most
// rather than one per replica. The handler answers only once every replica's
// request is in flight, which a round that asked them one at a time could
// never reach: its first request would time out alone.
func TestObserve_asksTheReplicasTogether(t *testing.T) {
	const replicas = 3
	var arrived atomic.Int32
	together := func(w http.ResponseWriter, r *http.Request) {
		arrived.Add(1)
		deadline := time.Now().Add(3 * time.Second)
		for arrived.Load() < replicas && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		answers(t, appliedBy(7))(w, r)
	}
	probe := fleet(t, together, ready("ratelimit-a"), ready("ratelimit-b"), ready("ratelimit-c"))

	view, err := probe.Observe(context.Background(), testDomain, want(7), false)

	require.NoError(t, err)
	assert.Equal(t, int32(replicas), view.Applied, "every replica answered within one timeout")
	assert.Empty(t, view.Silent)
}

// A view says when the probe stops answering from its round: the round's
// completion plus the freshness, so a reconciler that requeues for that
// moment takes a new round rather than the same one again. A probe that
// reuses nothing says one interval after the fleet was asked.
func TestObserve_aViewSaysWhenItsRoundExpires(t *testing.T) {
	clock := &fakeClock{base: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)}
	slow := func(w http.ResponseWriter, r *http.Request) {
		clock.advance(6 * time.Second)
		answers(t, appliedBy(7))(w, r)
	}

	reusing := fleet(t, slow, ready("ratelimit-a"), ready("ratelimit-b"))
	reusing.Freshness = 10 * time.Second
	reusing.Now = clock.now
	view, err := reusing.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, clock.base.Add(22*time.Second), view.RefreshAt,
		"a round taken at the base and completed twelve seconds later, reused for ten more")

	clock.offset.Store(0)
	single := fleet(t, answers(t, appliedBy(7)), ready("ratelimit-a"))
	single.Now = clock.now
	view, err = single.Observe(context.Background(), testDomain, want(7), false)
	require.NoError(t, err)
	assert.Equal(t, clock.base.Add(ProbeInterval), view.RefreshAt,
		"a probe that reuses nothing wants the next look one interval after the ask")
}

package controller

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

// answers replies with one generation for every caller.
func answers(t *testing.T, applied map[string]store.Applied) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, store.AppliedPath, r.URL.Path, "the probe reads the documented path")
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

	view, err := probe.Observe(context.Background(), testDomain, want(7))

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

	view, err := probe.Observe(context.Background(), testDomain, want(7))

	require.NoError(t, err)
	assert.Zero(t, view.Applied)
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind)
}

func TestObserve_aReplicaOnAnotherGenerationIsBehind(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(6)), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7))

	require.NoError(t, err)
	assert.Equal(t, int32(1), view.Total)
	assert.Zero(t, view.Applied)
	assert.Equal(t, []string{"ratelimit-a"}, view.Behind)
}

// A replica that has never compiled this domain answers without it, which is
// the honest answer for a pod that is not ready either.
func TestObserve_aReplicaThatDoesNotKnowTheDomainIsBehind(t *testing.T) {
	probe := fleet(t, answers(t, map[string]store.Applied{"gateway.private": want(7)}), ready("ratelimit-a"))

	view, err := probe.Observe(context.Background(), testDomain, want(7))

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

	view, err := probe.Observe(context.Background(), testDomain, want(7))

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

	_, err := probe.Observe(context.Background(), testDomain, want(7))

	require.Error(t, err, "no answer at all is ProbeFailed, not a fleet of stale replicas")
	assert.Contains(t, err.Error(), store.AppliedPath)
}

func TestObserve_aBodyThatDoesNotDecodeIsSilence(t *testing.T) {
	probe := fleet(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}, ready("ratelimit-a"), ready("ratelimit-b"))

	_, err := probe.Observe(context.Background(), testDomain, want(7))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

// An empty fleet is not an error: it is the NoReplicas case, and the leader
// reports it rather than failing.
func TestObserve_anEmptyFleetIsObservedAsEmpty(t *testing.T) {
	probe := fleet(t, answers(t, appliedBy(7)))

	view, err := probe.Observe(context.Background(), testDomain, want(7))

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

	_, err := probe.Observe(context.Background(), testDomain, want(7))

	require.Error(t, err, "a fleet that cannot be listed is unobservable, not empty")
	assert.Contains(t, err.Error(), "EndpointSlice")
}

// failingReader stands in for an API server that will not answer.
type failingReader struct{ client.Reader }

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return assert.AnError
}

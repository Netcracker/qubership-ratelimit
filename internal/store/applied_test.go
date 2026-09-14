package store

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// The JSON this handler serves is the contract the leader parses to decide
// whether a policy is Ready. A change in its shape should fail here rather than
// in a cluster, where it surfaces as every replica silently counted behind.

func TestApplied_isEmptyUntilTheFirstRebuild(t *testing.T) {
	u := &Updater{}

	assert.Empty(t, u.Applied(),
		"a replica that has compiled nothing enforces nothing, and says so")
}

func TestApplied_publishClonesSoALaterRebuildCannotMutateAReaderSMap(t *testing.T) {
	u := &Updater{}
	live := map[string]Applied{"gateway.public": {Generation: 7, UID: "uid-1"}}
	u.applied.publish(live)

	// The caller keeps writing into the map it handed over, the way the next
	// rebuild would.
	live["gateway.public"] = Applied{Generation: 8, UID: "uid-1"}
	live["gateway.private"] = Applied{Generation: 1, UID: "uid-2"}

	published := u.Applied()
	assert.Equal(t, int64(7), published["gateway.public"].Generation,
		"a probe reading the published map must not see a half-finished rebuild")
	assert.NotContains(t, published, "gateway.private")
}

func TestApplied_publishReplacesTheWholeAnswer(t *testing.T) {
	u := &Updater{}
	u.applied.publish(map[string]Applied{"gateway.public": {Generation: 7}})
	u.applied.publish(map[string]Applied{"gateway.private": {Generation: 1}})

	published := u.Applied()
	assert.NotContains(t, published, "gateway.public",
		"a domain whose policy was deleted is no longer enforced by this replica")
	assert.Contains(t, published, "gateway.private")
}

func TestAppliedHandler_servesWhatTheReplicaEnforces(t *testing.T) {
	u := &Updater{}
	stamp := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	u.applied.publish(map[string]Applied{
		"gateway.public": {Generation: 7, UID: "uid-1", AppliedAt: stamp},
	})

	recorder := httptest.NewRecorder()
	AppliedHandler(u).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AppliedPath, nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"),
		"a cached answer would report a generation the replica has already left")

	var decoded map[string]Applied
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &decoded))
	assert.Equal(t, map[string]Applied{
		"gateway.public": {Generation: 7, UID: "uid-1", AppliedAt: stamp},
	}, decoded, "the leader decodes into this exact shape")
}

func TestAppliedHandler_answersAnEmptyObjectBeforeTheFirstRebuild(t *testing.T) {
	recorder := httptest.NewRecorder()
	AppliedHandler(&Updater{}).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, AppliedPath, nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.JSONEq(t, "{}", recorder.Body.String(),
		"an empty object decodes; a null body would make every leader treat this replica as unreachable")
}

// appliedOf is what turns a compilation into the answer above, and the
// generation it publishes is the one enforced rather than the one last written.
func TestAppliedOf_publishesTheEnforcedGenerationPerDomain(t *testing.T) {
	result := &policy.Result{Policies: map[client.ObjectKey]policy.Outcome{
		{Namespace: "biz", Name: "gateway.public"}: {
			UID: "uid-1", Generation: 8, ActiveGeneration: 7,
		},
	}}

	applied := appliedOf(result)

	require.Contains(t, applied, "gateway.public")
	assert.Equal(t, int64(7), applied["gateway.public"].Generation,
		"the leader compares against what runs, not against what was written last")
	assert.Equal(t, "uid-1", applied["gateway.public"].UID)
	assert.WithinDuration(t, time.Now(), applied["gateway.public"].AppliedAt, time.Minute)
}

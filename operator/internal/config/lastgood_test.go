package config

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/operator/internal/policy"
)

// recorded drains the events the recorder holds.
func recorded(recorder *events.FakeRecorder) []string {
	var out []string
	for {
		select {
		case event := <-recorder.Events:
			out = append(out, event)
		default:
			return out
		}
	}
}

// The writer's save drops a saved last-good generation this build cannot
// use, and no later compile can tell it was there, so the writer records the
// loss when it saves: a Warning on the policy that lost it, none on the
// others. The reason used to reach the status for one reconcile at most.
// Both policies have a latest generation that does not compile; the
// saved generation 7 of gateway.public does not compile either, and the saved
// generation 5 of gateway.private does, so only gateway.public loses it, and
// the save keeps only the generation that still serves.
func TestReconcile_warnsOnlyThePolicyThatLostItsLastGood(t *testing.T) {
	ghost := []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}}
	brokenPublic := goodSpec("gateway.public")
	brokenPublic.Limits[0].Rules[0].Matches = ghost
	brokenPrivate := goodSpec("gateway.private")
	brokenPrivate.Limits[0].Rules[0].Matches = ghost
	saved := written(t, map[string]policy.Bundle{
		"gateway.public":  {UID: "u-public", GoodGeneration: 7, GoodSpec: brokenPublic},
		"gateway.private": {UID: "u-private", GoodGeneration: 5, GoodSpec: goodSpec("gateway.private")},
	})
	c := fakeClient(t, saved,
		&v1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: unitNamespace, Name: "gateway.public", UID: "u-public", Generation: 8},
			Spec: brokenPublic,
		},
		&v1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: unitNamespace, Name: "gateway.private", UID: "u-private", Generation: 6},
			Spec: brokenPrivate,
		})
	store := New(c, unitNamespace, nil, "v", logr.Discard())
	recorder := events.NewFakeRecorder(4)
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: store, Events: recorder}

	_, err := r.Reconcile(t.Context(), reconcileRequest())

	require.NoError(t, err)
	warnings := recorded(recorder)
	require.Len(t, warnings, 1, "events recorded by Reconcile")
	assert.Contains(t, warnings[0], "Warning", "the event")
	assert.Contains(t, warnings[0], ReasonLastGoodLost, "the event")
	assert.Contains(t, warnings[0], "last-good generation 7 does not compile with this operator build", "the event")
	bundles, err := store.Load(t.Context(), []string{"gateway.public", "gateway.private"})
	require.NoError(t, err)
	assert.Equal(t, map[string]policy.Bundle{
		"gateway.private": {UID: "u-private", GoodGeneration: 5, GoodSpec: goodSpec("gateway.private")},
	}, bundles, "Load after Reconcile")
}

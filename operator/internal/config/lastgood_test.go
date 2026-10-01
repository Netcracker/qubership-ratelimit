package config

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/operator/internal/policy"
)

// The writer's save drops a saved last-good generation this build cannot
// use, and no later compile can tell it was there, so the writer records the
// loss when it saves: a Warning on the policy that lost it, none on the
// others. The reason used to reach the status for one reconcile at most.
func TestReportLostLastGood_warnsThePolicyThatLostIt(t *testing.T) {
	lost := v1.RateLimitPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "gateway.public"},
		Spec: v1.RateLimitPolicySpec{Domain: "gateway.public"}}
	kept := v1.RateLimitPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "gateway.private"},
		Spec: v1.RateLimitPolicySpec{Domain: "gateway.private"}}
	input := policy.Input{Namespace: "ns", Policies: []v1.RateLimitPolicy{lost, kept}}
	result := &policy.Result{Policies: map[client.ObjectKey]policy.Outcome{
		client.ObjectKeyFromObject(&lost): {LastGoodLost: "last-good generation 7 does not compile with this operator build"},
		client.ObjectKeyFromObject(&kept): {ActiveGeneration: 3},
	}}
	recorder := events.NewFakeRecorder(4)

	(&Reconciler{Events: recorder}).reportLostLastGood(context.Background(), input, result)

	require.Len(t, recorder.Events, 1, "one Warning, for the policy that lost its last-good")
	event := <-recorder.Events
	assert.Contains(t, event, "Warning")
	assert.Contains(t, event, ReasonLastGoodLost)
	assert.Contains(t, event, "last-good generation 7 does not compile with this operator build")
}

// Reconcile reaches the report: a saved last-good generation this build does
// not compile, under a latest generation that does not compile either, ends
// in one Warning on the policy, and the save drops the generation.
func TestReconcile_warnsThePolicyThatLostItsLastGood(t *testing.T) {
	broken := goodSpec("gateway.public")
	broken.Limits[0].Rules[0].Matches = []v1.Predicate{{Key: "ghost", Operator: v1.OperatorExists}}
	object := &v1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: unitNamespace, Name: "gateway.public", UID: "u", Generation: 8},
		Spec:       broken,
	}
	saved := written(t, map[string]policy.Bundle{"gateway.public": {UID: "u", GoodGeneration: 7, GoodSpec: broken}})
	c := fake.NewClientBuilder().WithScheme(unitScheme(t)).WithObjects(object, saved).Build()
	store := New(c, unitNamespace, nil, "v", logr.Discard())
	recorder := events.NewFakeRecorder(4)
	r := &Reconciler{Client: c, Namespace: unitNamespace, Store: store, Events: recorder}

	_, err := r.Reconcile(context.Background(), reconcileRequest())
	require.NoError(t, err)

	require.Len(t, recorder.Events, 1, "the loss of the saved generation left no event")
	event := <-recorder.Events
	assert.Contains(t, event, "Warning")
	assert.Contains(t, event, ReasonLastGoodLost)
	assert.Contains(t, event, "last-good generation 7 does not compile with this operator build")
	bundles, err := store.Load(context.Background(), []string{"gateway.public"})
	require.NoError(t, err)
	assert.Empty(t, bundles["gateway.public"].UID, "the save kept the generation it reported lost")
}

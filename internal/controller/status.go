package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// StateReader is the part of the state store a reconciler needs.
type StateReader interface {
	Load(ctx context.Context, domains []string) (map[string]policy.Bundle, error)
}

// propagationDeadline separates a rollout from a breakage. Under it, replicas
// still taking up a new generation are Propagating; over it they are
// ReplicaStale, which is the condition worth alerting on: a broken informer, or
// image version skew that a rollout is not going to resolve on its own.
const propagationDeadline = 30 * time.Second

// compile recompiles the namespace against the last-good state of one domain.
//
// The last-good state is part of the input rather than an afterthought.
// Compiling without it would report an object as contributing nothing while an
// earlier generation of it is still in effect — a status that contradicts the
// snapshot the replicas are serving from.
func compile(
	ctx context.Context,
	reader client.Reader,
	state StateReader,
	namespace, domain string,
) (*policy.Result, error) {
	input, err := policy.Load(ctx, reader, namespace)
	if err != nil {
		return nil, err
	}
	if state != nil {
		if input.State, err = state.Load(ctx, []string{domain}); err != nil {
			return nil, err
		}
	}
	return policy.Compile(input), nil
}

// setAccepted records whether the latest generation compiles.
//
// A false Accepted always carries CompilationFailed and a summary: the
// individual causes live in RuleProblems, because conditions are a map keyed by
// type and a generation can break in several places at once.
func setAccepted(object *v1alpha1.RateLimitPolicy, outcome policy.Outcome) {
	if outcome.Compiled() {
		setCondition(&object.Status.Conditions, v1alpha1.ConditionAccepted, metav1.ConditionTrue,
			v1alpha1.ReasonRulesCompiled,
			fmt.Sprintf("generation %d compiles: %d blocks, %d rules",
				outcome.Generation, outcome.Blocks, outcome.Rules),
			object.Generation)
		return
	}
	setCondition(&object.Status.Conditions, v1alpha1.ConditionAccepted, metav1.ConditionFalse,
		v1alpha1.ReasonCompilationFailed,
		fmt.Sprintf("generation %d does not compile: %s", outcome.Generation, outcome.Err),
		object.Generation)
}

// fleetStatus is the pair of conditions that answer "are the rules I wrote the
// rules being enforced, and if not, is that a rollout or a breakage".
type fleetStatus struct {
	ready        metav1.ConditionStatus
	readyReason  string
	readyMessage string

	stalled       metav1.ConditionStatus
	stalledReason string
}

// judge derives Ready and Stalled from the compilation and the fleet.
//
// Ready is true under exactly three conditions at once: the latest generation
// is the one compiled, it is the one enforced rather than a last-good spec, and
// every ready replica reports it. Stalled separates "still in progress" from
// "stuck", so that a rollout does not page anyone and a broken informer does.
func judge(outcome policy.Outcome, view FleetView, probeErr error, since time.Duration) fleetStatus {
	progressing := fleetStatus{stalled: metav1.ConditionFalse, stalledReason: v1alpha1.ReasonProgressing}

	switch {
	// A generation that does not compile is stuck whatever the replicas say,
	// and the leader knows it without asking them.
	case !outcome.Compiled():
		return fleetStatus{
			ready:         metav1.ConditionFalse,
			readyReason:   v1alpha1.ReasonNotCompiled,
			readyMessage:  notCompiledMessage(outcome),
			stalled:       metav1.ConditionTrue,
			stalledReason: v1alpha1.ReasonNotCompiled,
		}

	case probeErr != nil:
		// The leader does not know, and a guess would be worse than saying so.
		progressing.ready = metav1.ConditionUnknown
		progressing.readyReason = v1alpha1.ReasonProbeFailed
		progressing.readyMessage = fmt.Sprintf("the replicas could not be observed: %v", probeErr)

	case view.Total == 0:
		// A leader that is alive but is not itself a ready endpoint. With no
		// pod at all there is nobody to write this, and the age of
		// lastCheckTime is what shows that instead.
		progressing.ready = metav1.ConditionFalse
		progressing.readyReason = v1alpha1.ReasonNoReplicas
		progressing.readyMessage = "the service has no ready endpoint: nothing is enforcing this policy"

	case view.Applied == view.Total:
		progressing.ready = metav1.ConditionTrue
		progressing.readyReason = v1alpha1.ReasonAllReplicas
		progressing.readyMessage = fmt.Sprintf("all %d ready replicas enforce generation %d",
			view.Total, outcome.ActiveGeneration)

	case since > propagationDeadline:
		return fleetStatus{
			ready:         metav1.ConditionFalse,
			readyReason:   v1alpha1.ReasonReplicaStale,
			readyMessage:  behindMessage(outcome, view),
			stalled:       metav1.ConditionTrue,
			stalledReason: v1alpha1.ReasonReplicaStale,
		}

	case view.Applied == 0:
		progressing.ready = metav1.ConditionFalse
		progressing.readyReason = v1alpha1.ReasonReconciling
		progressing.readyMessage = behindMessage(outcome, view)

	default:
		progressing.ready = metav1.ConditionFalse
		progressing.readyReason = v1alpha1.ReasonPropagating
		progressing.readyMessage = behindMessage(outcome, view)
	}
	return progressing
}

// notCompiledMessage says what is enforced instead of the latest generation.
// The distinction that matters is whether anything is running at all.
func notCompiledMessage(outcome policy.Outcome) string {
	if outcome.ActiveGeneration == 0 {
		return policy.ErrNoGeneration.Error()
	}
	return fmt.Sprintf("generation %d does not compile; generation %d remains enforced",
		outcome.Generation, outcome.ActiveGeneration)
}

// behindMessage names the replicas that have not taken the generation up. It
// prints at most a few: the list is a pointer to the pods worth looking at, not
// an inventory.
func behindMessage(outcome policy.Outcome, view FleetView) string {
	const named = 3

	message := fmt.Sprintf("%d of %d replicas enforce generation %d",
		view.Applied, view.Total, outcome.ActiveGeneration)
	if len(view.Behind) == 0 {
		return message
	}
	behind := view.Behind
	suffix := ""
	if len(behind) > named {
		behind, suffix = behind[:named], fmt.Sprintf(" and %d more", len(view.Behind)-named)
	}
	return fmt.Sprintf("%s; %s%s report another", message, strings.Join(behind, ", "), suffix)
}

// readyAge is how long Ready has held its current status, which is what
// separates a rollout from a stuck one. A condition observed against an older
// generation restarts the clock: the new edit has its own rollout.
func readyAge(object *v1alpha1.RateLimitPolicy, now time.Time) time.Duration {
	condition := meta.FindStatusCondition(object.Status.Conditions, v1alpha1.ConditionReady)
	if condition == nil || condition.ObservedGeneration != object.Generation {
		return 0
	}
	return now.Sub(condition.LastTransitionTime.Time)
}

// setCondition records one condition, carrying the generation into the condition
// itself: metav1.Condition has an ObservedGeneration of its own, and a reader
// comparing it with metadata.generation is how staleness is detected per condition
// rather than per object.
func setCondition(
	conditions *[]metav1.Condition,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
	generation int64,
) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            truncateMessage(message),
		ObservedGeneration: generation,
	})
}

// writeStatus persists the status if it changed, and reports whether it did.
//
// Skipping an unchanged write is not an optimization: the update would come back
// as an event and reconcile the object again, forever.
func writeStatus(
	ctx context.Context,
	writer client.StatusClient,
	object client.Object,
	before, after any,
) (bool, error) {
	if equalStatus(before, after) {
		return false, nil
	}
	if err := writer.Status().Update(ctx, object); err != nil {
		return false, fmt.Errorf("update RateLimitPolicy status: %w", err)
	}
	return true, nil
}

// equalStatus reports whether a status write would change anything. Semantic
// equality is the right comparison here: it treats a nil slice and an empty one as
// equal, which is what the API server does on the way back out.
func equalStatus(before, after any) bool {
	return apiequality.Semantic.DeepEqual(before, after)
}

// maxMessageLength is the limit the API server puts on a condition message.
const maxMessageLength = 32768

func truncateMessage(message string) string {
	if len(message) <= maxMessageLength {
		return message
	}
	return message[:maxMessageLength-3] + "..."
}

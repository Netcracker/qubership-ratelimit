package controller

import (
	"context"
	"fmt"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// The two reconcilers differ only in the middle: which outcome they read, which
// status fields they fill, and how they word Ready. Everything around that — the
// compilation they read from, the Accepted condition, and the write — is the same
// work, and is done here so the two cannot drift into disagreeing about it.

// StateReader is the part of the state store a reconciler needs.
type StateReader interface {
	Load(ctx context.Context, domains []string) (map[string]policy.Bundle, error)
}

// compile recompiles the namespace against the last-good state of one domain.
//
// The whole domain is compiled rather than the one object being reconciled,
// because a rule is only diagnosable in the context of its domain: whether a key
// exists depends on the mapping, and so does whether a group exists.
//
// The last-good state is part of the input rather than an afterthought. Compiling
// without it would report an object as contributing nothing while an earlier
// generation of it is still in effect — a status that contradicts the snapshot.
func compile(
	ctx context.Context,
	reader client.Reader,
	state StateReader,
	domain string,
) (*policy.Result, error) {
	input, err := policy.Load(ctx, reader)
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

// fetchAndCompile fetch the object, give up quietly if it is already gone, and recompile its domain.
//
// It reports whether the object still exists. A deleted object needs no cleanup
// in either kind — there are no finalizers, and the store updater drops it on the
// same informer event — so "not found" is a plain return rather than an error.
func fetchAndCompile[T client.Object](
	ctx context.Context,
	c client.Client,
	state StateReader,
	key client.ObjectKey,
	object T,
	domainOf func(T) string,
) (*policy.Result, bool, error) {
	if err := c.Get(ctx, key, object); err != nil {
		return nil, false, client.IgnoreNotFound(err)
	}
	result, err := compile(ctx, c, state, domainOf(object))
	if err != nil {
		return nil, false, err
	}
	return result, true, nil
}

// observe records which generation was seen and which one is in effect. The pair
// is one concept, and writing it in one place keeps a reconciler from updating
// half of it.
func observe(status *v1alpha1.GenerationStatus, seen, active int64) {
	status.ObservedGeneration = seen
	status.ActiveGeneration = active
}

// setAccepted records the Accepted condition, which reports structural validity.
//
// A spec the compiler rejects structurally is the only way it goes false, so the
// failing reason and message are always the same and the caller supplies only the
// wording for success.
func setAccepted(
	conditions *[]metav1.Condition,
	generation int64,
	err error,
	reason, message string,
) {
	status := metav1.ConditionTrue
	if err != nil {
		status, reason, message = metav1.ConditionFalse, v1alpha1.ReasonInvalidSpec, err.Error()
	}
	setCondition(conditions, v1alpha1.ConditionAccepted, status, reason, message, generation)
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
	kind string,
	before, after any,
) (bool, error) {
	if equalStatus(before, after) {
		return false, nil
	}
	if err := writer.Status().Update(ctx, object); err != nil {
		return false, fmt.Errorf("update %s status: %w", kind, err)
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

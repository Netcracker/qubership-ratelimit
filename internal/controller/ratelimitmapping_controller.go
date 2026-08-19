package controller

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// RateLimitMappingReconciler reconciles a RateLimitMapping object.
type RateLimitMappingReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// State reads the persisted last-good specs. Without them the gate would be
	// evaluated against "nothing is running", and a candidate that breaks live
	// rules would look acceptable.
	State StateReader
}

// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitmappings/status,verbs=get;update;patch

// Reconcile publishes the effective key set of the domain.
//
// The status is the one place a rule author can look up what a predicate may
// reference: the built-in keys plus whatever the mapping declared.
//
// Deleting a mapping needs no cleanup either: the domain falls back to the
// built-in keys on the same informer event, and the policies that depended on the
// declared keys lose validity with a problem of their own.
func (r *RateLimitMappingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var object v1alpha1.RateLimitMapping
	result, found, err := fetchAndCompile(ctx, r.Client, r.State, req.NamespacedName, &object,
		func(m *v1alpha1.RateLimitMapping) string { return m.Spec.Domain })
	if err != nil || !found {
		return ctrl.Result{}, err
	}
	outcome := result.Mappings[req.NamespacedName]

	status := object.Status.DeepCopy()
	observe(&object.Status.GenerationStatus, object.Generation, outcome.ActiveGeneration)
	object.Status.EffectiveKeys = outcome.EffectiveKeys
	object.Status.RejectedBy = outcome.RejectedBy

	setAccepted(&object.Status.Conditions, object.Generation, outcome.Err,
		v1alpha1.ReasonKeysResolved,
		fmt.Sprintf("%d keys in effect for domain %s: %s",
			len(outcome.EffectiveKeys), object.Spec.Domain, strings.Join(outcome.EffectiveKeys, ", ")))

	switch {
	case outcome.Ready():
		setCondition(&object.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionTrue,
			v1alpha1.ReasonSnapshotApplied, "The compiled extractor is the one serving checks.",
			object.Generation)
	case len(outcome.RejectedBy) > 0:
		// The gate vetoed this generation. Naming the count is what tells the
		// author whether one team is behind or the change is broadly breaking.
		setCondition(&object.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse,
			v1alpha1.ReasonRejectedByPolicies,
			fmt.Sprintf("generation %d would break %d running %s; generation %d remains active",
				outcome.Generation, len(outcome.RejectedBy),
				plural(len(outcome.RejectedBy), "policy", "policies"), outcome.ActiveGeneration),
			object.Generation)
	default:
		setCondition(&object.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse,
			v1alpha1.ReasonInvalidSpec,
			"The domain falls back to the built-in keys until the spec is corrected.", object.Generation)
	}

	written, err := writeStatus(ctx, r.Client, &object, "RateLimitMapping", status, &object.Status)
	if err != nil || !written {
		return ctrl.Result{}, err
	}
	log.Info("mapping reconciled",
		"domain", object.Spec.Domain,
		"generation", object.Generation,
		"activeGeneration", outcome.ActiveGeneration,
		"effectiveKeys", len(outcome.EffectiveKeys),
		"rejectedBy", len(outcome.RejectedBy),
	)
	return ctrl.Result{}, nil
}

func plural(count int, one, many string) string {
	if count == 1 {
		return one
	}
	return many
}

// SetupWithManager registers the reconciler with the manager.
func (r *RateLimitMappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.RateLimitMapping{}).
		// A policy decides whether a candidate mapping is accepted, so the veto
		// list of the mapping has to be recomputed when a policy changes.
		Watches(&v1alpha1.RateLimitPolicy{}, handler.EnqueueRequestsFromMapFunc(mappingOfDomain)).
		Named("ratelimitmapping").
		Complete(r)
}

// mappingOfDomain maps a policy to the mapping of its domain, which is the object
// named after that domain.
func mappingOfDomain(_ context.Context, object client.Object) []reconcile.Request {
	policyObject, ok := object.(*v1alpha1.RateLimitPolicy)
	if !ok {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{
			Namespace: policyObject.Namespace,
			Name:      policyObject.Spec.Domain,
		},
	}}
}

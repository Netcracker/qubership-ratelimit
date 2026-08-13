// Package controller reconciles RateLimitPolicy status.
//
// Status writes are the only leader-gated work in the operator: the rule store
// and the RLS endpoint run on every replica (see internal/store and internal/rls).
package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// RateLimitPolicyReconciler reconciles a RateLimitPolicy object.
type RateLimitPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitpolicies/status,verbs=get;update;patch

// Reconcile records that the operator has seen the policy.
func (r *RateLimitPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var policy ratelimitv1alpha1.RateLimitPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		// A deleted policy needs no cleanup: there are no finalizers, and the
		// store updater drops it on the same informer event.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	changed := meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:   ratelimitv1alpha1.ConditionAccepted,
		Status: metav1.ConditionTrue,
		// metav1.Condition.Reason is required and MinLength=1, so an empty value
		// is rejected by the API server, not merely ugly.
		Reason:             "Accepted",
		Message:            fmt.Sprintf("Policy is bound to domain %q.", policy.Spec.Domain),
		ObservedGeneration: policy.Generation,
	})
	if policy.Status.ObservedGeneration != policy.Generation {
		policy.Status.ObservedGeneration = policy.Generation
		changed = true
	}
	if !changed {
		return ctrl.Result{}, nil
	}

	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("update RateLimitPolicy status: %w", err)
	}
	log.Info("policy accepted", "domain", policy.Spec.Domain, "generation", policy.Generation)
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *RateLimitPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&ratelimitv1alpha1.RateLimitPolicy{}).
		Named("ratelimitpolicy").
		Complete(r)
}

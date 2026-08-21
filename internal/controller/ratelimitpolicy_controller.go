// Package controller writes the status of the custom resources.
//
// Status writes are the only leader-gated work in the operator: the rule store
// and the RLS endpoint run on every replica (see internal/store and internal/rls).
// A reconciler therefore never decides anything the engine depends on — it reads
// the same pure compilation the engine reads and reports what it says.
package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// RateLimitPolicyReconciler reconciles a RateLimitPolicy object.
type RateLimitPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// State reads the persisted last-good specs, so the status reports what the
	// engine enforces rather than what a compilation from scratch would produce.
	State StateReader
}

// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitpolicies;ratelimitmappings,verbs=get;list;watch
// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",namespace=ratelimit-system,resources=configmaps,verbs=get;list;create;update;patch;delete

// Reconcile compiles the domain of the policy and reports what the compiler said
// about this object.
//
// The whole domain is compiled rather than this one object, because a rule is
// only diagnosable in the context of its domain: whether a key exists depends on
// the mapping, and whether a group exists depends on the mapping too.
//
// A deleted policy needs no cleanup: there are no finalizers, and the store
// updater drops it on the same informer event.
func (r *RateLimitPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var object v1alpha1.RateLimitPolicy
	result, found, err := fetchAndCompile(ctx, r.Client, r.State, req.NamespacedName, &object,
		func(p *v1alpha1.RateLimitPolicy) string { return p.Spec.Domain })
	if err != nil || !found {
		return ctrl.Result{}, err
	}
	outcome := result.Policies[req.NamespacedName]

	status := object.Status.DeepCopy()
	observe(&object.Status.GenerationStatus, object.Generation, outcome.ActiveGeneration)
	object.Status.RuleProblems = outcome.Problems
	object.Status.Problems = int32(len(outcome.Problems))

	setAccepted(&object.Status.Conditions, object.Generation, outcome.Err,
		v1alpha1.ReasonRulesCompiled,
		fmt.Sprintf("%d blocks, %d rules compiled for domain %s",
			outcome.Blocks, outcome.Rules, object.Spec.Domain))

	if outcome.Ready() {
		setCondition(&object.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionTrue,
			v1alpha1.ReasonSnapshotApplied, "The compiled snapshot is the one serving checks.",
			object.Generation)
	} else {
		setCondition(&object.Status.Conditions, v1alpha1.ConditionReady, metav1.ConditionFalse,
			outcome.Reason, notReadyMessage(outcome), object.Generation)
	}

	written, err := writeStatus(ctx, r.Client, &object, "RateLimitPolicy", status, &object.Status)
	if err != nil || !written {
		return ctrl.Result{}, err
	}
	log.Info("policy reconciled",
		"domain", object.Spec.Domain,
		"generation", object.Generation,
		"activeGeneration", outcome.ActiveGeneration,
		"blocks", outcome.Blocks,
		"rules", outcome.Rules,
		"problems", len(outcome.Problems),
	)
	return ctrl.Result{}, nil
}

// notReadyMessage says what is enforced instead of the latest generation. The
// distinction that matters to whoever reads it is whether anything of this policy
// is running at all.
func notReadyMessage(outcome policy.PolicyOutcome) string {
	if outcome.ActiveGeneration == 0 {
		return fmt.Sprintf("generation %d is not enforced and no earlier generation is: "+
			"this policy contributes no rules", outcome.Generation)
	}
	return fmt.Sprintf("generation %d is not enforced; generation %d remains active",
		outcome.Generation, outcome.ActiveGeneration)
}

// SetupWithManager registers the reconciler with the manager.
func (r *RateLimitPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.RateLimitPolicy{}).
		// A mapping decides which keys and groups exist, so it decides which
		// rules are dead. Without this watch a rule fixed by adding a mapping
		// would keep its problem in the status until something else touched the
		// policy.
		Watches(&v1alpha1.RateLimitMapping{}, handler.EnqueueRequestsFromMapFunc(r.policiesOfDomain)).
		Named("ratelimitpolicy").
		Complete(r)
}

func (r *RateLimitPolicyReconciler) policiesOfDomain(ctx context.Context, object client.Object) []reconcile.Request {
	mapping, ok := object.(*v1alpha1.RateLimitMapping)
	if !ok {
		return nil
	}

	var list v1alpha1.RateLimitPolicyList
	if err := r.List(ctx, &list, client.InNamespace(mapping.Namespace)); err != nil {
		logf.FromContext(ctx).Error(err, "failed to list policies of a changed mapping",
			"domain", mapping.Spec.Domain)
		return nil
	}

	var requests []reconcile.Request
	for i := range list.Items {
		if list.Items[i].Spec.Domain != mapping.Spec.Domain {
			continue
		}
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&list.Items[i]),
		})
	}
	return requests
}

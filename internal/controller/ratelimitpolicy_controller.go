// Package controller writes the status of the custom resources.
//
// Status writes are the only leader-gated work in the operator: the rule store
// and the RLS endpoint run on every replica (see internal/store and internal/rls).
// A reconciler therefore never decides anything the engine depends on — it reads
// the same pure compilation the engine reads and reports what it says, plus the
// one thing only the leader can see: whether every replica agrees.
package controller

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// probeInterval is how often the leader re-reads the fleet while a generation
// is still propagating. Events cover the rest: a new generation or an
// EndpointSlice change reconciles on its own.
const probeInterval = 10 * time.Second

// RateLimitPolicyReconciler reconciles a RateLimitPolicy object.
type RateLimitPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Namespace is the component's own, a segment of every counter key.
	Namespace string

	// State reads the persisted last-good specs, so the status reports what the
	// engine enforces rather than what a compilation from scratch would produce.
	State StateReader

	// Probe reads the enforced generation from every ready replica. Without it
	// Ready cannot be established and reports ProbeFailed, which is the honest
	// answer for a leader that cannot see the fleet.
	Probe FleetProbe
}

// FleetProbe reports which replicas enforce which generation of a domain.
type FleetProbe interface {
	Observe(ctx context.Context, domain string, want store.Applied) (FleetView, error)
}

// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=ratelimit.netcracker.com,namespace=ratelimit-system,resources=ratelimitpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",namespace=ratelimit-system,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=discovery.k8s.io,namespace=ratelimit-system,resources=endpointslices,verbs=get;list;watch

// Reconcile compiles the domain of the policy, asks the replicas which
// generation they enforce, and reports both.
//
// A deleted policy needs no cleanup: there are no finalizers, and the store
// updater drops it on the same informer event.
func (r *RateLimitPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var object v1alpha1.RateLimitPolicy
	if err := r.Get(ctx, req.NamespacedName, &object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	result, err := compile(ctx, r.Client, r.State, r.Namespace, object.Spec.Domain)
	if err != nil {
		return ctrl.Result{}, err
	}
	outcome := result.Policies[req.NamespacedName]

	now := time.Now()
	view, probeErr := r.observe(ctx, &object, outcome)

	before := object.Status.DeepCopy()
	object.Status.ObservedGeneration = object.Generation
	object.Status.ActiveGeneration = outcome.ActiveGeneration
	object.Status.EffectiveKeys = outcome.EffectiveKeys
	object.Status.RuleProblems = outcome.Problems
	object.Status.Problems = int32(len(outcome.Problems))
	object.Status.Rules = int32(outcome.Rules)

	setAccepted(&object, outcome)

	// The clock for "is this a rollout or a breakage" starts when Ready first
	// went false for this generation, so it is read before the condition is
	// overwritten.
	judged := judge(outcome, view, probeErr, readyAge(&object, now))
	setCondition(&object.Status.Conditions, v1alpha1.ConditionReady,
		judged.ready, judged.readyReason, judged.readyMessage, object.Generation)
	setCondition(&object.Status.Conditions, v1alpha1.ConditionStalled,
		judged.stalled, judged.stalledReason, "", object.Generation)

	if probeErr == nil {
		object.Status.Replicas = v1alpha1.ReplicaStatus{
			Total:   view.Total,
			Applied: view.Applied,
			// Stamped below, and only when something else moved: a probe time
			// that advanced on its own would make every reconcile a write, and
			// every write another reconcile.
			LastCheckTime: before.Replicas.LastCheckTime,
		}
	}
	if !equalStatus(before, &object.Status) && probeErr == nil {
		object.Status.Replicas.LastCheckTime = &metav1.Time{Time: now}
	}

	written, err := writeStatus(ctx, r.Client, &object, before, &object.Status)
	if err != nil {
		return ctrl.Result{}, err
	}
	if written {
		log.Info("policy reconciled",
			"domain", object.Spec.Domain,
			"generation", object.Generation,
			"activeGeneration", outcome.ActiveGeneration,
			"rules", outcome.Rules,
			"problems", len(outcome.Problems),
			"replicas", view.Applied,
			"readyReplicas", view.Total,
			"ready", judged.readyReason,
		)
	}

	// A generation still spreading converges without an event, so the leader
	// comes back on its own rather than leaving the status behind the fleet.
	if judged.ready != metav1.ConditionTrue {
		return ctrl.Result{RequeueAfter: probeInterval}, nil
	}
	return ctrl.Result{}, nil
}

// observe asks the fleet which generation of this domain it enforces.
func (r *RateLimitPolicyReconciler) observe(
	ctx context.Context,
	object *v1alpha1.RateLimitPolicy,
	outcome policy.Outcome,
) (FleetView, error) {
	if r.Probe == nil {
		return FleetView{}, errNoProbe
	}
	return r.Probe.Observe(ctx, object.Spec.Domain, store.Applied{
		Generation: outcome.ActiveGeneration,
		UID:        outcome.UID,
	})
}

// SetupWithManager registers the reconciler with the manager.
func (r *RateLimitPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.RateLimitPolicy{}).
		Named("ratelimitpolicy").
		Complete(r)
}

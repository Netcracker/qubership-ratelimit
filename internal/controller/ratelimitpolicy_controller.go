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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// probeInterval is how often the leader re-reads the fleet. It runs on every
// reconcile, not only while a generation spreads: a replica can fall behind
// long after the status went green, and that transition produces no event on
// the policy itself. Events shorten the wait rather than replace it — a new
// generation or an EndpointSlice change reconciles on its own.
const probeInterval = 10 * time.Second

// lastCheckMaxAge bounds how stale status.replicas.lastCheckTime may look while
// nothing else about the status moves. The field documents the freshness of the
// probe, so a leader that keeps probing has to keep stamping it, but stamping
// every probe would write the object every probeInterval and reconcile it again
// on the way back. One write per domain per this interval is the compromise.
const lastCheckMaxAge = 5 * time.Minute

// RateLimitPolicyReconciler reconciles a RateLimitPolicy object.
type RateLimitPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Namespace is the component's own, a segment of every counter key.
	Namespace string

	// Service is the Service whose ready endpoints are the fleet. The watch on
	// its EndpointSlices is what turns a pod joining or leaving into a
	// reconcile; an empty name leaves the reconciler on its interval alone.
	Service string

	// State reads the persisted last-good specs, so the status reports what the
	// engine enforces rather than what a compilation from scratch would produce.
	State StateReader

	// Probe reads the enforced generation from every ready replica. Without it
	// Ready cannot be established and reports ProbeFailed, which is the honest
	// answer for a leader that cannot see the fleet.
	Probe FleetProbe

	// Events records the Warning a generation that does not compile raises.
	// It may be nil, which leaves the condition and the log as the only trace.
	Events events.EventRecorder
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

	// Read unstructured and decode here, for the reason policy.Load gives: a
	// typed read drops what this build does not know, and the status this
	// reconciler writes is where that has to be reported.
	stored := policy.Object()
	if err := r.Get(ctx, req.NamespacedName, stored); err != nil {
		if apierrors.IsNotFound(err) {
			// The name of a policy is its domain. Dropping the series here is
			// what keeps an alert on a stalled domain from firing forever on
			// an object nobody can fix, because it no longer exists.
			metrics.DropFleet(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	decoded, _, err := policy.Decode(stored)
	if err != nil {
		return ctrl.Result{}, err
	}
	object := *decoded

	result, err := compile(ctx, r.Client, r.State, r.Namespace, object.Spec.Domain)
	if err != nil {
		return ctrl.Result{}, err
	}
	// The skew of this object comes back through the same load every other
	// policy's does, so the outcome already carries it.
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
	// Read against the status as it was, before the write below overwrites it.
	newlyBroken := !outcome.Compiled() && turnedNotCompiled(before, object.Generation)

	// The clock for "is this a rollout or a breakage" starts when this
	// generation began spreading, so it is read before the condition is
	// overwritten and rewound by the write below.
	judged := judge(outcome, view, probeErr, readyAge(&object, now))
	setReadyCondition(&object.Status.Conditions,
		judged.ready, judged.readyReason, judged.readyMessage, object.Generation, now)
	setCondition(&object.Status.Conditions, v1alpha1.ConditionStalled,
		judged.stalled, judged.stalledReason, "", object.Generation)

	if probeErr == nil {
		object.Status.Replicas = v1alpha1.ReplicaStatus{
			Total:   view.Total,
			Applied: view.Applied,
			Summary: fmt.Sprintf("%d/%d", view.Applied, view.Total),
			// Carried over first, so that comparing the status against its
			// previous value below does not count this field as a change.
			LastCheckTime: before.Replicas.LastCheckTime,
		}
		if !equalStatus(before, &object.Status) || staleCheckTime(before.Replicas.LastCheckTime, now) {
			object.Status.Replicas.LastCheckTime = &metav1.Time{Time: now}
		}
	}

	// Published before the write, and whether or not it changes anything: these
	// series report what the leader last saw, and a scrape between two
	// unchanged reconciles has to keep seeing it.
	metrics.PublishFleet(object.Spec.Domain, metrics.FleetSample{
		Applied: object.Status.Replicas.Applied,
		Total:   object.Status.Replicas.Total,
		Stalled: judged.stalled == metav1.ConditionTrue,
		Reason:  judged.stalledReason,
	})

	written, err := writeStatus(ctx, r.Client, &object, before, &object.Status)
	if err != nil {
		return ctrl.Result{}, err
	}
	if newlyBroken && r.Events != nil {
		// After the write, not before: an event for a status that failed to
		// land would report a refusal nobody can see on the object.
		r.Events.Eventf(&object, nil, corev1.EventTypeWarning,
			v1alpha1.ReasonNotCompiled, "Compile",
			"generation %d does not compile: %s", object.Generation, outcome.Err)
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

	// The fleet changes without touching the policy: a pod restarts onto an
	// image that cannot compile the current generation and falls back to
	// last-good, and nothing about the object moves. Requeueing only while the
	// verdict is false would leave such a replica unnoticed until the next edit
	// or cache resync, which is exactly what Stalled exists to catch.
	return ctrl.Result{RequeueAfter: probeInterval}, nil
}

// staleCheckTime reports whether lastCheckTime has stood still long enough that
// a reader would take the leader for dead.
func staleCheckTime(last *metav1.Time, now time.Time) bool {
	return last == nil || now.Sub(last.Time) >= lastCheckMaxAge
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
//
// The EndpointSlice watch is what makes scaling visible: a pod joining or
// leaving changes the denominator of Ready without touching any policy, so
// without the watch status.replicas would hold its old fraction until the
// interval came round.
func (r *RateLimitPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Watched unstructured, so that this kind has one informer and it is the
	// one whose objects keep every field they were stored with.
	return ctrl.NewControllerManagedBy(mgr).
		For(policy.Object()).
		Watches(&discoveryv1.EndpointSlice{},
			handler.EnqueueRequestsFromMapFunc(r.policiesBehind)).
		Named("ratelimitpolicy").
		Complete(r)
}

// policiesBehind turns a change to the fleet's own EndpointSlice into a
// reconcile of every policy of the namespace. Slices of other Services are
// ignored: they say nothing about which replicas enforce these rules.
func (r *RateLimitPolicyReconciler) policiesBehind(
	ctx context.Context,
	object client.Object,
) []reconcile.Request {
	if r.Service == "" || object.GetLabels()[discoveryv1.LabelServiceName] != r.Service {
		return nil
	}

	// Unstructured, like every other read of this kind: it is the only informer
	// there is, and a typed list would ask the cache for one it does not have.
	// Nothing here reads the spec - the names are what become requests.
	list := policy.ObjectList()
	if err := r.List(ctx, list, client.InNamespace(object.GetNamespace())); err != nil {
		logf.FromContext(ctx).Error(err, "failed to list the policies of a changed EndpointSlice",
			"service", r.Service)
		return nil
	}

	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&list.Items[i]),
		})
	}
	return requests
}

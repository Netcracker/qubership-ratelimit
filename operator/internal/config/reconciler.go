package config

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/operator/internal/policy"
)

// Reconciler writes ratelimit-config. It is the operator's only writer of the
// object, and it runs on the leader: the Lease covers the overlap of two
// operator pods during a rollout.
//
// Every policy event, a change or a deletion of the ConfigMap itself, and the
// start of the process all reconcile the same one thing: the whole
// namespace. There is no per-object work, because the object is the
// namespace's, and a write is a compilation of every policy against the
// last-good state the object already holds, fitted to the size limit, and
// written back whole.
type Reconciler struct {
	client.Client

	// Namespace is the operator's own, and the one the ConfigMap lives in.
	Namespace string

	// Store reads and writes the object.
	Store *Store

	// Limit is the size the namespace's configuration must fit, in bytes.
	// Zero means policy.ConfigMapLimit, the API server's own wall; a test
	// sets a small one so the size path runs on a small object.
	Limit int
}

func (r *Reconciler) limit() int {
	if r.Limit > 0 {
		return r.Limit
	}
	return policy.ConfigMapLimit
}

// The operator creates and updates one ConfigMap and touches no other: create
// is the one verb RBAC cannot narrow by name, and the rest are granted on
// ratelimit-config alone. list and watch pass under the name because the
// cache selects the object by metadata.name (CacheOptions). The Deployment
// it reads is its own, which the chart narrows by name too.
// +kubebuilder:rbac:groups="",namespace=ratelimit-system,resources=configmaps,verbs=create
// +kubebuilder:rbac:groups="",namespace=ratelimit-system,resources=configmaps,resourceNames=ratelimit-config,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=apps,namespace=ratelimit-system,resources=deployments,verbs=get

// Reconcile compiles the namespace and writes the result. The request names
// the ConfigMap, whatever event brought it here.
func (r *Reconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	input, err := policy.Load(ctx, r.Client, r.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	// The last-good state of every domain, because the fit is a question
	// about the namespace's total and the status reconciler runs the same
	// fit over the same bundles.
	if input.State, err = r.Store.Load(ctx, policy.Domains(input)); err != nil {
		return ctrl.Result{}, err
	}
	result := policy.Compile(input)
	policy.Fit(input, result, r.limit())

	if err := r.Store.Save(ctx, result.State, r.limit()); err != nil {
		log.Error(err, "failed to write the configuration")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler: it owns the ConfigMap, follows
// every policy of the namespace, and runs once at start.
//
// The start is what a fresh namespace needs. With no policy there is no
// policy event, and with no ConfigMap there is no ConfigMap event, and the
// service would wait NotReady for an object nobody writes. The kick is a
// source of one event, sent when the manager starts the controller, which
// is after it took the lease.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	request := reconcile.Request{NamespacedName: types.NamespacedName{
		Namespace: r.Namespace, Name: contract.ConfigMapName}}
	toTheOne := handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
		return []reconcile.Request{request}
	})

	kick := make(chan event.TypedGenericEvent[client.Object], 1)
	kick <- event.TypedGenericEvent[client.Object]{Object: &corev1.ConfigMap{}}

	return ctrl.NewControllerManagedBy(mgr).
		Named("ratelimit-config").
		// The object itself: a deletion is a recreate, an edit by anyone else
		// is overwritten on the next pass.
		Watches(&corev1.ConfigMap{}, toTheOne, builder.WithPredicates(predicate.NewPredicateFuncs(
			func(object client.Object) bool {
				return object.GetNamespace() == r.Namespace && object.GetName() == contract.ConfigMapName
			}))).
		// Spec changes only: a status write of the probe cycle changes nothing
		// the writer reads, and without the predicate each one would cost a
		// recompile and a read of the object. Creates and deletes pass.
		Watches(policy.Object(), toTheOne, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WatchesRawSource(source.Channel(kick, toTheOne)).
		Complete(r)
}

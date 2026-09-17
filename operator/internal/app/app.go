// Package app is the operator's composition root: it builds the manager
// with both controllers registered and the probes wired, and hands it back
// unstarted. Everything a cluster is needed for happens in Start, which is
// main's; everything up to it is here, where an envtest can exercise it.
package app

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/internal/controller"
	"github.com/netcracker/qubership-ratelimit/internal/leader"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
	"github.com/netcracker/qubership-ratelimit/internal/process"
	"github.com/netcracker/qubership-ratelimit/operator/internal/config"
)

// ManagedBy labels the ConfigMap the operator writes, and names the event
// recorder.
const ManagedBy = "ratelimit-operator"

// Options is what the flags and the environment decided.
type Options struct {
	// ProbeAddr and MetricsAddr are the bind addresses of the health probes
	// and the Prometheus endpoint.
	ProbeAddr, MetricsAddr string

	// Deployment is the operator's own Deployment, which owns the
	// configuration ConfigMap.
	Deployment string

	// Version is stamped into the manifest as operatorVersion.
	Version string

	// LeaderElection is off only in a test that starts the manager itself.
	// In the binary it is always on: the Lease covers the overlap of two
	// pods during a rollout, which is the only time there are two.
	LeaderElection bool

	// Log is the logger the components write through.
	Log logr.Logger

	// Warn takes the lines that are not errors but that an operator should
	// read on startup, such as an owner the store could not find.
	Warn func(format string, args ...any)
}

// Build wires the operator: the manager with the split's cache, the
// configuration store and its writer, the status reconciler over the
// service's replicas, and the probes. It returns the manager unstarted.
func Build(restConfig *rest.Config, scheme *runtime.Scheme, namespace string, options Options) (ctrl.Manager, error) {
	warn := options.Warn
	if warn == nil {
		warn = func(string, ...any) {}
	}

	// The lease is signed with the pod name, so the leader a reader finds on
	// the Lease is the pod they can look at. Outside a pod the hostname
	// stands in, and that is worth a line in the log.
	if process.PodName() == "" {
		warn("POD_NAME is not set, so the lease is signed with the hostname")
	}
	lock, err := leader.Lock(restConfig, namespace)
	if err != nil {
		return nil, err
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                              scheme,
		Metrics:                             metricsserver.Options{BindAddress: options.MetricsAddr},
		HealthProbeBindAddress:              options.ProbeAddr,
		Client:                              controller.ClientOptions(),
		LeaderElection:                      options.LeaderElection,
		LeaderElectionID:                    leader.LeaseName,
		LeaderElectionResourceLockInterface: lock,
		// Read only when the lock is nil, which is a run outside a pod:
		// controller-runtime then builds the lock itself and has no pod to
		// take the namespace from.
		LeaderElectionNamespace: namespace,
		Cache:                   config.CacheOptions(namespace),
	})
	if err != nil {
		return nil, fmt.Errorf("create manager: %w", err)
	}
	// The fleet series of the status reconciler ride the manager's metrics
	// endpoint.
	metrics.Register(ctrlmetrics.Registry)

	// The configuration store reads and writes through an uncached client:
	// the object is read once per reconcile and written once.
	direct, err := client.New(restConfig, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return nil, fmt.Errorf("create the direct client: %w", err)
	}
	store := config.New(direct, namespace, map[string]string{
		"app.kubernetes.io/managed-by": ManagedBy,
	}, options.Version, options.Log.WithName("config"))
	adopt, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := store.AdoptDeployment(adopt, direct, options.Deployment); err != nil {
		warn("%v", err)
	}
	cancel()

	writer := &config.Reconciler{Client: mgr.GetClient(), Namespace: namespace, Store: store}
	if err := writer.SetupWithManager(mgr); err != nil {
		return nil, fmt.Errorf("set up the configuration writer: %w", err)
	}

	status := &controller.RateLimitPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: namespace,
		Service:   contract.ServiceName,
		State:     store,
		Events:    mgr.GetEventRecorder(ManagedBy),
		// The service's replicas, reached on the port the Service publishes
		// under the contract name; the operator knows no bind address of
		// theirs. Port zero is what says "by name".
		Probe: &controller.ReplicaProbe{
			Reader:    mgr.GetCache(),
			Namespace: namespace,
			Service:   contract.ServiceName,
			Freshness: controller.ProbeInterval,
		},
		PropagationDeadline: controller.SplitPropagationDeadline,
		ConfigMapLimit:      policy.ConfigMapLimit,
	}
	if err := status.SetupWithManager(mgr); err != nil {
		return nil, fmt.Errorf("set up the RateLimitPolicy controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("add liveness check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return nil, fmt.Errorf("add readiness check: %w", err)
	}
	return mgr, nil
}

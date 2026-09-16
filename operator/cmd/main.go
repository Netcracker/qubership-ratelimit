// The operator: the control-plane half of the split. It reconciles the
// RateLimitPolicy objects of its namespace into one ConfigMap the service
// mounts, writes the policy status, and reads the service replicas of the
// other Deployment to judge Ready. It serves no traffic and holds no counter
// store; it is the only process of the delivery with a Role.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/controller"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
	"github.com/netcracker/qubership-ratelimit/internal/process"
	"github.com/netcracker/qubership-ratelimit/operator/internal/config"
)

// loggerName prefixes every log line this process writes.
const loggerName = "ratelimit-operator"

// managedBy labels the ConfigMap the operator writes.
const managedBy = "ratelimit-operator"

// version is stamped into the manifest as operatorVersion. It is set by the
// build through -ldflags; "dev" is a local build.
var version = "dev"

var (
	scheme   = runtime.NewScheme()
	setupLog logging.Logger
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ratelimitv1alpha1.AddToScheme(scheme))
}

func main() {
	var probeAddr, metricsAddr, deployment string

	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the Prometheus metrics endpoint binds to. \"0\" disables it.")
	flag.StringVar(&deployment, "deployment", "",
		"The operator's own Deployment, which owns the configuration ConfigMap so that it goes with the "+
			"operator. Defaults to microservice.name.")
	flag.Parse()

	configloader.InitWithSourcesArray(configloader.BasePropertySources())
	ctxmanager.Register([]ctxmanager.ContextProvider{xrequestid.XRequestIdProvider{}})

	setupLog = logging.GetLogger(loggerName)
	logrLogger := process.NewLogrLogger(loggerName)
	ctrl.SetLogger(logrLogger)
	klog.SetLogger(logrLogger)

	if deployment == "" {
		deployment = configloader.GetOrDefaultString("microservice.name", "ratelimit-operator")
	}
	if err := run(probeAddr, metricsAddr, deployment); err != nil {
		setupLog.Errorf("operator exited with an error: %v", err)
		os.Exit(1)
	}
}

func run(probeAddr, metricsAddr, deployment string) error {
	namespace, err := process.Namespace()
	if err != nil {
		return err
	}
	restConfig := ctrl.GetConfigOrDie()

	// The lease is signed with the pod name, so the leader a reader finds on
	// the Lease is the pod they can look at. Outside a pod the hostname
	// stands in, and that is worth a line in the log.
	if process.LeaderIdentity() == "" {
		setupLog.Warnf("POD_NAME is not set, so the lease is signed with the hostname")
	}
	lock, err := process.LeaderLock(restConfig, namespace)
	if err != nil {
		return err
	}

	// The cache of the one-binary packaging, plus the one ConfigMap this
	// process owns: watched by name, so that the informer holds one object
	// and not every ConfigMap of the namespace.
	cacheOptions := controller.CacheOptions(namespace)
	cacheOptions.ByObject[&corev1.ConfigMap{}] = cache.ByObject{
		Namespaces: map[string]cache.Config{namespace: {
			FieldSelector: fields.OneTermEqualSelector("metadata.name", contract.ConfigMapName),
		}},
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		Client:                 controller.ClientOptions(),
		// Always on, with one replica: the Lease covers the overlap of two
		// pods during a rollout, which is the only time there are two.
		LeaderElection:                      true,
		LeaderElectionID:                    process.LeaseName,
		LeaderElectionResourceLockInterface: lock,
		Cache:                               cacheOptions,
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// The configuration store reads and writes through an uncached client:
	// the object is read once per reconcile and written once.
	direct, err := client.New(restConfig, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return fmt.Errorf("create the direct client: %w", err)
	}
	store := config.New(direct, namespace, map[string]string{
		"app.kubernetes.io/managed-by": managedBy,
	}, version, process.NewLogrLogger(loggerName).WithName("config"))
	setOwner(direct, store, namespace, deployment)

	writer := &config.Reconciler{Client: mgr.GetClient(), Namespace: namespace, Store: store}
	if err := writer.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the configuration writer: %w", err)
	}

	status := &controller.RateLimitPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: namespace,
		Service:   contract.ServiceName,
		State:     store,
		Events:    mgr.GetEventRecorder(managedBy),
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
		return fmt.Errorf("set up the RateLimitPolicy controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add liveness check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	setupLog.Infof("starting operator namespace=%v deployment=%v leaderIdentity=%v version=%v",
		namespace, deployment, process.LeaderIdentity(), version)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

// setOwner points the store at the operator's own Deployment, so the
// ConfigMap it writes is garbage-collected with the operator and never with
// a policy. A Deployment the operator cannot read leaves the object without
// an owner rather than unwritten: a missing owner costs a manual cleanup, a
// missing ConfigMap costs the service its configuration.
func setOwner(reader client.Reader, store *config.Store, namespace, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var owner appsv1.Deployment
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &owner); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			setupLog.Warnf("could not read Deployment %s within 10s; %s is written without an owner", name, contract.ConfigMapName)
			return
		}
		setupLog.Warnf("could not read Deployment %s: %v; %s is written without an owner", name, err, contract.ConfigMapName)
		return
	}
	store.SetOwner(&owner, "apps/v1", "Deployment")
}

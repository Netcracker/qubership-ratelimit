package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/controller"
	"github.com/netcracker/qubership-ratelimit/internal/rls"
	"github.com/netcracker/qubership-ratelimit/internal/state"
	"github.com/netcracker/qubership-ratelimit/internal/store"
	// +kubebuilder:scaffold:imports
)

// Modes select which components this process runs. Controller and RLS engine
// share one binary and one Deployment today; the flag exists so that splitting
// them later is a Helm change rather than a refactor.
const (
	modeAll        = "all"
	modeController = "controller"
	modeRLS        = "rls"
)

// loggerName prefixes every log line this service writes. Sub-loggers are
// derived from it, e.g. ratelimit/rls.
const loggerName = "ratelimit"

// managedBy marks the objects this operator creates for itself. It is a separate
// constant from loggerName on purpose: one is a logging concern and the other is
// object metadata, and renaming the log prefix must not relabel stored state.
const managedBy = "ratelimit"

var (
	scheme   = runtime.NewScheme()
	setupLog logging.Logger
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ratelimitv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var mode string
	var probeAddr string
	var rlsAddr string
	var enableLeaderElection bool
	var storeDebounce time.Duration
	var drainTimeout time.Duration

	flag.StringVar(&mode, "mode", modeAll,
		"Components to run: all, controller (status writes only) or rls (rate limit endpoint only).")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&rlsAddr, "rls-bind-address", ":9000", "The address the rate limit gRPC endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election. Only status writes are leader-gated; the rate limit endpoint "+
			"and its store run on every replica.")
	flag.DurationVar(&storeDebounce, "store-debounce", store.DefaultDebounce,
		"How long to collect resource events before rebuilding the rule store.")
	flag.DurationVar(&drainTimeout, "rls-drain-timeout", rls.DefaultDrainTimeout,
		"How long in-flight rate limit checks may delay shutdown.")

	flag.Parse()

	// Properties first, loggers second: LOG_LEVEL and the namespace both arrive
	// through configloader, and logging.GetLogger reads its level from it.
	configloader.InitWithSourcesArray(configloader.BasePropertySources())

	ctxmanager.Register([]ctxmanager.ContextProvider{xrequestid.XRequestIdProvider{}})

	setupLog = logging.GetLogger(loggerName)
	// Route controller-runtime (logr) and client-go (klog) through the platform
	// logger too.
	logrLogger := newLogrLogger()
	ctrl.SetLogger(logrLogger)
	klog.SetLogger(logrLogger)

	if err := run(mode, probeAddr, rlsAddr, enableLeaderElection, storeDebounce, drainTimeout); err != nil {
		setupLog.Errorf("service exited with an error: %v", err)
		os.Exit(1)
	}
}

// getCloudNamespace returns the namespace the manager watches.
func getCloudNamespace() (string, error) {
	namespace := configloader.GetOrDefaultString("cloud.namespace", "")
	if namespace == "" {
		return "", fmt.Errorf("CLOUD_NAMESPACE must be set")
	}
	return namespace, nil
}

func run(
	mode, probeAddr, rlsAddr string,
	enableLeaderElection bool,
	storeDebounce, drainTimeout time.Duration,
) error {
	runController := mode == modeAll || mode == modeController
	runRLS := mode == modeAll || mode == modeRLS
	if !runController && !runRLS {
		return fmt.Errorf("unknown --mode %q, expected one of %q, %q, %q", mode, modeAll, modeController, modeRLS)
	}

	namespace, err := getCloudNamespace()
	if err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"}, // disabled for now
		HealthProbeBindAddress: probeAddr,
		// Only status writes are leader-gated. In rls mode nothing is, so the
		// process does not compete for a lease it would never use.
		LeaderElection:   enableLeaderElection && runController,
		LeaderElectionID: "ratelimit.netcracker.com",
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&ratelimitv1alpha1.RateLimitPolicy{}: {
					Namespaces: map[string]cache.Config{namespace: {}},
				},
				&ratelimitv1alpha1.RateLimitMapping{}: {
					Namespaces: map[string]cache.Config{namespace: {}},
				},
			},
			ReaderFailOnMissingInformer: true,
		},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// The last-good state lives in ConfigMaps read with an uncached client.
	stateClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return fmt.Errorf("create the state client: %w", err)
	}
	// Only what the operator can keep true. app.kubernetes.io/name is deliberately
	// absent: the chart derives it from .Values.nameOverride, which this process
	// cannot see, so setting it here would drift from every other object of the
	// release the moment someone overrides the name. These ConfigMaps are internal
	// state looked up by name, never by selector, so the label buys nothing.
	lastGood := state.New(stateClient, namespace, map[string]string{
		"app.kubernetes.io/managed-by": managedBy,
	})

	if runController {
		if err := (&controller.RateLimitPolicyReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			State:  lastGood,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up RateLimitPolicy controller: %w", err)
		}
		if err := (&controller.RateLimitMappingReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			State:  lastGood,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up RateLimitMapping controller: %w", err)
		}
	}
	// +kubebuilder:scaffold:builder

	var rlsRunner *rls.Runner
	if runRLS {
		ruleStore := store.New()
		updater := &store.Updater{
			Cache: mgr.GetCache(),
			Store: ruleStore,
			// In-memory counters: every replica counts alone. The Redis-backed
			// store plugs in here through the same interface and turns the
			// limits cluster-wide.
			Counters: memory.New(),
			Debounce: storeDebounce,
			Log:      newLogrLogger().WithName("store"),
			State:    lastGood,
			Elected:  mgr.Elected(),
		}
		if err := mgr.Add(updater); err != nil {
			return fmt.Errorf("add store updater: %w", err)
		}

		rlsRunner = &rls.Runner{
			Addr:         rlsAddr,
			Server:       rls.NewServer(ruleStore, logging.GetLogger(loggerName+"/rls")),
			DrainTimeout: drainTimeout,
			Log:          newLogrLogger().WithName("rls"),
		}
		if err := mgr.Add(rlsRunner); err != nil {
			return fmt.Errorf("add rls server: %w", err)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add liveness check: %w", err)
	}
	readyCheck := healthz.Ping
	if rlsRunner != nil {
		// Readiness follows the gRPC listener so a replica leaves the Service
		// endpoints the moment it stops answering checks.
		readyCheck = rlsRunner.Healthz
	}
	if err := mgr.AddReadyzCheck("readyz", readyCheck); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	setupLog.Infof("starting service mode=%v namespace=%v leaderElection=%v",
		mode, namespace, enableLeaderElection && runController)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

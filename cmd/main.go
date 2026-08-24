package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
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

	goredis "github.com/redis/go-redis/v9"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	enginestore "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
	"github.com/netcracker/qubership-ratelimit/internal/controller"
	"github.com/netcracker/qubership-ratelimit/internal/management"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
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
	var metricsAddr string
	var rlsAddr string
	var managementAddr string
	var corsOrigins string
	var enableLeaderElection bool
	var storeDebounce time.Duration
	var drainTimeout time.Duration

	flag.StringVar(&mode, "mode", modeAll,
		"Components to run: all, controller (status writes only) or rls (rate limit endpoint only).")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the Prometheus metrics endpoint binds to. \"0\" disables it.")
	flag.StringVar(&rlsAddr, "rls-bind-address", ":9000", "The address the rate limit gRPC endpoint binds to.")
	flag.StringVar(&managementAddr, "management-bind-address", ":8082",
		"The address the management API binds to. Empty disables it. Never route a gateway to this address: "+
			"its endpoints reset counters and lift limits.")
	flag.StringVar(&corsOrigins, "management-cors-origins", "",
		"Comma-separated origins a browser UI may call the management API from. Empty allows none.")
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

	options := runOptions{
		mode:                 mode,
		probeAddr:            probeAddr,
		metricsAddr:          metricsAddr,
		rlsAddr:              rlsAddr,
		managementAddr:       managementAddr,
		corsOrigins:          splitList(corsOrigins),
		enableLeaderElection: enableLeaderElection,
		storeDebounce:        storeDebounce,
		drainTimeout:         drainTimeout,
	}
	if err := run(options); err != nil {
		setupLog.Errorf("service exited with an error: %v", err)
		os.Exit(1)
	}
}

// runOptions collects what the flags decided. It replaces a parameter list
// that had grown past the point where a caller could tell two strings apart.
type runOptions struct {
	mode           string
	probeAddr      string
	metricsAddr    string
	rlsAddr        string
	managementAddr string
	corsOrigins    []string

	enableLeaderElection bool
	storeDebounce        time.Duration
	drainTimeout         time.Duration
}

// splitList parses a comma-separated flag, dropping empty entries so that a
// trailing comma does not become an origin that matches nothing.
func splitList(raw string) []string {
	var out []string
	for item := range strings.SplitSeq(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// replicaName is what this pod calls itself on the decision audit stream. The
// downward API supplies it; outside a cluster the hostname is close enough.
func replicaName() string {
	if name := configloader.GetOrDefaultString("pod.name", ""); name != "" {
		return name
	}
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

// newCounterStore picks where the counters live, and returns the client whose
// lifecycle the caller owns — the store never closes it.
//
// Redis is what makes a limit a limit of the domain rather than of each replica:
// with N replicas counting in their own memory, a limit of 100 admits 100*N. The
// in-process store is correct at one replica and for tests, and is what an empty
// address list selects.
//
// The topology is the caller's business, which is why the engine takes a
// UniversalClient: one address is a standalone server, several are a cluster, and
// a master name selects Sentinel. The domain hash tag in the counter keys keeps
// each decision on one Cluster slot, so the script is valid on all three.
func newCounterStore() counterBackend {
	addresses := configloader.GetOrDefaultString("redis.addresses", "")
	if addresses == "" {
		return counterBackend{
			store:       memory.New(),
			description: "in-process, counted per replica",
			scope:       management.ScopeReplica,
		}
	}

	shared := goredis.NewUniversalClient(&goredis.UniversalOptions{
		Addrs:      strings.Split(addresses, ","),
		Username:   configloader.GetOrDefaultString("redis.username", ""),
		Password:   configloader.GetOrDefaultString("redis.password", ""),
		DB:         redisDatabase(),
		MasterName: configloader.GetOrDefaultString("redis.masterName", ""),
	})
	return counterBackend{
		store:       redisstore.New(shared),
		closer:      shared,
		description: "redis at " + addresses,
		scope:       management.ScopeShared,
	}
}

// counterBackend is the chosen counter store and what the rest of the process
// needs to know about it: the client whose lifecycle the caller owns, a
// description for the startup line, and how far a reset through the management
// API reaches.
type counterBackend struct {
	store       enginestore.Store
	closer      io.Closer
	description string
	scope       management.CounterScope
}

// nearLimitRatio reads the near-limit margin for the metrics. The property
// key spells every hump as its own segment because the configloader turns
// each underscore of METRICS_NEAR_LIMIT_RATIO into a dot; a camelCase key
// would never see the variable.
func nearLimitRatio() float64 {
	raw := configloader.GetOrDefaultString("metrics.near.limit.ratio", "")
	if raw == "" {
		return rls.DefaultNearLimitRatio
	}
	ratio, err := strconv.ParseFloat(raw, 64)
	if err != nil || ratio <= 0 || ratio >= 1 {
		setupLog.Errorf("METRICS_NEAR_LIMIT_RATIO=%q is not a ratio in (0, 1), using %v",
			raw, rls.DefaultNearLimitRatio)
		return rls.DefaultNearLimitRatio
	}
	return ratio
}

// redisDatabase reads the database index.
func redisDatabase() int {
	raw := configloader.GetOrDefaultString("redis.db", "0")
	database, err := strconv.Atoi(raw)
	if err != nil {
		setupLog.Errorf("REDIS_DB=%q is not a number, using database 0", raw)
		return 0
	}
	return database
}

// managementOptions is what the management API needs from the process around
// it.
type managementOptions struct {
	addr        string
	corsOrigins []string
	namespace   string

	rules    *store.Store
	counters enginestore.Store
	scope    management.CounterScope

	switchboard *auditstream.Switchboard
	selection   *auditstream.Store
	hub         *auditstream.Hub
}

// addManagementAPI builds the control interface and registers it with the
// manager.
//
// It fails the process when it cannot be built rather than starting without
// it. A silently missing control interface is the worst of the three outcomes:
// the operator looks healthy, and the endpoint an engineer reaches for during
// an incident is not there.
func addManagementAPI(mgr ctrl.Manager, options managementOptions) error {
	auth, err := management.NewKubeAuth(mgr.GetConfig(), management.DefaultAuthCacheTTL)
	if err != nil {
		return fmt.Errorf("set up management authentication: %w", err)
	}

	api := &management.API{
		Rules:    options.rules,
		Counters: options.counters,
		Scope:    options.scope,
		Auditor: &management.KubeAuditor{
			Log:       newLogrLogger().WithName("management"),
			Recorder:  mgr.GetEventRecorder(loggerName + "-management"),
			Namespace: options.namespace,
		},
		Switchboard: options.switchboard,
		Selection:   options.selection,
		Hub:         options.hub,
		Replica:     replicaName(),
		Log:         newLogrLogger().WithName("management"),
	}

	if err := mgr.Add(&management.Runner{
		Addr:    options.addr,
		Handler: api.Handler(auth, auth, options.corsOrigins),
		Log:     newLogrLogger().WithName("management"),
	}); err != nil {
		return fmt.Errorf("add the management API: %w", err)
	}
	return nil
}

// getCloudNamespace returns the namespace the manager watches.
func getCloudNamespace() (string, error) {
	namespace := configloader.GetOrDefaultString("cloud.namespace", "")
	if namespace == "" {
		return "", fmt.Errorf("CLOUD_NAMESPACE must be set")
	}
	return namespace, nil
}

func run(options runOptions) error {
	mode := options.mode
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
		Metrics:                metricsserver.Options{BindAddress: options.metricsAddr},
		HealthProbeBindAddress: options.probeAddr,
		// Only status writes are leader-gated. In rls mode nothing is, so the
		// process does not compete for a lease it would never use.
		LeaderElection:   options.enableLeaderElection && runController,
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
	// release the moment someone overrides the name. The domain label the store
	// adds is what a new leader sweeps retired domains by.
	lastGood := state.New(stateClient, namespace, map[string]string{
		"app.kubernetes.io/managed-by": managedBy,
	}, newLogrLogger().WithName("state"), mgr.GetEventRecorder("ratelimit"))

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
	var ruleUpdater *store.Updater
	if runRLS {
		backend := newCounterStore()
		if backend.closer != nil {
			defer func() {
				if err := backend.closer.Close(); err != nil {
					setupLog.Errorf("failed to close the counter store: %v", err)
				}
			}()
		}
		setupLog.Infof("counter store selected backend=%v", backend.description)

		cacheStats := &engine.CacheStats{}
		metrics.RegisterCacheStats(cacheStats)

		ruleStore := store.New()
		updater := &store.Updater{
			Cache:      mgr.GetCache(),
			Store:      ruleStore,
			Debounce:   options.storeDebounce,
			Log:        newLogrLogger().WithName("store"),
			Counters:   backend.store,
			CacheStats: cacheStats,
			State:      lastGood,
			Elected:    mgr.Elected(),
		}
		if err := mgr.Add(updater); err != nil {
			return fmt.Errorf("add store updater: %w", err)
		}
		ruleUpdater = updater

		// The decision audit stream: a switchboard this replica reads on every
		// decision, and the shared selection every replica converges on.
		switchboard := auditstream.NewSwitchboard()
		hub := auditstream.NewHub()
		selection := &auditstream.Store{
			Client:    stateClient,
			Namespace: namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": managedBy},
		}
		if err := mgr.Add(&auditstream.Refresher{
			Store:       selection,
			Switchboard: switchboard,
			Log:         newLogrLogger().WithName("audit"),
		}); err != nil {
			return fmt.Errorf("add the decision audit refresher: %w", err)
		}

		if options.managementAddr != "" {
			if err := addManagementAPI(mgr, managementOptions{
				addr:        options.managementAddr,
				corsOrigins: options.corsOrigins,
				namespace:   namespace,
				rules:       ruleStore,
				counters:    backend.store,
				scope:       backend.scope,
				switchboard: switchboard,
				selection:   selection,
				hub:         hub,
			}); err != nil {
				return err
			}
		}

		rlsRunner = &rls.Runner{
			Addr: options.rlsAddr,
			Server: rls.NewServer(ruleStore, logging.GetLogger(loggerName+"/rls"),
				rls.WithDecisionAudit(switchboard, hub, replicaName()),
				rls.WithNearLimitRatio(nearLimitRatio())),
			DrainTimeout: options.drainTimeout,
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
		// Readiness follows the gRPC listener, so a replica leaves the Service
		// endpoints the moment it stops answering checks — and the rule store,
		// so it does not join them before it has rules. The listener comes up
		// first, and a replica answering from an empty store admits everything:
		// joining the endpoints in that state turns the limits off for a share
		// of the traffic on every rollout.
		readyCheck = func(req *http.Request) error {
			if err := rlsRunner.Healthz(req); err != nil {
				return err
			}
			if ruleUpdater != nil && !ruleUpdater.Ready() {
				return errors.New("the rate limit store has not been built yet")
			}
			return nil
		}
	}
	if err := mgr.AddReadyzCheck("readyz", readyCheck); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}

	setupLog.Infof("starting service mode=%v namespace=%v leaderElection=%v",
		mode, namespace, options.enableLeaderElection && runController)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

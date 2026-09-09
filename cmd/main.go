package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	// Sets GOMEMLIMIT from the container's memory limit at init, so the Go heap
	// starts collecting before the cgroup runs out and the kernel kills the pod.
	// It works by being imported and nothing calls into it.
	_ "github.com/netcracker/qubership-core-lib-go/v3/memlimit"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
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
	"github.com/netcracker/qubership-ratelimit/internal/controller"
	"github.com/netcracker/qubership-ratelimit/internal/management"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/internal/records"
	"github.com/netcracker/qubership-ratelimit/internal/rls"
	"github.com/netcracker/qubership-ratelimit/internal/state"
	"github.com/netcracker/qubership-ratelimit/internal/store"
	// +kubebuilder:scaffold:imports
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
	var probeAddr string
	var metricsAddr string
	var rlsAddr string
	var managementAddr string
	var serviceName string
	var storeDebounce time.Duration
	var drainTimeout time.Duration

	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"The address the Prometheus metrics endpoint binds to. \"0\" disables it.")
	flag.StringVar(&rlsAddr, "rls-bind-address", ":9000", "The address the rate limit gRPC endpoint binds to.")
	flag.StringVar(&managementAddr, "management-bind-address", "0",
		"The address the management API binds to. \"0\" disables it. It must never be reachable "+
			"from the data path: these endpoints lift limits.")
	flag.StringVar(&serviceName, "service-name", "",
		"The Service whose ready endpoints are this component's replicas. The leader reads the enforced "+
			"generation from each of them to decide whether a policy is Ready. Defaults to microservice.name.")
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
		probeAddr:      probeAddr,
		metricsAddr:    metricsAddr,
		rlsAddr:        rlsAddr,
		managementAddr: managementAddr,
		serviceName:    serviceName,
		storeDebounce:  storeDebounce,
		drainTimeout:   drainTimeout,
	}
	if err := run(options); err != nil {
		setupLog.Errorf("service exited with an error: %v", err)
		os.Exit(1)
	}
}

// runOptions collects what the flags decided. It replaces a parameter list
// that had grown past the point where a caller could tell two strings apart.
type runOptions struct {
	probeAddr      string
	metricsAddr    string
	rlsAddr        string
	managementAddr string
	serviceName    string

	storeDebounce time.Duration
	drainTimeout  time.Duration
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
		// The records live where the counters do. Leaving them nil would start
		// the management API with a nil store, and every mutation would panic
		// into an RLS-0500 while the reads kept working. In-process counting is
		// correct at one replica, and so are in-process records.
		counters := memory.New()
		return counterBackend{
			store:       counters,
			records:     records.NewMemory(counters),
			description: "in-process, counted per replica",
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
		records:     records.NewRedis(shared),
		closer:      shared,
		description: "redis at " + addresses,
		shared:      true,
	}
}

// counterBackend is the chosen counter store and what the rest of the process
// needs to know about it: the client whose lifecycle the caller owns, a
// description for the startup line.
type counterBackend struct {
	store       enginestore.Store
	records     records.Store
	closer      io.Closer
	description string

	// shared marks a store every replica counts in. Without one a limit of N
	// admits N per replica — and the management API's records are per replica
	// too.
	shared bool
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

// getCloudNamespace returns the namespace the manager watches.
func getCloudNamespace() (string, error) {
	namespace := configloader.GetOrDefaultString("cloud.namespace", "")
	if namespace == "" {
		return "", fmt.Errorf("CLOUD_NAMESPACE must be set")
	}
	return namespace, nil
}

// run wires the process together and hands it to the manager.
//
// Every replica runs both halves: the controller that writes status and the
// rate limit endpoint that answers checks. Each component is set up by its own
// function, which keeps the shape of the process readable here - namespace,
// manager, controllers, endpoint, probes.
func run(options runOptions) error {
	namespace, err := getCloudNamespace()
	if err != nil {
		return err
	}

	// The applied-generations endpoint is registered with the metrics server,
	// which the manager owns, while the updater that answers it is built after
	// the manager exists. The holder is what lets one refer to the other.
	applied := &deferredHandler{}

	mgr, err := newManager(options, namespace, applied)
	if err != nil {
		return err
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

	if err := addControllers(mgr, options, namespace, lastGood); err != nil {
		return err
	}
	// +kubebuilder:scaffold:builder

	limiter, err := addRateLimitEndpoint(mgr, options, namespace, lastGood)
	if err != nil {
		return err
	}
	applied.set(limiter.applied)
	// The counter store client outlives every runnable that uses it, so it is
	// released here rather than where it was built.
	defer closeCounterStore(limiter.closer)

	if err := addManagementAPI(mgr, options, namespace, limiter); err != nil {
		return err
	}

	if err := addProbes(mgr, limiter); err != nil {
		return err
	}

	setupLog.Infof("starting service namespace=%v leaderIdentity=%v", namespace, leaderIdentity())
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

// newManager builds the controller-runtime manager. The cache is scoped to the
// one namespace this installation serves, which is what keeps the operator's
// RBAC a Role rather than a ClusterRole.
func newManager(
	options runOptions,
	namespace string,
	applied http.Handler,
) (ctrl.Manager, error) {
	config := ctrl.GetConfigOrDie()

	// The lease is held under the pod's own name. Left to itself
	// controller-runtime signs the lease with the hostname plus a random
	// suffix, which is the pod name only by coincidence of how kubelet sets
	// the hostname, and never matches it once a pod sets hostname or
	// subdomain. The status messages name the replicas that lag by pod name,
	// so a reader comparing them against the lease holder has to be looking at
	// the same identifier.
	lock, err := leaderLock(config, namespace)
	if err != nil {
		return nil, err
	}

	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: options.metricsAddr,
			// Read-only diagnostics on the cluster-internal metrics port: the
			// leader reads it to learn which generation each replica enforces.
			// It is not the management API, carries no authentication, and is
			// outside the compatibility promises.
			ExtraHandlers: map[string]http.Handler{store.AppliedPath: applied},
		},
		HealthProbeBindAddress: options.probeAddr,
		// Always on. Only status writes are leader-gated - the rate limit
		// endpoint and its store run on every replica - and a status writer
		// that is not elected is two replicas writing conditions over each
		// other, so there is no deployment this is right to switch off.
		LeaderElection:                      true,
		LeaderElectionID:                    "ratelimit.netcracker.com",
		LeaderElectionResourceLockInterface: lock,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				// Unstructured, so that the objects reaching the compiler carry
				// every field they were stored with. A typed informer decodes
				// leniently and drops what this build's schema does not define,
				// which would enforce a newer object as the subset of itself
				// this build happens to understand. Registering the typed kind
				// as well would put a second informer and a second copy of
				// every object behind the same watch.
				policyInformerObject(): {
					Namespaces: map[string]cache.Config{namespace: {}},
				},
				// The leader reads the ready endpoints of its own Service to
				// learn which replicas enforce which generation. Only the
				// controller needs them, and only in its own namespace.
				&discoveryv1.EndpointSlice{}: {
					Namespaces: map[string]cache.Config{namespace: {}},
				},
			},
			ReaderFailOnMissingInformer: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create manager: %w", err)
	}
	return mgr, nil
}

// policyInformerObject names the kind the policy informer caches, in the
// unstructured form the compiler reads it in.
func policyInformerObject() client.Object {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(ratelimitv1alpha1.GroupVersion.WithKind("RateLimitPolicy"))
	return object
}

// leaderIdentity is the name this replica signs the lease with: the pod's own
// name, from the Downward API. It is empty outside a pod, where there is no
// pod name to borrow.
func leaderIdentity() string {
	return os.Getenv("POD_NAME")
}

// leaderLock builds the lease this replica competes for, signed with the pod
// name. It returns a nil lock when POD_NAME is unset, which hands the choice
// of identity back to controller-runtime: outside a pod - a local run, an
// envtest - the hostname is the only name there is, and refusing to start
// would make the binary unrunnable off-cluster for no gain.
//
// The renew deadline mirrors controller-runtime's own default, because it only
// sizes the client timeout of the lock; the manager keeps timing the election
// itself.
func leaderLock(config *rest.Config, namespace string) (resourcelock.Interface, error) {
	identity := leaderIdentity()
	if identity == "" {
		setupLog.Warnf("POD_NAME is not set, so the lease is signed with the hostname")
		return nil, nil
	}
	lock, err := resourcelock.NewFromKubeconfig(
		resourcelock.LeasesResourceLock,
		namespace,
		"ratelimit.netcracker.com",
		resourcelock.ResourceLockConfig{Identity: identity},
		config,
		10*time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("create the leader election lock: %w", err)
	}
	return lock, nil
}

// addControllers registers the reconcilers that write object status. They are
// the only leader-gated part of the process.
func addControllers(
	mgr ctrl.Manager,
	options runOptions,
	namespace string,
	lastGood *state.Store,
) error {
	reconciler := &controller.RateLimitPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: namespace,
		Service:   serviceName(options),
		State:     lastGood,
	}
	// A typed nil in an interface field is not nil, and the reconciler reads a
	// missing probe as "the fleet cannot be observed".
	if probe := replicaProbe(mgr, options, namespace); probe != nil {
		reconciler.Probe = probe
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up RateLimitPolicy controller: %w", err)
	}
	return nil
}

// replicaProbe builds the fleet probe, or returns nil when the metrics port is
// disabled: without it there is no /debug/applied to read, and a probe that
// cannot reach anybody would report every replica as behind rather than
// admitting it cannot see them.
func replicaProbe(mgr ctrl.Manager, options runOptions, namespace string) *controller.ReplicaProbe {
	port, err := portOf(options.metricsAddr)
	if err != nil {
		setupLog.Warnf("replica status is unavailable: %v", err)
		return nil
	}
	return &controller.ReplicaProbe{
		Reader:    mgr.GetCache(),
		Namespace: namespace,
		Service:   serviceName(options),
		Port:      port,
	}
}

// serviceName is the Service whose ready endpoints are the replicas: the flag
// when set, otherwise the platform's own name for this microservice.
func serviceName(options runOptions) string {
	if options.serviceName != "" {
		return options.serviceName
	}
	return configloader.GetOrDefaultString("microservice.name", "ratelimit")
}

// portOf reads the port out of a bind address. "0" and an empty address both
// mean the endpoint is disabled.
func portOf(addr string) (int, error) {
	if addr == "" || addr == "0" {
		return 0, errors.New("the metrics endpoint is disabled, so replicas cannot be probed")
	}
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("read the port of the metrics address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("the metrics address %q carries no usable port", addr)
	}
	return port, nil
}

// rateLimitEndpoint is what serving rate limit checks adds to the process: the
// gRPC runner and the store updater feeding it, plus the counter store client
// whose lifetime the caller owns.
type rateLimitEndpoint struct {
	runner  *rls.Runner
	updater *store.Updater
	closer  io.Closer

	// rules is the enforced rule set and counters is where it counts. The
	// management API reads both, so they are handed out rather than rebuilt:
	// an endpoint reporting a second copy of the rules would report something
	// other than what is being enforced.
	rules    *store.Store
	counters enginestore.Store

	// records is where accepted mutations are remembered, in the counter store
	// itself: losing both together leaves a re-executed reset over an empty
	// store, which is harmless, while losing one without the other would not
	// be.
	records records.Store

	// backend describes the counter store in the words the startup line uses,
	// which is what the status endpoint reports, and shared says whether every
	// replica counts in it.
	backend string
	shared  bool

	// applied answers the leader's probe with the generation this replica
	// enforces.
	applied http.Handler
}

// deferredHandler stands in for a handler that exists only once the manager
// does. Until then it answers 503: a replica that has not built its rule store
// is not enforcing anything, and the leader reads that as "behind", which it
// is.
type deferredHandler struct {
	inner atomic.Pointer[http.Handler]
}

func (d *deferredHandler) set(h http.Handler) {
	if h == nil {
		return
	}
	d.inner.Store(&h)
}

func (d *deferredHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	inner := d.inner.Load()
	if inner == nil {
		http.Error(w, "this replica is not serving rate limit checks", http.StatusServiceUnavailable)
		return
	}
	(*inner).ServeHTTP(w, r)
}

// addRateLimitEndpoint registers the decision path: the counter store, the rule
// store and its updater, the metrics it feeds, and the
// gRPC server itself.
func addRateLimitEndpoint(
	mgr ctrl.Manager,
	options runOptions,
	namespace string,
	lastGood *state.Store,
) (rateLimitEndpoint, error) {
	backend := newCounterStore()
	endpoint := rateLimitEndpoint{closer: backend.closer}
	setupLog.Infof("counter store selected backend=%v", backend.description)

	cacheStats := &engine.CacheStats{}
	metrics.RegisterCacheStats(cacheStats)

	ruleStore := store.New()
	endpoint.rules = ruleStore
	endpoint.counters = backend.store
	endpoint.records = backend.records
	endpoint.backend = backend.description
	endpoint.shared = backend.shared
	endpoint.updater = &store.Updater{
		Cache:      mgr.GetCache(),
		Store:      ruleStore,
		Namespace:  namespace,
		Debounce:   options.storeDebounce,
		Log:        newLogrLogger().WithName("store"),
		Counters:   backend.store,
		CacheStats: cacheStats,
		State:      lastGood,
		Elected:    mgr.Elected(),
	}
	if err := mgr.Add(endpoint.updater); err != nil {
		return endpoint, fmt.Errorf("add store updater: %w", err)
	}
	endpoint.applied = store.AppliedHandler(endpoint.updater)

	endpoint.runner = &rls.Runner{
		Addr: options.rlsAddr,
		Server: rls.NewServer(ruleStore, logging.GetLogger(loggerName+"/rls"),
			rls.WithNearLimitRatio(nearLimitRatio())),
		DrainTimeout: options.drainTimeout,
		Log:          newLogrLogger().WithName("rls"),
	}
	if err := mgr.Add(endpoint.runner); err != nil {
		return endpoint, fmt.Errorf("add rls server: %w", err)
	}
	return endpoint, nil
}

// managementClaims names the claims the subject and its roles are read from.
// Both accept a dotted path, because an IdP often nests the roles: Keycloak
// issues them under realm_access.roles.
func managementClaims() management.ClaimNames {
	return management.ClaimNames{
		Subject: configloader.GetOrDefaultString("management.claims.subject",
			management.DefaultClaimNames.Subject),
		Roles: configloader.GetOrDefaultString("management.claims.roles",
			management.DefaultClaimNames.Roles),
	}
}

// managementRoles maps the role names the IdP issues onto the two this API
// authorizes against. Both properties are comma-separated lists, and both
// default to the canonical name, which is what a deployment issuing "viewer"
// and "operator" already has.
func managementRoles() management.RoleMapping {
	return management.RoleMapping{
		Viewer:   csv(configloader.GetOrDefaultString("management.roles.viewer", management.RoleViewer)),
		Operator: csv(configloader.GetOrDefaultString("management.roles.operator", management.RoleOperator)),
	}
}

// csv splits a comma-separated property, dropping the empty entries a trailing
// comma or a blank value leaves behind.
func csv(value string) []string {
	var out []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// addManagementAPI registers the control interface, on its own listener.
//
// It is off unless an address is configured, and the address is never the one
// the gateways reach: these endpoints lift limits, so serving them on the data
// path would let the traffic being limited turn its own limits off. It follows
// the decision path rather than the controller — every replica serves it, for
// the same reason every replica answers checks, and a reset against a shared
// store takes effect wherever it lands.
func addManagementAPI(
	mgr ctrl.Manager,
	options runOptions,
	namespace string,
	limiter rateLimitEndpoint,
) error {
	if options.managementAddr == "" || options.managementAddr == "0" {
		return nil
	}

	if !limiter.shared {
		// The in-process counter store is a single-replica configuration by
		// definition, and the management API assumes a shared one: records,
		// confirmation tokens, and operations live beside the counters, so with
		// several replicas a retry that lands elsewhere finds nothing. The chart
		// keeps replicas at one in this configuration; this line is what a
		// deployment that got it wrong will find in its log.
		setupLog.Warnf("management API is serving over the in-process counter store; " +
			"it is correct at one replica only, like the limits themselves")
	}

	api := &management.API{
		Rules:          limiter.rules,
		Counters:       limiter.counters,
		Records:        limiter.records,
		Namespace:      namespace,
		Claims:         managementClaims(),
		Roles:          managementRoles(),
		CounterBackend: limiter.backend,
		Log:            logging.GetLogger(loggerName + "/management"),
	}
	app, err := management.NewApp(api)
	if err != nil {
		return err
	}
	runner := &management.Runner{
		Addr:         options.managementAddr,
		App:          app,
		API:          api,
		Log:          logging.GetLogger(loggerName + "/management"),
		DrainTimeout: options.drainTimeout,
	}
	if err := mgr.Add(runner); err != nil {
		return fmt.Errorf("add management api: %w", err)
	}
	return nil
}

// closeCounterStore releases the counter store client at shutdown. A process
// that never built one passes nil.
func closeCounterStore(closer io.Closer) {
	if closer == nil {
		return
	}
	if err := closer.Close(); err != nil {
		setupLog.Errorf("failed to close the counter store: %v", err)
	}
}

// addProbes wires liveness and readiness.
//
// Readiness follows the gRPC listener, so a replica leaves the Service
// endpoints the moment it stops answering checks — and the rule store, so it
// does not join them before it has rules. The listener comes up first, and a
// replica answering from an empty store admits everything: joining the
// endpoints in that state turns the limits off for a share of the traffic on
// every rollout.
func addProbes(mgr ctrl.Manager, limiter rateLimitEndpoint) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add liveness check: %w", err)
	}

	readyCheck := healthz.Ping
	if limiter.runner != nil {
		readyCheck = func(req *http.Request) error {
			if err := limiter.runner.Healthz(req); err != nil {
				return err
			}
			if limiter.updater != nil && !limiter.updater.Ready() {
				return errors.New("the rate limit store has not been built yet")
			}
			return nil
		}
	}
	if err := mgr.AddReadyzCheck("readyz", readyCheck); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}
	return nil
}

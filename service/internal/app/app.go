// Package app composes the service from its parts and runs them: the watcher
// of the mounted configuration, the rate limit gRPC endpoint, the management
// API, and the two HTTP listeners for metrics and probes. It holds no
// Kubernetes client; what it knows of the cluster is a directory and two
// environment variables the Downward API fills. main is flags and loggers
// around Build.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/service/internal/config"
	"github.com/netcracker/qubership-ratelimit/service/internal/management"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
	"github.com/netcracker/qubership-ratelimit/service/internal/settings"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

// Logger is the platform logger as the gRPC server and the management API
// take it.
type Logger interface {
	rls.Logger
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Options is what the flags and the environment decided.
type Options struct {
	ProbeAddr      string
	MetricsAddr    string
	RLSAddr        string
	ManagementAddr string

	// ConfigDir is the mounted ConfigMap, contract.MountPath in a pod.
	ConfigDir string

	// Resync is how often the watcher re-reads the directory on its own;
	// zero is config.DefaultResync.
	Resync time.Duration

	DrainTimeout time.Duration

	// Replica names this pod for the management API.
	Replica string

	// Log is the logr logger the watcher and the runners write through;
	// Platform is the platform logger the servers write through, and where
	// the wiring says what it chose.
	Log      logr.Logger
	Platform Logger
}

// Service is the built process, ready to Run.
type Service struct {
	watcher    *config.Watcher
	applier    *config.Applier
	rls        *rls.Runner
	management *management.Runner
	metrics    *http.Server
	probes     *http.Server
	closer     io.Closer
	log        logr.Logger

	// Registry is the metrics registry the metrics listener serves; it is
	// exported for a test that scrapes it in-process.
	Registry *prometheus.Registry
}

// Build wires the service. Nothing listens until Run.
func Build(namespace string, options Options) (*Service, error) {
	if options.ConfigDir == "" {
		options.ConfigDir = contract.MountPath
	}
	platform := options.Platform

	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics.Register(registry)

	backend := settings.CounterStore(platform.Errorf)
	platform.Infof("counter store selected backend=%v", backend.Description)

	cacheStats := &engine.CacheStats{}
	metrics.RegisterCacheStats(registry, cacheStats)

	rules := store.New()
	applier := &config.Applier{
		Namespace:  namespace,
		Store:      rules,
		Counters:   backend.Store,
		CacheStats: cacheStats,
		Log:        options.Log.WithName("config"),
	}
	service := &Service{
		applier: applier,
		watcher: &config.Watcher{
			Dir:     options.ConfigDir,
			Applier: applier,
			Log:     options.Log.WithName("config"),
			Resync:  options.Resync,
		},
		rls: &rls.Runner{
			Addr: options.RLSAddr,
			Server: rls.NewServer(rules, platform,
				rls.WithNearLimitRatio(settings.NearLimitRatio(platform.Errorf))),
			DrainTimeout: options.DrainTimeout,
			Log:          options.Log.WithName("rls"),
		},
		closer:   backend.Closer,
		log:      options.Log,
		Registry: registry,
	}

	if enabled(options.ManagementAddr) {
		if !backend.Shared {
			// The in-process counter store is a single-replica configuration
			// by definition, and the management API assumes a shared one:
			// records, confirmation tokens, and operations live beside the
			// counters, so with several replicas a retry that lands elsewhere
			// finds nothing. The chart keeps replicas at one in this
			// configuration; this line is what a deployment that got it wrong
			// will find in its log.
			platform.Warnf("management API is serving over the in-process counter store; " +
				"it is correct at one replica only, like the limits themselves")
		}
		api := &management.API{
			Rules:          rules,
			Counters:       backend.Store,
			Records:        backend.Records,
			Namespace:      namespace,
			Claims:         settings.ManagementClaims(),
			Roles:          settings.ManagementRoles(),
			Replica:        options.Replica,
			CounterBackend: backend.Description,
			Log:            platform,
		}
		app, err := management.NewApp(api)
		if err != nil {
			return nil, err
		}
		service.management = &management.Runner{
			Addr:         options.ManagementAddr,
			App:          app,
			API:          api,
			Log:          platform,
			DrainTimeout: options.DrainTimeout,
		}
	}

	if enabled(options.MetricsAddr) {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		// Read-only diagnostics on the cluster-internal metrics port: the
		// operator reads it to learn which generation each replica enforces.
		// It is not the management API, carries no authentication, and is
		// outside the compatibility promises.
		mux.Handle(contract.AppliedPath, applier.Handler())
		service.metrics = &http.Server{Addr: options.MetricsAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	}
	if enabled(options.ProbeAddr) {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.HandleFunc("/readyz", service.readyz)
		service.probes = &http.Server{Addr: options.ProbeAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	}
	return service, nil
}

// Ready reports whether this replica should take traffic: the gRPC listener
// is up and a configuration has been applied. The listener comes up first,
// and a replica answering from an empty store admits everything: joining the
// endpoints in that state turns the limits off for a share of the traffic.
func (s *Service) Ready() error {
	if err := s.rls.Healthz(nil); err != nil {
		return err
	}
	if !s.applier.Ready() {
		return errors.New("no configuration has been applied yet")
	}
	return nil
}

// Applied is what this replica enforces, for a test that does not scrape.
func (s *Service) Applied() *config.Applier { return s.applier }

func (s *Service) readyz(w http.ResponseWriter, _ *http.Request) {
	if err := s.Ready(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Run serves until ctx ends, then drains. The first runner to fail ends
// the others: a service that lost its gRPC listener has nothing left to
// be ready for.
func (s *Service) Run(ctx context.Context) error {
	defer s.close()
	group, ctx := errgroup.WithContext(ctx)

	group.Go(func() error { return s.watcher.Run(ctx) })
	group.Go(func() error { return s.rls.Start(ctx) })
	if s.management != nil {
		group.Go(func() error { return s.management.Start(ctx) })
	}
	for name, server := range map[string]*http.Server{"metrics": s.metrics, "probes": s.probes} {
		if server == nil {
			continue
		}
		group.Go(func() error { return serve(ctx, name, server) })
	}
	return group.Wait()
}

// serve runs one HTTP listener until ctx ends, then shuts it down.
func serve(ctx context.Context, name string, server *http.Server) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen for %s on %s: %w", name, server.Addr, err)
	}
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(listener) }()
	select {
	case err := <-errs:
		return fmt.Errorf("serve %s: %w", name, err)
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

// close releases the counter store client. It outlives every runner that
// uses it, so it is released here rather than where it was built.
func (s *Service) close() {
	if s.closer == nil {
		return
	}
	if err := s.closer.Close(); err != nil {
		s.log.Error(err, "failed to close the counter store")
	}
}

// enabled reads a bind address flag: "0" and empty both disable the listener.
func enabled(addr string) bool { return addr != "" && addr != "0" }

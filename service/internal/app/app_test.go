package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3/model/rest"

	envoycommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
	"github.com/netcracker/qubership-ratelimit/service/internal/settings"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// writeConfiguration puts a manifest with the given specs in dir, as the
// kubelet would.
func writeConfiguration(t *testing.T, dir string, specs ...v1.RateLimitPolicySpec) {
	t.Helper()
	m := manifest.Manifest{OperatorVersion: "t", Domains: map[string]manifest.Domain{}}
	for _, s := range specs {
		compressed, hash, err := manifest.EncodePayload(s)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, manifest.PayloadKey(s.Domain)), compressed, 0o600))
		m.Domains[s.Domain] = manifest.Domain{Generation: 1, UID: "uid-" + s.Domain, Hash: hash}
	}
	raw, err := manifest.Encode(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, contract.ManifestKey), raw, 0o600))
}

// oneShot sends every request on a connection of its own and closes it after
// the response. A poll that keeps a connection for reuse can leave one dialed
// and never used, and a server shutting down waits 5 s before it treats such a
// connection as idle.
var oneShot = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

// get answers the status and the body of a GET of url, or 0 and the error when
// the request does not complete.
func get(url string) (int, string) {
	resp, err := oneShot.Get(url) //nolint:gosec // a test-local address
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err.Error()
	}
	return resp.StatusCode, string(body)
}

// getOnceListening polls url until its listener answers, and returns the
// answer.
func getOnceListening(t *testing.T, url string) (code int, body string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		code, body = get(url)
		assert.NotZero(c, code, "GET %s: %s", url, body)
	}, 5*time.Second, 20*time.Millisecond, "a listener to answer GET %s", url)
	return code, body
}

// listeningOptions configures a service with every listener on a free local
// address, reading the configuration mounted in dir.
func listeningOptions(t *testing.T, dir string) Options {
	t.Helper()
	return Options{
		ProbeAddr:      freeAddr(t),
		MetricsAddr:    freeAddr(t),
		RLSAddr:        freeAddr(t),
		ManagementAddr: freeAddr(t),
		ConfigDir:      dir,
		Resync:         100 * time.Millisecond,
		DrainTimeout:   time.Second,
		Replica:        "ratelimit-0",
		Version:        "test-build",
		Log:            logr.Discard(),
		Platform:       logging.GetLogger("test"),
		counters:       inProcess(),
	}
}

// inProcess is a counter store in this process, for the tests whose subject is
// not the Redis the service counts in.
func inProcess() *settings.CounterBackend {
	counters := memory.New()
	return &settings.CounterBackend{
		Store:       counters,
		Management:  counters,
		Records:     records.NewMemory(counters),
		Description: "in process, for a test",
	}
}

// startService builds the service in namespace biz and runs it until the
// test ends. The cleanup stops it and fails the test when the run ended with
// an error.
func startService(t *testing.T, options Options) *Service {
	t.Helper()
	service, stop := runService(t, options)
	t.Cleanup(func() { require.NoError(t, stop(), "Run") })
	return service
}

// runService builds the service in namespace biz and runs it until stop is
// called or the test ends. stop waits for the run to end and returns its
// error, the same one on every call; the end of the test does not wait.
func runService(t *testing.T, options Options) (service *Service, stop func() error) {
	t.Helper()
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	service, err := Build("biz", options)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	return service, sync.OnceValue(func() error {
		cancel()
		return <-done
	})
}

// waitReady waits until the gRPC listener is up and a configuration is
// applied.
func waitReady(t *testing.T, service *Service) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NoError(c, service.Ready(), "Ready()")
	}, 5*time.Second, 20*time.Millisecond, "the service to become ready")
}

// checkerOf returns a function that sends one check of the path in the domain
// to the gRPC listener at addr.
func checkerOf(t *testing.T, addr string) func(domain, path string) envoyratelimit.RateLimitResponse_Code {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := envoyratelimit.NewRateLimitServiceClient(conn)
	return func(domain, path string) envoyratelimit.RateLimitResponse_Code {
		t.Helper()
		callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer callCancel()
		resp, err := client.ShouldRateLimit(callCtx, &envoyratelimit.RateLimitRequest{
			Domain: domain,
			Descriptors: []*envoycommon.RateLimitDescriptor{{Entries: []*envoycommon.RateLimitDescriptor_Entry{
				{Key: "path", Value: path}}}},
		})
		require.NoError(t, err, "ShouldRateLimit(domain=%q, path=%q)", domain, path)
		return resp.GetOverallCode()
	}
}

// appliedReport reads the applied report from the metrics listener at addr,
// or an empty one while it cannot.
func appliedReport(addr string) applied.Report {
	var report applied.Report
	if code, body := get("http://" + addr + contract.AppliedPath); code == http.StatusOK {
		_ = json.Unmarshal([]byte(body), &report)
	}
	return report
}

// A replica answering from an empty store admits everything, so the service
// stays NotReady while no configuration is mounted, however many resyncs of
// the directory pass, and an empty manifest is a configuration that makes it
// Ready. /healthz answers 200 meanwhile: a replica waiting for its
// configuration is alive.
func TestService_isNotReadyUntilAConfigurationIsApplied(t *testing.T) {
	dir := t.TempDir()
	options := listeningOptions(t, dir)
	startService(t, options)
	readyz := "http://" + options.ProbeAddr + "/readyz"
	healthz, _ := getOnceListening(t, "http://"+options.ProbeAddr+"/healthz")
	require.Equal(t, http.StatusOK, healthz, "GET /healthz")

	// Three resyncs of 100 ms pass with nothing to apply.
	assert.Never(t, func() bool { code, _ := get(readyz); return code == http.StatusOK },
		300*time.Millisecond, 20*time.Millisecond, "GET /readyz answered 200 with no configuration mounted")
	code, body := get(readyz)
	assert.Equal(t, http.StatusServiceUnavailable, code, "GET /readyz with no configuration mounted")
	assert.Contains(t, body, "no configuration", "GET /readyz body")

	writeConfiguration(t, dir)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		code, body := get(readyz)
		assert.Equal(c, http.StatusOK, code, "GET /readyz: %s", body)
	}, 5*time.Second, 20*time.Millisecond, "the service to become ready on an empty manifest")
}

// The applied report is served before anything is applied, with the manifest
// format versions this build reads.
func TestService_servesAnEmptyAppliedReportBeforeAnyConfiguration(t *testing.T) {
	options := listeningOptions(t, t.TempDir())
	startService(t, options)

	code, body := getOnceListening(t, "http://"+options.MetricsAddr+contract.AppliedPath)

	require.Equal(t, http.StatusOK, code, "GET %s: %s", contract.AppliedPath, body)
	var report applied.Report
	require.NoError(t, json.Unmarshal([]byte(body), &report), "GET %s body", contract.AppliedPath)
	assert.Empty(t, report.Domains, "Report.Domains")
	assert.Equal(t, manifest.SupportedVersions(), report.FormatVersions, "Report.FormatVersions")
}

// An empty manifest makes every request one for an unknown domain, which
// passes.
func TestService_admitsACheckOfADomainNoPolicyClaims(t *testing.T) {
	dir := t.TempDir()
	writeConfiguration(t, dir)
	options := listeningOptions(t, dir)
	service := startService(t, options)
	waitReady(t, service)

	code := checkerOf(t, options.RLSAddr)("gateway.public", "/api")

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, code, "check of /api in gateway.public")
}

// The metrics listener serves the service's own registry: the Go runtime's
// series, the build information, and the rebuild that applying the
// configuration counted. The operator's series have no place on the service's
// scrape. The rebuild counter is a package variable that every service this
// binary builds increments, so the test compares what it gained in this run.
func TestService_servesItsOwnRegistryOnTheMetricsListener(t *testing.T) {
	dir := t.TempDir()
	writeConfiguration(t, dir)
	options := listeningOptions(t, dir)
	rebuilds := testutil.ToFloat64(metrics.SnapshotRebuilds.WithLabelValues("ok"))
	service := startService(t, options)
	waitReady(t, service)

	code, body := getOnceListening(t, "http://"+options.MetricsAddr+"/metrics")

	require.Equal(t, http.StatusOK, code, "GET /metrics: %s", body)
	assert.Contains(t, body, `ratelimit_snapshot_rebuilds_total{result="ok"}`)
	assert.Contains(t, body, `ratelimit_build_info{component="service",version="test-build"} 1`)
	assert.Contains(t, body, "go_goroutines")
	assert.NotContains(t, body, "ratelimit_leader")
	assert.Equal(t, rebuilds+1, testutil.ToFloat64(metrics.SnapshotRebuilds.WithLabelValues("ok")),
		`ratelimit_snapshot_rebuilds_total{result="ok"}`)
}

// The management API answers on its own listener. A request under its base
// path without a bearer token reaches the API's identity check, which refuses
// it: 401, or 503 while no token verifier could be built, as on a machine with
// no service account token. A path outside the API answers 404 on the same
// listener, so the refusal comes from the API's routes and not from the
// listener.
func TestService_servesTheManagementAPIOnItsOwnListener(t *testing.T) {
	options := listeningOptions(t, t.TempDir())
	startService(t, options)
	routed := "http://" + options.ManagementAddr + "/ratelimit/v1/status"
	outside := "http://" + options.ManagementAddr + "/api/v1/status"

	code, body := getOnceListening(t, routed)
	outsideCode, outsideBody := get(outside)

	assert.Contains(t, []int{http.StatusUnauthorized, http.StatusServiceUnavailable}, code,
		"GET %s: %s", routed, body)
	assert.Equal(t, http.StatusNotFound, outsideCode, "GET %s: %s", outside, outsideBody)
}

// A configuration that changes while the service runs is applied, and the
// applied report lists the domain it brought.
func TestService_reportsADomainThatArrivesWhileRunning(t *testing.T) {
	dir := t.TempDir()
	writeConfiguration(t, dir)
	options := listeningOptions(t, dir)
	service := startService(t, options)
	waitReady(t, service)

	writeConfiguration(t, dir, v1.RateLimitPolicySpec{Domain: "gateway.public", Limits: []v1.LimitBlock{{
		Name: "api", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}})

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Contains(c, appliedReport(options.MetricsAddr).Domains, "gateway.public", "Report.Domains")
	}, 5*time.Second, 20*time.Millisecond, "the applied report to list gateway.public")
	assert.NoError(t, service.Ready(), "Ready()")
}

// The snapshot endpoint renders an applied domain, on the metrics listener.
func TestService_rendersAnAppliedDomainOnTheSnapshotEndpoint(t *testing.T) {
	dir := t.TempDir()
	writeConfiguration(t, dir, v1.RateLimitPolicySpec{Domain: "gateway.public", Limits: []v1.LimitBlock{{
		Name: "api", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}})
	options := listeningOptions(t, dir)
	service := startService(t, options)
	waitReady(t, service)

	code, body := getOnceListening(t, "http://"+options.MetricsAddr+contract.SnapshotPath+"/gateway.public")

	require.Equal(t, http.StatusOK, code, "GET %s/gateway.public: %s", contract.SnapshotPath, body)
	assert.Contains(t, body, `"id": "api/total"`)
}

// A replica told to count in a DBaaS database it cannot resolve does not
// start: counting in memory instead would give each replica its own limit,
// silently. The error names the classifier it looked for.
func TestService_refusesToStartWithoutItsCounterStoreConnection(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})

	_, err := Build("biz", Options{
		ProbeAddr: "0", MetricsAddr: "0", ManagementAddr: "0", RLSAddr: freeAddr(t),
		ConfigDir: t.TempDir(), RedisMicroservice: "ratelimit-service",
		RedisResolver: failingResolver{},
		Log:           logr.Discard(), Platform: logging.GetLogger("test"),
	})

	assert.ErrorContains(t, err, "ratelimit-service")
	assert.ErrorContains(t, err, "biz")
}

// failingResolver is a DBaaS client that finds nothing: no mounted Secret,
// and no token for the REST fallback.
type failingResolver struct{}

func (failingResolver) GetConnection(context.Context, string, map[string]any,
	rest.BaseDbParams) (map[string]any, error) {
	return nil, errors.New("no mounted Secret matches, and dbaas-agent answered 401")
}

// fixedResolver is a DBaaS client that finds the database at one URL.
type fixedResolver struct{ url string }

func (r fixedResolver) GetConnection(context.Context, string, map[string]any,
	rest.BaseDbParams) (map[string]any, error) {
	return map[string]any{"url": r.url}, nil
}

// warningLog is the platform logger with the warnings it is given kept for the
// test to read. The service warns from goroutines of its own.
type warningLog struct {
	Logger

	mu       sync.Mutex
	warnings []string
}

func (w *warningLog) Warnf(format string, args ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.warnings = append(w.warnings, fmt.Sprintf(format, args...))
}

// logged joins the warnings so far, one per line.
func (w *warningLog) logged() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.warnings, "\n")
}

// optionsOverRedisAt configures a service that counts in the DBaaS Redis its
// resolver finds at url, with an empty manifest mounted, the probe, metrics,
// and management listeners off, and a platform logger that keeps the warnings.
func optionsOverRedisAt(t *testing.T, url string) (Options, *warningLog) {
	t.Helper()
	dir := t.TempDir()
	writeConfiguration(t, dir)
	options := listeningOptions(t, dir)
	options.ProbeAddr, options.MetricsAddr, options.ManagementAddr = "0", "0", "0"
	options.counters = nil
	options.RedisMicroservice = "ratelimit-service"
	options.RedisResolver = fixedResolver{url: url}
	platform := &warningLog{Logger: logging.GetLogger("test")}
	options.Platform = platform
	return options, platform
}

// The service reads the counter store's eviction policy at start, and a store
// whose policy it cannot read is a warning in the log while the replica runs
// on: the policy belongs to the Redis adapter's installation, and a replica
// that refused to start over it would turn a risk under memory pressure into
// an outage. Nothing listens at the address the resolver names, so the read
// fails.
func TestService_warnsOfAnEvictionPolicyItCannotReadAndRunsOn(t *testing.T) {
	options, platform := optionsOverRedisAt(t, "redis://"+freeAddr(t))

	service := startService(t, options)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Contains(c, platform.logged(), "maxmemory-policy", "the warnings logged")
	}, 5*time.Second, 20*time.Millisecond, "a warning about the counter store's eviction policy")
	waitReady(t, service)
}

// A replica that shuts down before the counter store answers the read of its
// eviction policy has nothing to report about the store, and logs no warning.
// The store at the resolver's address takes the connection and never answers,
// so the read is in flight when the replica shuts down, and Run waits for it to
// end.
func TestService_warnsOfNothingWhenItShutsDownBeforeTheStoreAnswers(t *testing.T) {
	store, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	connected := make(chan net.Conn, 1)
	go func() {
		if conn, err := store.Accept(); err == nil {
			connected <- conn
		}
	}()
	options, platform := optionsOverRedisAt(t, "redis://"+store.Addr().String())
	_, stop := runService(t, options)
	select {
	case conn := <-connected:
		t.Cleanup(func() { _ = conn.Close() })
	case <-time.After(5 * time.Second):
		t.Fatal("waited 5s for the read of the eviction policy to connect to the store; none connected")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()

	select {
	case err := <-stopped:
		require.NoError(t, err, "Run")
	case <-time.After(10 * time.Second):
		t.Fatal("waited 10s for Run to end after the shutdown; it is still running")
	}
	assert.Empty(t, platform.logged(), "the warnings logged")
}

// The probe, metrics, and management listeners are optional, and "0" turns
// each off: a run with all three off becomes ready and ends without a listen
// error.
func TestService_runsWithEveryOptionalListenerOff(t *testing.T) {
	dir := t.TempDir()
	writeConfiguration(t, dir)
	options := listeningOptions(t, dir)
	options.ProbeAddr, options.MetricsAddr, options.ManagementAddr = "0", "0", "0"

	service := startService(t, options)

	waitReady(t, service)
}

// Nothing listens before Run, so a built service is not ready.
func TestService_isNotReadyBeforeRun(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	service, err := Build("biz", Options{
		ProbeAddr: "0", MetricsAddr: "0", ManagementAddr: "0", RLSAddr: freeAddr(t),
		ConfigDir: t.TempDir(), Log: logr.Discard(), Platform: logging.GetLogger("test"), counters: inProcess(),
	})
	require.NoError(t, err)

	assert.Error(t, service.Ready(), "Ready() before Run")
}

func TestService_reportsAListenerItCannotTake(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()
	service, err := Build("biz", Options{
		ProbeAddr: taken.Addr().String(), MetricsAddr: "0", ManagementAddr: "0", RLSAddr: freeAddr(t),
		ConfigDir: t.TempDir(), Log: logr.Discard(), Platform: logging.GetLogger("test"), counters: inProcess(),
	})
	require.NoError(t, err)
	// The deadline bounds a run that takes the listener after all, so the
	// test reports it rather than hanging.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err = service.Run(ctx)

	assert.ErrorContains(t, err, "listen for probes")
}

// onePerMinute admits one request per minute for the whole domain, on every
// path: the second decided check of the domain is refused.
func onePerMinute(domain string) v1.RateLimitPolicySpec {
	return v1.RateLimitPolicySpec{Domain: domain, Limits: []v1.LimitBlock{{
		Name: "all", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}}
}

// checker runs a service that enforces onePerMinute in gateway.private and in
// gateway.public, with the management API on managementAddr and no other
// optional listener, and returns a function that sends one check of the path
// to the service's gRPC listener.
func checker(t *testing.T, managementAddr string) func(domain, path string) envoyratelimit.RateLimitResponse_Code {
	t.Helper()
	dir := t.TempDir()
	writeConfiguration(t, dir, onePerMinute("gateway.private"), onePerMinute("gateway.public"))
	options := listeningOptions(t, dir)
	options.ProbeAddr, options.MetricsAddr, options.ManagementAddr = "0", "0", managementAddr
	service := startService(t, options)
	waitReady(t, service)
	return checkerOf(t, options.RLSAddr)
}

// With the management API on, a check of a path under its base path is exempt
// in the domains MANAGEMENT_GATEWAY_DOMAINS names: the second check passes
// where the domain admits one request per minute. The same path in another
// domain is decided, and its second check is refused.
func TestService_exemptsTheManagementPathsInTheGatewayDomains(t *testing.T) {
	t.Setenv("MANAGEMENT_GATEWAY_DOMAINS", "gateway.private")
	check := checker(t, freeAddr(t))

	const path = "/ratelimit/v1/status"
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("gateway.private", path),
		"the first check in gateway.private")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("gateway.private", path),
		"the second check in gateway.private")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("gateway.public", path),
		"the first check in gateway.public")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("gateway.public", path),
		"the second check in gateway.public")
}

// With the management API off, nothing serves its base path, and the path is
// decided like any other whatever MANAGEMENT_GATEWAY_DOMAINS names.
func TestService_exemptsNothingWithTheManagementAPIOff(t *testing.T) {
	t.Setenv("MANAGEMENT_GATEWAY_DOMAINS", "gateway.private")
	check := checker(t, "0")

	const path = "/ratelimit/v1/status"
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, check("gateway.private", path), "the first check")
	assert.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, check("gateway.private", path), "the second check")
}

// A service needs one Redis to count in, so a build that names none, or names
// two, is refused before anything listens. A service without one used to
// count in its own memory, a limit of N admitting N per replica.
func TestBuild_refusesAnythingButOneCounterStore(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	for name, options := range map[string]Options{
		"none": {},
		"two":  {RedisMicroservice: "ratelimit-service", RedisAddr: "127.0.0.1:6379"},
	} {
		t.Run(name, func(t *testing.T) {
			options.ProbeAddr, options.MetricsAddr, options.ManagementAddr = "0", "0", "0"
			options.RLSAddr, options.ConfigDir = freeAddr(t), t.TempDir()
			options.Log, options.Platform = logr.Discard(), logging.GetLogger("test")

			_, err := Build("biz", options)

			assert.ErrorContains(t, err, "--redis-")
		})
	}
}

// --redis-addr counts in the Redis at that address, without DBaaS, for the
// developer loop.
func TestCounterStore_countsInTheRedisAtRedisAddr(t *testing.T) {
	backend, connection, err := counterStore("biz", Options{RedisAddr: "127.0.0.1:6380", Log: logr.Discard()})

	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Closer.Close() })
	require.NotNil(t, connection, "the connection that keeps the credentials current")
	assert.Equal(t, "127.0.0.1:6380", connection.Connection().Addr())
	assert.Equal(t, "redis at 127.0.0.1:6380", backend.Description)
}

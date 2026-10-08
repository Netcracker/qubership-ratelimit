package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
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
	}
}

// startService builds the service in namespace biz and runs it until the
// test ends. The cleanup stops it and fails the test when the run ended with
// an error.
func startService(t *testing.T, options Options) *Service {
	t.Helper()
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	service, err := Build("biz", options)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done, "Run")
	})
	return service
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

func TestService_servesTheManagementAPIOnItsOwnListener(t *testing.T) {
	options := listeningOptions(t, t.TempDir())
	startService(t, options)
	url := "http://" + options.ManagementAddr + "/api/v1/status"

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		code, body := get(url)
		assert.NotZero(c, code, "GET %s: %s", url, body)
	}, 5*time.Second, 20*time.Millisecond, "the management listener to answer GET %s", url)
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
		ConfigDir: t.TempDir(), Log: logr.Discard(), Platform: logging.GetLogger("test"),
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
		ConfigDir: t.TempDir(), Log: logr.Discard(), Platform: logging.GetLogger("test"),
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

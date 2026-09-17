package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	envoycommon "github.com/envoyproxy/go-control-plane/envoy/extensions/common/ratelimit/v3"
	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/go-logr/logr"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
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
func writeConfiguration(t *testing.T, dir string, specs ...v1alpha1.RateLimitPolicySpec) {
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

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // a test-local address
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// The service, built and run against a directory: the whole of the ticket's
// definition of done, in one process.
func TestService_isNotReadyWithoutAConfigurationAndReadyOnAnEmptyOne(t *testing.T) {
	t.Setenv("REDIS_ADDRESSES", "")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	dir := t.TempDir()

	options := Options{
		ProbeAddr:      freeAddr(t),
		MetricsAddr:    freeAddr(t),
		RLSAddr:        freeAddr(t),
		ManagementAddr: freeAddr(t),
		ConfigDir:      dir,
		Resync:         100 * time.Millisecond,
		DrainTimeout:   time.Second,
		Replica:        "ratelimit-0",
		Log:            logr.Discard(),
		Platform:       logging.GetLogger("test"),
	}
	service, err := Build("biz", options)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	probes := "http://" + options.ProbeAddr
	require.Eventually(t, func() bool { code, _ := get(t, probes+"/healthz"); return code == http.StatusOK },
		5*time.Second, 20*time.Millisecond)

	// NotReady, and staying so: no configuration, no timeout.
	time.Sleep(300 * time.Millisecond)
	code, body := get(t, probes+"/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.Contains(t, body, "no configuration")

	// The report is served before anything is applied, with the versions.
	code, body = get(t, "http://"+options.MetricsAddr+contract.AppliedPath)
	require.Equal(t, http.StatusOK, code)
	var report applied.Report
	require.NoError(t, json.Unmarshal([]byte(body), &report))
	assert.Empty(t, report.Domains)
	assert.Equal(t, manifest.SupportedVersions(), report.FormatVersions)

	// An empty manifest: Ready, and every request an unknown domain, which
	// passes.
	writeConfiguration(t, dir)
	require.Eventually(t, func() bool { code, _ := get(t, probes+"/readyz"); return code == http.StatusOK },
		5*time.Second, 20*time.Millisecond)

	conn, err := grpc.NewClient(options.RLSAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	resp, err := envoyratelimit.NewRateLimitServiceClient(conn).ShouldRateLimit(callCtx, &envoyratelimit.RateLimitRequest{
		Domain: "gateway.public",
		Descriptors: []*envoycommon.RateLimitDescriptor{{Entries: []*envoycommon.RateLimitDescriptor_Entry{
			{Key: "path", Value: "/api"}}}},
	})
	require.NoError(t, err)
	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())

	// The metrics ride the plain registry, and say the swap happened.
	code, body = get(t, "http://"+options.MetricsAddr+"/metrics")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, `ratelimit_snapshot_rebuilds_total{result="ok"} 1`)
	assert.Contains(t, body, "go_goroutines")

	// The management API is up, on its own listener.
	code, _ = get(t, "http://"+options.ManagementAddr+"/api/v1/status")
	assert.NotEqual(t, 0, code, "the listener answers")

	// A domain arrives: enforced, reported.
	writeConfiguration(t, dir, v1alpha1.RateLimitPolicySpec{Domain: "gateway.public", Limits: []v1alpha1.LimitBlock{{
		Name: "api", Rules: []v1alpha1.Rule{{Name: "total", Rates: []v1alpha1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}})
	require.Eventually(t, func() bool {
		_, body := get(t, "http://"+options.MetricsAddr+contract.AppliedPath)
		return strings.Contains(body, `"gateway.public"`)
	}, 5*time.Second, 20*time.Millisecond)
	assert.NoError(t, service.Ready())
}

func TestService_buildsWithEveryListenerOff(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	service, err := Build("biz", Options{
		ProbeAddr: "0", MetricsAddr: "0", ManagementAddr: "0", RLSAddr: freeAddr(t),
		ConfigDir: t.TempDir(), Log: logr.Discard(), Platform: logging.GetLogger("test"),
	})
	require.NoError(t, err)
	assert.Nil(t, service.metrics)
	assert.Nil(t, service.probes)
	assert.Nil(t, service.management)
	assert.Error(t, service.Ready(), "nothing listens before Run")
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
	err = service.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen for probes")
}

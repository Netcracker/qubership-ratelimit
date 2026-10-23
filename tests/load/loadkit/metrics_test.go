package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rlsCluster = "outbound|9000||ratelimit.rl.svc.cluster.local"

// gatewayText is what the gateway's Envoy serves: the histogram and the
// timeouts of the rate limit service's cluster, the same of another cluster,
// and a family with two TYPE lines, which the text parser refuses.
const gatewayText = `# TYPE envoy_cluster_upstream_rq_time histogram
envoy_cluster_upstream_rq_time_bucket{cluster_name="outbound|9000||ratelimit.rl.svc.cluster.local",le="0.5"} 7
envoy_cluster_upstream_rq_time_bucket{cluster_name="outbound|9000||ratelimit.rl.svc.cluster.local",le="1"} 9
envoy_cluster_upstream_rq_time_bucket{cluster_name="outbound|9000||ratelimit.rl.svc.cluster.local",le="+Inf"} 10
envoy_cluster_upstream_rq_time_sum{cluster_name="outbound|9000||ratelimit.rl.svc.cluster.local"} 12
envoy_cluster_upstream_rq_time_count{cluster_name="outbound|9000||ratelimit.rl.svc.cluster.local"} 10
envoy_cluster_upstream_rq_time_bucket{cluster_name="outbound|8080||backend.rl.svc.cluster.local",le="0.5"} 500
envoy_cluster_upstream_rq_time_bucket{cluster_name="outbound|8080||backend.rl.svc.cluster.local",le="1"} 500
envoy_cluster_upstream_rq_time_bucket{cluster_name="outbound|8080||backend.rl.svc.cluster.local",le="+Inf"} 500
envoy_cluster_upstream_rq_time_sum{cluster_name="outbound|8080||backend.rl.svc.cluster.local"} 100
envoy_cluster_upstream_rq_time_count{cluster_name="outbound|8080||backend.rl.svc.cluster.local"} 500
# TYPE envoy_cluster_upstream_rq_timeout counter
envoy_cluster_upstream_rq_timeout{cluster_name="outbound|9000||ratelimit.rl.svc.cluster.local"} 2
envoy_cluster_upstream_rq_timeout{cluster_name="outbound|8080||backend.rl.svc.cluster.local"} 40
# TYPE envoy_server_live gauge
# TYPE envoy_server_live gauge
envoy_server_live 1
`

// serviceText is what a rate limit service pod serves: its histograms for
// the test's domain and for another one.
const serviceText = `# TYPE ratelimit_check_duration_seconds histogram
ratelimit_check_duration_seconds_bucket{domain="gateway.public",le="0.0005"} 3
ratelimit_check_duration_seconds_bucket{domain="gateway.public",le="0.001"} 4
ratelimit_check_duration_seconds_bucket{domain="gateway.public",le="+Inf"} 4
ratelimit_check_duration_seconds_sum{domain="gateway.public"} 0.002
ratelimit_check_duration_seconds_count{domain="gateway.public"} 4
ratelimit_check_duration_seconds_bucket{domain="gateway.private",le="0.0005"} 90
ratelimit_check_duration_seconds_bucket{domain="gateway.private",le="0.001"} 90
ratelimit_check_duration_seconds_bucket{domain="gateway.private",le="+Inf"} 90
ratelimit_check_duration_seconds_sum{domain="gateway.private"} 0.01
ratelimit_check_duration_seconds_count{domain="gateway.private"} 90
# TYPE ratelimit_store_roundtrip_seconds histogram
ratelimit_store_roundtrip_seconds_bucket{domain="gateway.public",le="0.0005"} 4
ratelimit_store_roundtrip_seconds_bucket{domain="gateway.public",le="0.001"} 4
ratelimit_store_roundtrip_seconds_bucket{domain="gateway.public",le="+Inf"} 4
ratelimit_store_roundtrip_seconds_sum{domain="gateway.public"} 0.001
ratelimit_store_roundtrip_seconds_count{domain="gateway.public"} 4
`

// routedClient returns a client that sends every request to srv, whatever
// address its URL names, so two addresses can stand for two pods.
func routedClient(srv *httptest.Server) *http.Client {
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return &http.Client{Transport: &http.Transport{DialContext: dial}}
}

// fakePod serves body at path and returns the host:port of a target whose
// host the config's lookup resolves to the server's address.
func fakePod(t *testing.T, path, body string) (target, addr string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	addr, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	return net.JoinHostPort("pods-of-"+path, port), addr
}

func sampleConfig(lookup func(ctx context.Context, host string) ([]string, error)) metricsConfig {
	return metricsConfig{cluster: rlsCluster, domain: "gateway.public", interval: time.Millisecond,
		timeout: time.Second, lookup: lookup, client: http.DefaultClient}
}

// A sample keeps the series of the rate limit service's cluster and of the
// test's domain, and leaves out another cluster, another domain, and a
// family the text parser would refuse.
func TestTakeSample_keepsTheRateLimitClusterAndDomain(t *testing.T) {
	gateway, gwAddr := fakePod(t, "/stats/prometheus", gatewayText)
	service, svcAddr := fakePod(t, "/metrics", serviceText)
	cfg := sampleConfig(func(_ context.Context, host string) ([]string, error) {
		return []string{map[string]string{"pods-of-/stats/prometheus": gwAddr, "pods-of-/metrics": svcAddr}[host]}, nil
	})
	cfg.gateway, cfg.service = gateway, service

	s := takeSample(context.Background(), cfg)

	assert.Equal(t, map[string]gatewayStats{gwAddr: {
		Call:     histogramStats{Bounds: []float64{0.5, 1}, Counts: []float64{7, 9}, Sum: 12, Count: 10},
		Timeouts: 2,
	}}, s.Gateway)
	assert.Equal(t, map[string]serviceStats{svcAddr: {
		Check: histogramStats{Bounds: []float64{0.0005, 0.001}, Counts: []float64{3, 4}, Sum: 0.002, Count: 4},
		Store: histogramStats{Bounds: []float64{0.0005, 0.001}, Counts: []float64{4, 4}, Sum: 0.001, Count: 4},
	}}, s.Service)
	assert.Empty(t, s.GatewayErrors)
	assert.Empty(t, s.ServiceErrors)
}

// A source that gives no statistics leaves its reason in the sample: the
// gateway serves no histogram of the cluster, which is what a gateway
// without the stats matcher does, and the service answers 404.
func TestTakeSample_recordsWhyEachSourceGaveNothing(t *testing.T) {
	gateway, gwAddr := fakePod(t, "/stats/prometheus", "# TYPE envoy_server_live gauge\nenvoy_server_live 1\n")
	service, svcAddr := fakePod(t, "/no-metrics-here", "")
	cfg := sampleConfig(func(_ context.Context, host string) ([]string, error) {
		addrs := map[string]string{"pods-of-/stats/prometheus": gwAddr, "pods-of-/no-metrics-here": svcAddr}
		return []string{addrs[host]}, nil
	})
	cfg.gateway, cfg.service = gateway, service

	s := takeSample(context.Background(), cfg)

	assert.Equal(t, []string{"http://" + net.JoinHostPort(gwAddr, portOf(t, gateway)) +
		"/stats/prometheus: no envoy_cluster_upstream_rq_time of cluster " + rlsCluster +
		": enable the gateway's statistics of the rate limit service"}, s.GatewayErrors)
	assert.Equal(t, []string{"http://" + net.JoinHostPort(svcAddr, portOf(t, service)) + "/metrics: status 404"},
		s.ServiceErrors)
	assert.Empty(t, s.Gateway)
	assert.Empty(t, s.Service)
}

func portOf(t *testing.T, target string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(target)
	require.NoError(t, err)
	return port
}

// cancelAfter is a writer that cancels its context once it holds n lines.
type cancelAfter struct {
	n      int
	cancel context.CancelFunc
	lines  []string
}

func (w *cancelAfter) Write(p []byte) (int, error) {
	w.lines = append(w.lines, string(p))
	if len(w.lines) == w.n {
		w.cancel()
	}
	return len(p), nil
}

// The sampler writes a line per sample until it is stopped, and logs an
// error that every sample repeats only once.
func TestSampleMetrics_writesALinePerSampleAndLogsEachErrorOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &cancelAfter{n: 3, cancel: cancel}
	var log strings.Builder
	cfg := sampleConfig(func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") })
	cfg.service = "pods-of-the-service:8080"

	require.NoError(t, sampleMetrics(ctx, cfg, out, &log))

	assert.Len(t, out.lines, 3)
	assert.Equal(t, "loadkit metrics: pods-of-the-service:8080: no such host\n", log.String())
}

// Every address the host resolves to is a pod, sampled and keyed on its own.
func TestTakeSample_readsEveryPodTheHostResolvesTo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, gatewayText)
	}))
	defer srv.Close()
	cfg := sampleConfig(func(context.Context, string) ([]string, error) { return []string{"10.0.0.1", "10.0.0.2"}, nil })
	cfg.gateway, cfg.client = "pods-of-the-gateway:15090", routedClient(srv)

	s := takeSample(context.Background(), cfg)

	assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, sortedKeys(s.Gateway))
	assert.Empty(t, s.GatewayErrors)
}

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// The families the sampler reads. Envoy names the histogram of a cluster's
// upstream request time envoy_cluster_upstream_rq_time and labels it with
// cluster_name; the service labels its histograms with domain.
const (
	envoyCallTime     = "envoy_cluster_upstream_rq_time"
	envoyCallTimeouts = "envoy_cluster_upstream_rq_timeout"
	serviceCheckTime  = "ratelimit_check_duration_seconds"
	serviceStoreTime  = "ratelimit_store_roundtrip_seconds"
)

// metricsSample is one line of the file loadkit metrics writes: what every
// pod that answered reported at T, keyed by the pod's address.
type metricsSample struct {
	T       int64                   `json:"t"` // milliseconds since the epoch
	Gateway map[string]gatewayStats `json:"gateway,omitempty"`
	Service map[string]serviceStats `json:"service,omitempty"`
	// GatewayErrors and ServiceErrors hold why a source, or a pod of it,
	// gave no statistics in this sample.
	GatewayErrors []string `json:"gatewayErrors,omitempty"`
	ServiceErrors []string `json:"serviceErrors,omitempty"`
}

// gatewayStats holds the counters of the gateway's Envoy for its cluster of
// the rate limit service.
type gatewayStats struct {
	Call     histogramStats `json:"call"` // upstream_rq_time, in milliseconds
	Timeouts float64        `json:"timeouts"`
}

// serviceStats holds the histograms of the rate limit service for one domain,
// in seconds.
type serviceStats struct {
	Check histogramStats `json:"check"`
	Store histogramStats `json:"store"`
}

// histogramStats is a cumulative histogram: Counts[i] observations at or
// under Bounds[i], and Count in all, so the +Inf bucket is Count.
type histogramStats struct {
	Bounds []float64 `json:"le"`
	Counts []float64 `json:"counts"`
	Sum    float64   `json:"sum"`
	Count  float64   `json:"count"`
}

type metricsConfig struct {
	// gateway and service are host:port pairs; the host resolves to the
	// address of every pod, as a headless Service does. An empty one is not
	// sampled.
	gateway, service string
	cluster          string // Envoy cluster of the rate limit service
	domain           string
	interval         time.Duration
	timeout          time.Duration
	lookup           func(ctx context.Context, host string) ([]string, error)
	client           *http.Client
}

// metricsCommand samples, every -interval until it is stopped with SIGTERM or
// SIGINT, the gateway's statistics of its calls to the rate limit service and
// the service's statistics of its checks, and appends one JSON line per
// sample to -out. A source that does not answer leaves its reason in the
// line, and on stderr the first time, and is tried again at the next sample.
func metricsCommand(args []string, _ io.Writer) error {
	fs := flag.NewFlagSet("metrics", flag.ContinueOnError)
	var cfg metricsConfig
	fs.StringVar(&cfg.gateway, "gateway", "", "host:port of the gateway pods' Envoy statistics, "+
		"a host that resolves to every pod; empty skips the gateway")
	fs.StringVar(&cfg.cluster, "cluster", "", "Envoy cluster of the rate limit service in the gateway, "+
		"such as outbound|9000||ratelimit.<namespace>.svc.cluster.local")
	fs.StringVar(&cfg.service, "service", "", "host:port of the rate limit service pods' metrics, "+
		"a host that resolves to every pod; empty skips the service")
	fs.StringVar(&cfg.domain, "domain", "", "rate limit domain of the gateway")
	fs.DurationVar(&cfg.interval, "interval", 5*time.Second, "time between samples")
	fs.DurationVar(&cfg.timeout, "timeout", 3*time.Second, "time one pod has to answer")
	out := fs.String("out", "", "file the samples are appended to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case fs.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case *out == "":
		return errors.New("-out is required")
	case cfg.gateway == "" && cfg.service == "":
		return errors.New("-gateway, -service, or both are required")
	case cfg.gateway != "" && cfg.cluster == "":
		return errors.New("-cluster is required with -gateway")
	case cfg.service != "" && cfg.domain == "":
		return errors.New("-domain is required with -service")
	case cfg.interval <= 0 || cfg.timeout <= 0:
		return errors.New("-interval and -timeout must be positive")
	}
	cfg.lookup = net.DefaultResolver.LookupHost
	cfg.client = &http.Client{Timeout: cfg.timeout}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	return sampleMetrics(ctx, cfg, f, os.Stderr)
}

// sampleMetrics writes a sample to w at once and then every cfg.interval
// until ctx is done, and prints each distinct error to log once.
func sampleMetrics(ctx context.Context, cfg metricsConfig, w io.Writer, log io.Writer) error {
	seen := map[string]bool{}
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		s := takeSample(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		for _, e := range slices.Concat(s.GatewayErrors, s.ServiceErrors) {
			if !seen[e] {
				seen[e] = true
				_, _ = fmt.Fprintf(log, "loadkit metrics: %s\n", e)
			}
		}
		line, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// takeSample reads every pod of each configured source once.
func takeSample(ctx context.Context, cfg metricsConfig) metricsSample {
	s := metricsSample{T: time.Now().UnixMilli()}
	if cfg.gateway != "" {
		s.Gateway = map[string]gatewayStats{}
		keep := func(addr string, fams families) error {
			call, ok := histogramOf(fams[envoyCallTime], "cluster_name", cfg.cluster)
			if !ok {
				return fmt.Errorf("no %s of cluster %s: enable the gateway's statistics of the rate limit service",
					envoyCallTime, cfg.cluster)
			}
			timeouts, _ := counterOf(fams[envoyCallTimeouts], "cluster_name", cfg.cluster)
			s.Gateway[addr] = gatewayStats{Call: call, Timeouts: timeouts}
			return nil
		}
		forEachPod(ctx, cfg, cfg.gateway, "/stats/prometheus", &s.GatewayErrors, keep, envoyCallTime, envoyCallTimeouts)
	}
	if cfg.service != "" {
		s.Service = map[string]serviceStats{}
		keep := func(addr string, fams families) error {
			check, ok := histogramOf(fams[serviceCheckTime], "domain", cfg.domain)
			if !ok {
				return fmt.Errorf("no %s of domain %s", serviceCheckTime, cfg.domain)
			}
			store, _ := histogramOf(fams[serviceStoreTime], "domain", cfg.domain)
			s.Service[addr] = serviceStats{Check: check, Store: store}
			return nil
		}
		forEachPod(ctx, cfg, cfg.service, "/metrics", &s.ServiceErrors, keep, serviceCheckTime, serviceStoreTime)
	}
	return s
}

// forEachPod resolves the host of target, reads path from every address it
// resolves to, and passes the families named in names to fn. Every failure
// goes to errs, prefixed with target when the host does not resolve and with
// the URL of the pod otherwise, fn's failures included.
func forEachPod(ctx context.Context, cfg metricsConfig, target, path string, errs *[]string,
	fn func(addr string, fams families) error, names ...string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s: %v", target, err))
		return
	}
	lookupCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	addrs, err := cfg.lookup(lookupCtx, host)
	cancel()
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("%s: %v", target, err))
		return
	}
	for _, addr := range addrs {
		// Envoy's statistics port and the service's metrics port speak plain
		// HTTP, the way Prometheus scrapes them; the generator runs outside
		// the mesh, so no mesh encrypts the hop either.
		location := url.URL{Scheme: "http", Host: net.JoinHostPort(addr, port), Path: path}
		endpoint := location.String()
		fams, err := scrape(ctx, cfg.client, endpoint, names)
		if err == nil {
			err = fn(addr, fams)
		}
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s: %v", endpoint, err))
		}
	}
}

// families holds the metric families of one scrape by name.
type families map[string]*dto.MetricFamily

// scrape reads the Prometheus text exposition at endpoint and parses the
// families named in names. It parses only their lines, so a line of another
// family that the text parser would refuse does not cost the sample.
func scrape(ctx context.Context, client *http.Client, endpoint string, names []string) (families, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var kept bytes.Buffer
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := sc.Text(); belongsTo(line, names) {
			kept.WriteString(line)
			kept.WriteByte('\n')
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	return parser.TextToMetricFamilies(&kept)
}

// belongsTo reports whether line is a sample, a TYPE line, or a HELP line of
// a family named in names, a histogram's _bucket, _sum, and _count samples
// included.
func belongsTo(line string, names []string) bool {
	name := line
	if rest, ok := strings.CutPrefix(line, "# TYPE "); ok {
		name = rest
	} else if rest, ok := strings.CutPrefix(line, "# HELP "); ok {
		name = rest
	} else if strings.HasPrefix(line, "#") {
		return false
	}
	if i := strings.IndexAny(name, "{ "); i >= 0 {
		name = name[:i]
	}
	for _, f := range names {
		switch name {
		case f, f + "_bucket", f + "_sum", f + "_count":
			return true
		}
	}
	return false
}

// histogramOf returns the histogram of fam whose label has the value want.
func histogramOf(fam *dto.MetricFamily, label, want string) (histogramStats, bool) {
	m := metricWith(fam, label, want)
	if m == nil || m.GetHistogram() == nil {
		return histogramStats{}, false
	}
	h := m.GetHistogram()
	out := histogramStats{Sum: h.GetSampleSum(), Count: float64(h.GetSampleCount())}
	for _, b := range h.GetBucket() {
		if math.IsInf(b.GetUpperBound(), 1) {
			continue
		}
		out.Bounds = append(out.Bounds, b.GetUpperBound())
		out.Counts = append(out.Counts, float64(b.GetCumulativeCount()))
	}
	return out, true
}

// counterOf returns the value of the counter of fam whose label has the
// value want.
func counterOf(fam *dto.MetricFamily, label, want string) (float64, bool) {
	m := metricWith(fam, label, want)
	if m == nil {
		return 0, false
	}
	if c := m.GetCounter(); c != nil {
		return c.GetValue(), true
	}
	if u := m.GetUntyped(); u != nil {
		return u.GetValue(), true
	}
	return 0, false
}

func metricWith(fam *dto.MetricFamily, label, want string) *dto.Metric {
	if fam == nil {
		return nil
	}
	for _, m := range fam.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == label && l.GetValue() == want {
				return m
			}
		}
	}
	return nil
}

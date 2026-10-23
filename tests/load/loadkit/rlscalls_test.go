package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envoyHist is a cumulative histogram over Envoy's first three default
// bounds, in milliseconds.
func envoyHist(counts ...float64) histogramStats {
	return histogramStats{Bounds: []float64{0.5, 1, 5}, Counts: counts, Count: counts[len(counts)-1]}
}

func gw(call histogramStats, timeouts float64) gatewayStats {
	return gatewayStats{Call: call, Timeouts: timeouts}
}

// A step counts what each gateway pod's statistics grew by between its first
// and its last sample inside the step: the samples at 0 and 12000, outside
// the step from 1000 to 9000, would add 1010 calls if they counted.
func TestRLSCalls_sumsWhatEveryGatewayPodGrewByInsideTheStep(t *testing.T) {
	in := &rlsInput{samples: []metricsSample{
		{T: 0, Gateway: map[string]gatewayStats{"a": gw(envoyHist(0, 0, 0), 0)}},
		{T: 1000, Gateway: map[string]gatewayStats{"a": gw(envoyHist(10, 10, 10), 0), "b": gw(envoyHist(0, 0, 0), 1)}},
		{T: 5000, Gateway: map[string]gatewayStats{"a": gw(envoyHist(20, 25, 25), 2), "b": gw(envoyHist(5, 5, 6), 1)}},
		{T: 9000, Gateway: map[string]gatewayStats{"a": gw(envoyHist(30, 38, 40), 3), "b": gw(envoyHist(8, 9, 10), 1)}},
		{T: 12000, Gateway: map[string]gatewayStats{"a": gw(envoyHist(1000, 1000, 1040), 3)}},
	}}

	got := rlsCalls(in, [][2]int64{{1000, 9000}})

	require.Len(t, got, 1)
	assert.Equal(t, rlsCallReport{
		Step: 1, GatewayCalls: 40, GatewayP50UnderMs: 1, GatewayP90UnderMs: 2, GatewayP99UnderMs: 6, Timeouts: 3,
		ServiceNote: "the service was not sampled",
	}, got[0])
}

// The service's quantiles interpolate inside a bucket, and its mean divides
// the growth of the sum by that of the count.
func TestRLSCalls_interpolatesTheServiceQuantiles(t *testing.T) {
	bounds := []float64{0.0005, 0.001, 0.0025}
	in := &rlsInput{samples: []metricsSample{
		{T: 1000, Service: map[string]serviceStats{"a": {
			Check: histogramStats{Bounds: bounds, Counts: []float64{0, 0, 0}},
			Store: histogramStats{Bounds: bounds, Counts: []float64{0, 0, 0}},
		}}},
		{T: 9000, Service: map[string]serviceStats{"a": {
			Check: histogramStats{Bounds: bounds, Counts: []float64{50, 90, 100}, Sum: 0.06, Count: 100},
			Store: histogramStats{Bounds: bounds, Counts: []float64{90, 100, 100}, Sum: 0.03, Count: 100},
		}}},
	}}

	got := rlsCalls(in, [][2]int64{{1000, 9000}})

	require.Len(t, got, 1)
	assert.Equal(t, int64(100), got[0].ServiceChecks)
	assert.InDelta(t, 0.5, got[0].CheckP50Ms, 1e-9, "check p50")
	assert.InDelta(t, 2.35, got[0].CheckP99Ms, 1e-9, "check p99")
	assert.InDelta(t, 0.6, got[0].CheckMeanMs, 1e-9, "check mean")
	assert.InDelta(t, 0.95, got[0].StoreP99Ms, 1e-9, "store p99")
}

// A step without statistics says why: the last error the gateway gave in
// the step, that the service was never sampled, that the statistics of a
// pod that answered did not grow, or, for a step with one sample, that it
// needs two.
func TestRLSCalls_aStepWithoutStatisticsSaysWhy(t *testing.T) {
	idle := serviceStats{Check: histogramStats{Bounds: []float64{0.001}, Counts: []float64{5}, Count: 5}}
	in := &rlsInput{samples: []metricsSample{
		{T: 1000, Gateway: map[string]gatewayStats{}, GatewayErrors: []string{"first error"}},
		{T: 5000, Gateway: map[string]gatewayStats{}, GatewayErrors: []string{"last error"}},
		{T: 12000, Gateway: map[string]gatewayStats{"a": gw(envoyHist(1, 1, 1), 0)}},
		{T: 21000, Service: map[string]serviceStats{"s": idle}},
		{T: 25000, Service: map[string]serviceStats{"s": idle}},
	}}

	got := rlsCalls(in, [][2]int64{{1000, 9000}, {10000, 15000}, {20000, 29000}})

	assert.Equal(t, []rlsCallReport{
		{Step: 1, GatewayNote: "last error", ServiceNote: "the service was not sampled"},
		{Step: 2, GatewayNote: "fewer than two samples of the metrics fall inside the step",
			ServiceNote: "fewer than two samples of the metrics fall inside the step"},
		{Step: 3, GatewayNote: "the gateway was not sampled",
			ServiceNote: "the service's statistics did not grow in the step"},
	}, got)
}

// A metrics file verify cannot read leaves every step with the error.
func TestRLSCalls_aMissingMetricsFileSaysSo(t *testing.T) {
	in := readMetrics(filepath.Join(t.TempDir(), "metrics.jsonl"))

	got := rlsCalls(&in, [][2]int64{{1000, 9000}})

	require.Len(t, got, 1)
	assert.Contains(t, got[0].GatewayNote, "the metrics could not be read: open ")
	assert.Contains(t, got[0].ServiceNote, "the metrics could not be read: open ")
}

// A step with statistics says what it may miss: a pod whose buckets differ
// from the sum's, here pod b, which sorts after pod a whose buckets the sum
// takes, and a pod that gave nothing in some samples. Pod b's growth of 100
// calls is left out.
func TestRLSCalls_aStepThatMayMissCallsSaysWhy(t *testing.T) {
	other := func(n float64) histogramStats {
		return histogramStats{Bounds: []float64{1, 2}, Counts: []float64{n, n}, Count: n}
	}
	in := &rlsInput{samples: []metricsSample{
		{T: 1000, Gateway: map[string]gatewayStats{"b": gw(other(0), 0), "a": gw(envoyHist(0, 0, 0), 0)}},
		{T: 5000, Gateway: map[string]gatewayStats{"b": gw(other(100), 0), "a": gw(envoyHist(4, 4, 4), 0)},
			GatewayErrors: []string{"http://c:15090/stats/prometheus: connection refused"}},
		{T: 9000, Gateway: map[string]gatewayStats{"b": gw(other(200), 0), "a": gw(envoyHist(8, 8, 8), 0)}},
	}}

	got := rlsCalls(in, [][2]int64{{1000, 9000}})

	require.Len(t, got, 1)
	assert.Equal(t, int64(8), got[0].GatewayCalls)
	assert.Equal(t, "a pod whose histogram has other buckets is left out; a pod gave nothing in some samples, "+
		"so the step may miss calls: http://c:15090/stats/prometheus: connection refused", got[0].GatewayNote)
}

func TestHistogramGrow_addsTheGrowthSinceThePreviousSample(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prev, cur histogramStats
		want      histogramStats
	}{
		{"a count that grew adds the difference",
			envoyHist(40, 45, 50), envoyHist(46, 52, 60), envoyHist(6, 7, 10)},
		{"a count that fell restarted from zero",
			envoyHist(40, 45, 50), envoyHist(5, 7, 8), envoyHist(5, 7, 8)},
		{"other buckets restarted from zero",
			histogramStats{Bounds: []float64{1, 5}, Counts: []float64{1, 2}, Count: 2},
			envoyHist(5, 7, 8), envoyHist(5, 7, 8)},
		{"an unchanged count adds nothing",
			envoyHist(40, 45, 50), envoyHist(40, 45, 50), histogramStats{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h histogramStats
			assert.True(t, h.grow(tc.prev, tc.cur), "grow(%v, %v)", tc.prev, tc.cur)
			assert.Equal(t, tc.want, h)
		})
	}
}

// A counter that fell between two samples restarted from zero, so all of it
// is growth; one that rose grew by the difference.
func TestCounterGrowth_aCounterThatFellRestartedFromZero(t *testing.T) {
	assert.Equal(t, 4.0, counterGrowth(3, 7), "counterGrowth(3, 7)")
	assert.Equal(t, 2.0, counterGrowth(7, 2), "counterGrowth(7, 2)")
}

// Growth over other buckets than the ones the sum holds is left out, and
// grow says so.
func TestHistogramGrow_refusesGrowthOverOtherBuckets(t *testing.T) {
	h := envoyHist(1, 2, 3)
	other := histogramStats{Bounds: []float64{1, 5}, Counts: []float64{1, 2}, Count: 2}

	assert.False(t, h.grow(histogramStats{Bounds: other.Bounds, Counts: []float64{0, 0}}, other),
		"grow over the bounds %v", other.Bounds)
	assert.Equal(t, envoyHist(1, 2, 3), h)
}

// Envoy counts truncated whole milliseconds, so a quantile in the bucket up
// to le lies under floor(le)+1; a quantile whose rank equals a bucket's count
// falls in that bucket.
func TestBoundUnder_givesTheWholeMillisecondEachQuantileLiesUnder(t *testing.T) {
	h := histogramStats{Bounds: []float64{0.5, 1, 5, 10}, Counts: []float64{50, 70, 95, 99}, Count: 100}
	for _, tc := range []struct {
		q    float64
		want float64
	}{
		{0.50, 1},
		{0.60, 2},
		{0.90, 6},
		{0.99, 11},
		{0.995, -1},
	} {
		assert.Equal(t, tc.want, boundUnder(h, tc.q), "boundUnder(h, %v)", tc.q)
	}
}

// As histogram_quantile does, a quantile interpolates linearly inside its
// bucket from the bound below, 0 for the first, and a quantile past the
// largest bound is that bound.
func TestInterpolate_followsHistogramQuantile(t *testing.T) {
	h := histogramStats{Bounds: []float64{0.001, 0.002}, Counts: []float64{40, 80}, Count: 100}
	for _, tc := range []struct {
		q    float64
		want float64
	}{
		{0.2, 0.0005},
		{0.6, 0.0015},
		{0.9, 0.002},
	} {
		assert.InDelta(t, tc.want, interpolate(h, tc.q), 1e-12, "interpolate(h, %v)", tc.q)
	}
}

// A line the sampler was stopped while writing is skipped, and the samples
// come back in time order.
func TestReadMetrics_skipsALineCutShortAndSortsByTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("{\"t\":2000}\n{\"t\":1000}\n{\"t\":30"), 0o600))

	in := readMetrics(path)

	require.NoError(t, in.err)
	assert.Equal(t, []metricsSample{{T: 1000}, {T: 2000}}, in.samples)
}

// reportWithMetrics returns the report of one admitted sample in a step from
// 0 to 10 s, with the metrics of in.
func reportWithMetrics(in *rlsInput, requireMetrics bool) report {
	cfg := verifyConfig{steps: []step{{rate: 1, duration: 10 * time.Second}}, start: midnight,
		maxLag: time.Second, requireMetrics: requireMetrics}
	a := newAccumulator(cfg)
	a.add(at("ann", admitted, time.Second, 10*time.Millisecond))
	a.rls = in
	return a.report()
}

// -require-metrics fails a step for each end without statistics, and names
// the reason; a step with both passes, and without the flag every step does.
func TestReport_requireMetricsFailsAStepForEachEndWithoutStatistics(t *testing.T) {
	grown := func(n float64) map[string]gatewayStats {
		return map[string]gatewayStats{"a": gw(envoyHist(n, n, n), 0)}
	}
	checked := func(n float64) map[string]serviceStats {
		return map[string]serviceStats{"s": {Check: histogramStats{Bounds: []float64{0.001}, Counts: []float64{n}, Count: n}}}
	}
	noHost := []string{"pods-of-the-service:8080: no such host"}
	tests := []struct {
		name    string
		samples []metricsSample
		require bool
		want    []string
	}{
		{"neither end", []metricsSample{
			{T: midnight + 1000, ServiceErrors: noHost}, {T: midnight + 2000, ServiceErrors: noHost},
		}, true, []string{
			"step 1 has no statistics of the gateway's calls to the rate limit service: the gateway was not sampled",
			"step 1 has no statistics of the rate limit service's checks: pods-of-the-service:8080: no such host",
		}},
		{"the gateway alone", []metricsSample{
			{T: midnight + 1000, Gateway: grown(0), ServiceErrors: noHost},
			{T: midnight + 2000, Gateway: grown(5), ServiceErrors: noHost},
		}, true, []string{
			"step 1 has no statistics of the rate limit service's checks: pods-of-the-service:8080: no such host",
		}},
		{"both ends", []metricsSample{
			{T: midnight + 1000, Gateway: grown(0), Service: checked(0)},
			{T: midnight + 2000, Gateway: grown(5), Service: checked(5)},
		}, true, nil},
		{"neither end without the flag", []metricsSample{
			{T: midnight + 1000, ServiceErrors: noHost}, {T: midnight + 2000, ServiceErrors: noHost},
		}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, reportWithMetrics(&rlsInput{samples: tt.samples}, tt.require).Failures)
		})
	}
}

// The table gives the gateway's quantiles as bounds and the service's as
// milliseconds, a dash where a source or the store has no statistics, and
// the reason under the table.
func TestRLSCallsMarkdown_rendersBoundsMillisecondsAndReasons(t *testing.T) {
	var b strings.Builder
	rlsCallsMarkdown(&b, []rlsCallReport{
		{Step: 1, GatewayCalls: 40, GatewayP50UnderMs: 1, GatewayP90UnderMs: 2, GatewayP99UnderMs: -1, Timeouts: 3,
			ServiceChecks: 100, CheckP50Ms: 0.5, CheckP99Ms: 2.35, CheckMeanMs: 0.6, StoreP99Ms: 0.95},
		{Step: 2, GatewayNote: "no statistics", ServiceChecks: 7, CheckP50Ms: 0.25, CheckP99Ms: 1, CheckMeanMs: 0.3},
	})

	assert.Equal(t, "\nCalls to the rate limit service in each step, all the traffic of the gateway and the service:\n\n"+
		"| Step | Gateway calls | Gateway p50 ms | Gateway p90 ms | Gateway p99 ms | Timeouts "+
		"| Service checks | Check p50 ms | Check p99 ms | Check mean ms | Store p99 ms |\n"+
		"| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n"+
		"| 1 | 40 | <1 | <2 | past the buckets | 3 | 100 | 0.50 | 2.35 | 0.60 | 0.95 |\n"+
		"| 2 | - | - | - | - | - | 7 | 0.25 | 1.00 | 0.30 | - |\n"+
		"\nThe gateway's Envoy records a call in whole milliseconds, so each gateway quantile is the bound "+
		"it lies under. A check is the service's own handling of a call, the counter store included. A step counts "+
		"from its first to its last sample of the metrics.\n"+
		"\n- Step 2, gateway: no statistics.\n", b.String())
}

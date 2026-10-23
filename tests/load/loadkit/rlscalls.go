package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"slices"
	"strings"
)

// rlsInput is what verify has of the calls to the rate limit service: the
// samples loadkit metrics wrote, or the error that kept verify from reading
// them.
type rlsInput struct {
	samples []metricsSample
	err     error
}

// readMetrics reads the file loadkit metrics wrote. It skips a line it
// cannot parse, such as the last line of a sampler stopped while writing it.
func readMetrics(path string) rlsInput {
	f, err := os.Open(path)
	if err != nil {
		return rlsInput{err: err}
	}
	defer func() { _ = f.Close() }()
	var in rlsInput
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var s metricsSample
		if json.Unmarshal(sc.Bytes(), &s) == nil {
			in.samples = append(in.samples, s)
		}
	}
	in.err = sc.Err()
	slices.SortFunc(in.samples, func(a, b metricsSample) int { return cmp.Compare(a.T, b.T) })
	return in
}

// rlsCallReport describes the calls to the rate limit service in the measured
// part of one step: the gateway's calls as its Envoy times them, and the
// checks as the service times them, the counter store included. Both count
// every call through that gateway and service, not only those of the test,
// from the first to the last sample inside the measured part, which can fall
// up to one sampling interval short of its start and of its end.
type rlsCallReport struct {
	Step int `json:"step"`
	// GatewayCalls counts the calls the gateway's statistics grew by. With
	// none, GatewayNote says why; with some, it says what may be missing.
	GatewayCalls int64 `json:"gatewayCalls"`
	// The gateway's quantiles are bounds in milliseconds the quantile lies
	// under (boundUnder), or -1 for a quantile past the largest bucket.
	GatewayP50UnderMs float64 `json:"gatewayP50UnderMs"`
	GatewayP90UnderMs float64 `json:"gatewayP90UnderMs"`
	GatewayP99UnderMs float64 `json:"gatewayP99UnderMs"`
	// Timeouts counts the calls the gateway gave up on at the filter's
	// timeout.
	Timeouts    int64  `json:"timeouts"`
	GatewayNote string `json:"gatewayNote,omitempty"`
	// ServiceChecks counts the checks of the domain the service's statistics
	// grew by, and ServiceNote says why there are none or what may be
	// missing. The quantiles interpolate inside a bucket (interpolate);
	// CheckMeanMs is exact.
	ServiceChecks int64   `json:"serviceChecks"`
	CheckP50Ms    float64 `json:"checkP50Ms"`
	CheckP99Ms    float64 `json:"checkP99Ms"`
	CheckMeanMs   float64 `json:"checkMeanMs"`
	// StoreP99Ms is 0 when the service's statistics hold no store round trip.
	StoreP99Ms  float64 `json:"storeP99Ms"`
	ServiceNote string  `json:"serviceNote,omitempty"`
}

// rlsCalls returns a report per step, each over the samples taken inside the
// measured part of the step, whose bounds are milliseconds since the epoch.
func rlsCalls(in *rlsInput, bounds [][2]int64) []rlsCallReport {
	reports := make([]rlsCallReport, len(bounds))
	for i, b := range bounds {
		r := &reports[i]
		r.Step = i + 1
		var inside []metricsSample
		for _, s := range in.samples {
			if s.T >= b[0] && s.T <= b[1] {
				inside = append(inside, s)
			}
		}
		if len(inside) < 2 {
			note := "fewer than two samples of the metrics fall inside the step"
			if in.err != nil {
				note = fmt.Sprintf("the metrics could not be read: %v", in.err)
			}
			r.GatewayNote, r.ServiceNote = note, note
			continue
		}
		gatewayCalls(r, inside)
		serviceChecks(r, inside)
	}
	return reports
}

// metricsFailures returns a failure for every step whose metrics hold no
// call of the gateway or no check of the service.
func metricsFailures(reports []rlsCallReport) []string {
	var failures []string
	for _, r := range reports {
		if r.GatewayCalls == 0 {
			failures = append(failures, fmt.Sprintf(
				"step %d has no statistics of the gateway's calls to the rate limit service: %s", r.Step, r.GatewayNote))
		}
		if r.ServiceChecks == 0 {
			failures = append(failures, fmt.Sprintf(
				"step %d has no statistics of the rate limit service's checks: %s", r.Step, r.ServiceNote))
		}
	}
	return failures
}

func gatewayCalls(r *rlsCallReport, samples []metricsSample) {
	var call histogramStats
	var timeouts float64
	prev := map[string]gatewayStats{}
	mixed := false
	for _, s := range samples {
		for _, addr := range sortedKeys(s.Gateway) {
			cur := s.Gateway[addr]
			if p, ok := prev[addr]; ok {
				mixed = !call.grow(p.Call, cur.Call) || mixed
				timeouts += counterGrowth(p.Timeouts, cur.Timeouts)
			}
			prev[addr] = cur
		}
	}
	r.GatewayCalls = int64(call.Count)
	r.Timeouts = int64(timeouts)
	of := func(s metricsSample) ([]string, bool) { return s.GatewayErrors, s.Gateway != nil }
	if call.Count == 0 {
		r.GatewayNote = noData(samples, "gateway", of)
		return
	}
	r.GatewayP50UnderMs = boundUnder(call, 0.50)
	r.GatewayP90UnderMs = boundUnder(call, 0.90)
	r.GatewayP99UnderMs = boundUnder(call, 0.99)
	r.GatewayNote = partialData(samples, mixed, of)
}

func serviceChecks(r *rlsCallReport, samples []metricsSample) {
	var check, store histogramStats
	prev := map[string]serviceStats{}
	mixed := false
	for _, s := range samples {
		for _, addr := range sortedKeys(s.Service) {
			cur := s.Service[addr]
			if p, ok := prev[addr]; ok {
				mixed = !check.grow(p.Check, cur.Check) || mixed
				mixed = !store.grow(p.Store, cur.Store) || mixed
			}
			prev[addr] = cur
		}
	}
	r.ServiceChecks = int64(check.Count)
	of := func(s metricsSample) ([]string, bool) { return s.ServiceErrors, s.Service != nil }
	if check.Count == 0 {
		r.ServiceNote = noData(samples, "service", of)
		return
	}
	const ms = 1000
	r.CheckP50Ms = interpolate(check, 0.50) * ms
	r.CheckP99Ms = interpolate(check, 0.99) * ms
	r.CheckMeanMs = check.Sum / check.Count * ms
	if store.Count > 0 {
		r.StoreP99Ms = interpolate(store, 0.99) * ms
	}
	r.ServiceNote = partialData(samples, mixed, of)
}

// sortedKeys returns the addresses of m in order. The pods of a step are
// summed in this order, so the pod whose buckets the sum takes when pods
// differ is the same on every run over the same samples.
func sortedKeys[V any](m map[string]V) []string {
	keys := slices.Collect(maps.Keys(m))
	slices.Sort(keys)
	return keys
}

// noData returns why the samples of a step hold no call of a source: the
// last error the source gave in the step, or that it was not sampled, or
// that its statistics did not grow.
func noData(samples []metricsSample, source string, of func(metricsSample) ([]string, bool)) string {
	sampled := false
	for i := len(samples) - 1; i >= 0; i-- {
		errs, ok := of(samples[i])
		if len(errs) > 0 {
			return errs[len(errs)-1]
		}
		sampled = sampled || ok
	}
	if !sampled {
		return "the " + source + " was not sampled"
	}
	return "the " + source + "'s statistics did not grow in the step"
}

// partialData returns what a step with statistics of a source may miss: a
// pod whose buckets differ from the sum's, and a pod that gave nothing in
// some samples, with the last error of the source in the step. It returns
// "" when the step misses nothing.
func partialData(samples []metricsSample, mixed bool, of func(metricsSample) ([]string, bool)) string {
	var notes []string
	if mixed {
		notes = append(notes, "a pod whose histogram has other buckets is left out")
	}
	for i := len(samples) - 1; i >= 0; i-- {
		if errs, _ := of(samples[i]); len(errs) > 0 {
			notes = append(notes, "a pod gave nothing in some samples, so the step may miss calls: "+errs[len(errs)-1])
			break
		}
	}
	return strings.Join(notes, "; ")
}

// grow adds to h the growth of a histogram from prev to cur, two samples of
// one pod. A cur whose count fell below prev's, or whose buckets differ from
// prev's, belongs to a restarted process, and its growth counts from zero.
// grow reports false, and adds nothing, when the buckets of that growth
// differ from those h already holds.
func (h *histogramStats) grow(prev, cur histogramStats) bool {
	delta := cur
	if slices.Equal(prev.Bounds, cur.Bounds) && cur.Count >= prev.Count {
		delta = histogramStats{Bounds: cur.Bounds, Counts: make([]float64, len(cur.Counts)),
			Sum: cur.Sum - prev.Sum, Count: cur.Count - prev.Count}
		for i := range cur.Counts {
			delta.Counts[i] = cur.Counts[i] - prev.Counts[i]
		}
	}
	if delta.Count == 0 {
		return true
	}
	if h.Count == 0 && len(h.Bounds) == 0 {
		h.Bounds = slices.Clone(delta.Bounds)
		h.Counts = make([]float64, len(delta.Counts))
	}
	if !slices.Equal(h.Bounds, delta.Bounds) {
		return false
	}
	for i := range delta.Counts {
		h.Counts[i] += delta.Counts[i]
	}
	h.Sum += delta.Sum
	h.Count += delta.Count
	return true
}

// counterGrowth returns the growth of a counter from prev to cur; a cur below
// prev restarted from zero.
func counterGrowth(prev, cur float64) float64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// boundUnder returns the bound, in milliseconds, that the q-quantile of h
// lies under, where h counts durations Envoy truncated to whole
// milliseconds. The quantile falls in the first bucket whose count reaches q
// of the total, and every duration counted at or under its upper bound le
// is under floor(le)+1 ms: a bucket up to 0.5 holds the durations Envoy
// recorded as 0, those under 1 ms. A quantile past the largest bound gives
// -1.
func boundUnder(h histogramStats, q float64) float64 {
	rank := q * h.Count
	for i, le := range h.Bounds {
		if h.Counts[i] >= rank {
			return math.Floor(le) + 1
		}
	}
	return -1
}

// interpolate returns the q-quantile of h the way PromQL's
// histogram_quantile does: linearly inside the bucket it falls in, the first
// bucket starting at 0. A quantile past the largest bound gives that bound.
func interpolate(h histogramStats, q float64) float64 {
	rank := q * h.Count
	lower, below := 0.0, 0.0
	for i, le := range h.Bounds {
		if h.Counts[i] >= rank {
			if h.Counts[i] == below {
				return le
			}
			return lower + (le-lower)*(rank-below)/(h.Counts[i]-below)
		}
		lower, below = le, h.Counts[i]
	}
	return lower
}

// rlsCallsMarkdown renders the reports as the section of summary.md on the
// calls to the rate limit service.
func rlsCallsMarkdown(b *strings.Builder, reports []rlsCallReport) {
	b.WriteString("\nCalls to the rate limit service in each step, all the traffic of the gateway and the service:\n\n")
	b.WriteString("| Step | Gateway calls | Gateway p50 ms | Gateway p90 ms | Gateway p99 ms | Timeouts " +
		"| Service checks | Check p50 ms | Check p99 ms | Check mean ms | Store p99 ms |\n")
	b.WriteString("| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	var notes []string
	for _, r := range reports {
		gw := []string{"-", "-", "-", "-", "-"}
		if r.GatewayCalls > 0 {
			gw = []string{fmt.Sprint(r.GatewayCalls), under(r.GatewayP50UnderMs), under(r.GatewayP90UnderMs),
				under(r.GatewayP99UnderMs), fmt.Sprint(r.Timeouts)}
		}
		svc := []string{"-", "-", "-", "-", "-"}
		if r.ServiceChecks > 0 {
			store := "-"
			if r.StoreP99Ms > 0 {
				store = millis(r.StoreP99Ms)
			}
			svc = []string{fmt.Sprint(r.ServiceChecks), millis(r.CheckP50Ms), millis(r.CheckP99Ms),
				millis(r.CheckMeanMs), store}
		}
		fmt.Fprintf(b, "| %d | %s | %s |\n", r.Step, strings.Join(gw, " | "), strings.Join(svc, " | "))
		if r.GatewayNote != "" {
			notes = append(notes, fmt.Sprintf("Step %d, gateway: %s.", r.Step, r.GatewayNote))
		}
		if r.ServiceNote != "" {
			notes = append(notes, fmt.Sprintf("Step %d, service: %s.", r.Step, r.ServiceNote))
		}
	}
	b.WriteString("\nThe gateway's Envoy records a call in whole milliseconds, so each gateway quantile is the bound " +
		"it lies under. A check is the service's own handling of a call, the counter store included. A step counts " +
		"from its first to its last sample of the metrics.\n")
	if len(notes) > 0 {
		b.WriteString("\n")
		for _, n := range notes {
			fmt.Fprintf(b, "- %s\n", n)
		}
	}
}

func under(bound float64) string {
	if bound < 0 {
		return "past the buckets"
	}
	return fmt.Sprintf("<%g", bound)
}

func millis(v float64) string { return fmt.Sprintf("%.2f", v) }

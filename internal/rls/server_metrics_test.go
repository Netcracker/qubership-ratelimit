package rls

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// delta reads a counter twice around an action; the tests below assert on
// differences because the package-level series accumulate across tests.
func delta(read func() float64, act func()) float64 {
	before := read()
	act()
	return read() - before
}

func TestShouldRateLimit_countsChecksAndDecisions(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, output := recordingLogger()
	server := NewServer(ruleStore, log)

	check := func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api"}))
		require.NoError(t, err)
	}

	const rule = "one/b/all"
	reads := map[string]func() float64{
		"checks ok": func() float64 {
			return testutil.ToFloat64(metrics.Checks.WithLabelValues(domain, metrics.VerdictOK))
		},
		"checks over_limit": func() float64 {
			return testutil.ToFloat64(metrics.Checks.WithLabelValues(domain, metrics.VerdictOverLimit))
		},
		"decisions ok": func() float64 {
			return testutil.ToFloat64(metrics.Decisions.WithLabelValues(domain, rule, metrics.OutcomeOK))
		},
		"decisions over_limit": func() float64 {
			return testutil.ToFloat64(metrics.Decisions.WithLabelValues(domain, rule, metrics.OutcomeOverLimit))
		},
		// The first request drains the one-per-hour limit entirely, so its
		// admission is already inside the near-limit margin.
		"near limit": func() float64 {
			return testutil.ToFloat64(metrics.NearLimit.WithLabelValues(domain, rule))
		},
	}
	before := map[string]float64{}
	for name, read := range reads {
		before[name] = read()
	}

	check()
	check()

	for name, read := range reads {
		assert.Equal(t, before[name]+1, read(), "%s must grow by one across the pair", name)
	}
	assert.Contains(t, output(), "rate limit refused domain=gateway.public path=/api")
}

func TestShouldRateLimit_countsAShadowRefusalAsItsOwnOutcome(t *testing.T) {
	const domain = "gateway.public"
	p := model.Policy{Name: "dry", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "trial", Behavior: model.BehaviorShadow,
			Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	shadow := func() float64 {
		return testutil.ToFloat64(metrics.Decisions.WithLabelValues(
			domain, "dry/b/trial", metrics.OutcomeShadowOverLimit))
	}
	near := func() float64 {
		return testutil.ToFloat64(metrics.NearLimit.WithLabelValues(domain, "dry/b/trial"))
	}
	nearBefore := near()
	got := delta(shadow, func() {
		for range 2 {
			resp, err := server.ShouldRateLimit(context.Background(),
				request(domain, map[string]string{"path": "/api"}))
			require.NoError(t, err)
			require.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
				"a shadow rule reports, never vetoes")
		}
	})
	assert.Equal(t, 1.0, got, "the second request is over the shadow limit")
	assert.Equal(t, nearBefore, near(),
		"a dry run near its experimental limit is not a precursor of client-visible refusals")
}

func TestShouldRateLimit_countsAnUnmatchedCheck(t *testing.T) {
	const domain = "gateway.unmatched"
	p := model.Policy{Name: "narrow", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathExact, Value: "/api/only"}}}},
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetIn(t, domain, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	unmatched := func() float64 {
		return testutil.ToFloat64(metrics.UnmatchedChecks.WithLabelValues(domain))
	}
	got := delta(unmatched, func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/elsewhere"}))
		require.NoError(t, err)
	})
	assert.Equal(t, 1.0, got, "a check outside every route charges nothing and must say so")
}

func TestShouldRateLimit_countsTheDescriptorOverflow(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, output := recordingLogger()
	server := NewServer(ruleStore, log)

	req := request(domain, map[string]string{"path": "/api"})
	for range maxDescriptorsPerCheck {
		req.Descriptors = append(req.Descriptors, req.Descriptors[0])
	}

	overflow := func() float64 {
		return testutil.ToFloat64(metrics.Refusals.WithLabelValues(domain, metrics.CauseTooManyDescriptors))
	}
	got := delta(overflow, func() {
		resp, err := server.ShouldRateLimit(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, envoyratelimit.RateLimitResponse_OVER_LIMIT, resp.GetOverallCode())
	})
	assert.Equal(t, 1.0, got)
	// The violation repeats at traffic speed by nature, so its log line rides
	// a sampler; the first line of a window always comes through.
	assert.Contains(t, output(), "descriptors, over the limit")
	assert.Contains(t, output(), "suppressed=0")
}

func TestShouldRateLimit_samplesTheViolationLog(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, output := recordingLogger()
	server := NewServer(ruleStore, log)
	server.violationLog.limit = 1

	req := request(domain, map[string]string{"path": "/api"})
	for range maxDescriptorsPerCheck {
		req.Descriptors = append(req.Descriptors, req.Descriptors[0])
	}

	refused := func() float64 {
		return testutil.ToFloat64(metrics.Refusals.WithLabelValues(domain, metrics.CauseTooManyDescriptors))
	}
	got := delta(refused, func() {
		for range 5 {
			_, err := server.ShouldRateLimit(context.Background(), req)
			require.NoError(t, err)
		}
	})
	assert.Equal(t, 5.0, got, "the counter stays complete whatever the log budget")
	lines := strings.Count(output(), "descriptors, over the limit")
	assert.LessOrEqual(t, lines, 2, "a burst must not become a log line per request")
}

func TestShouldRateLimit_countsAnUnknownDomain(t *testing.T) {
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	unknown := func() float64 { return testutil.ToFloat64(metrics.UnknownDomainChecks) }
	placeholder := func() float64 {
		return testutil.ToFloat64(metrics.Checks.WithLabelValues(metrics.UnknownDomain, metrics.VerdictOK))
	}
	before := placeholder()
	got := delta(unknown, func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request("nobody.claims.this", map[string]string{"path": "/api"}))
		require.NoError(t, err)
	})
	assert.Equal(t, 1.0, got)
	assert.Equal(t, before+1, placeholder(),
		"the check series must use the placeholder, never the caller's domain name")
}

func TestShouldRateLimit_countsExtractionsAndSkips(t *testing.T) {
	const domain = "gateway.public"
	p := model.Policy{Name: "per-client", Domain: domain, Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "each", Counters: []string{model.KeyClient},
			Rates: []model.Rate{{Requests: 10, Period: time.Hour}}}},
	}}}
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, p))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	extractions := func() float64 {
		return testutil.ToFloat64(metrics.Extractions.WithLabelValues(model.KeyClient))
	}
	skips := func() float64 {
		return testutil.ToFloat64(metrics.ExtractionSkips.WithLabelValues(model.KeyClient, "decode_failed"))
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`))

	assert.Equal(t, 1.0, delta(extractions, func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api", "token": "h." + payload + ".s"}))
		require.NoError(t, err)
	}), "a decodable token carrying the claim counts as one extraction")

	assert.Equal(t, 1.0, delta(skips, func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api", "token": "garbage"}))
		require.NoError(t, err)
	}), "an undecodable token counts as a skip for the planned key")
}

// failingRuleSet compiles the one-per-hour policy over a store that refuses
// every operation, standing in for an outage.
func failingRuleSet(t *testing.T, domain string) *store.RuleSet {
	t.Helper()
	snap, problems := compile.Compile(domain, []model.Policy{onePerHourPolicy()}, nil)
	require.Empty(t, problems)
	return store.NewRuleSet(map[string]store.Domain{
		domain: {Engine: engine.New(snap, failingCounters{}), Snapshot: snap},
	})
}

// ruleSetIn compiles the policies into the given domain over private
// in-memory counters — for tests whose counter assertions need a domain of
// their own.
func ruleSetIn(t *testing.T, domain string, policies ...model.Policy) *store.RuleSet {
	t.Helper()
	snap, problems := compile.Compile(domain, policies, nil)
	for _, p := range problems {
		require.False(t, p.Blocking, "blocking compile problem: %+v", p)
	}
	return store.NewRuleSet(map[string]store.Domain{
		domain: {Engine: engine.New(snap, memory.New()), Snapshot: snap},
	})
}

func TestShouldRateLimit_timesTheUnknownDomainCheck(t *testing.T) {
	// Checks of an unknown domain must be visible in latency too, not only in
	// count - under the placeholder label, never the caller's name.
	ruleStore := store.New()
	ruleStore.Replace(ruleSetOf(t))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	before := histogramSamples(t, metrics.CheckDuration, metrics.UnknownDomain)
	_, err := server.ShouldRateLimit(context.Background(),
		request("nobody.claims.this.either", map[string]string{"path": "/api"}))
	require.NoError(t, err)

	assert.Equal(t, before+1, histogramSamples(t, metrics.CheckDuration, metrics.UnknownDomain),
		"the check must land one observation under the placeholder label")
}

// histogramSamples reads the sample count of one series of a histogram
// vector. Reading through the vector creates the series if absent, which is
// exactly what a before/after delta needs.
func histogramSamples(t *testing.T, vec *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	observer, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	var out dto.Metric
	require.NoError(t, observer.(prometheus.Metric).Write(&out))
	return out.GetHistogram().GetSampleCount()
}

func TestNearLimit_theExactBoundaryCounts(t *testing.T) {
	// 100*(1-0.9) computes to just under 10 in binary floating point; the
	// epsilon keeps the canonical "90% consumed" request inside the margin.
	rule := engine.RuleOutcome{Limit: 100, Remaining: 10}
	assert.True(t, nearLimit(rule, 0.9), "remaining exactly at the margin is near")

	rule.Remaining = 11
	assert.False(t, nearLimit(rule, 0.9), "one request earlier is not")
}

func TestShouldRateLimit_samplesTheStoreErrorLog(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(failingRuleSet(t, domain))
	log, output := recordingLogger()
	server := NewServer(ruleStore, log)
	server.storeLog.limit = 1

	for range 5 {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api"}))
		require.Error(t, err, "a store failure surfaces as a gRPC error")
	}

	lines := strings.Count(output(), "rate limit store error")
	require.GreaterOrEqual(t, lines, 1, "the first line of a window always comes through")
	assert.LessOrEqual(t, lines, 2, "an outage must not become a log line per check")
	assert.Contains(t, output(), "suppressed=0")
}

func TestNearLimit_theBoundaryHoldsAtLargeLimits(t *testing.T) {
	// At a billion the float grid step near the threshold is coarser than any
	// absolute epsilon; the relative one keeps the canonical 90%-consumed
	// request inside the margin at every scale.
	rule := engine.RuleOutcome{Limit: 1_000_000_000, Remaining: 100_000_000}
	assert.True(t, nearLimit(rule, 0.9))

	rule.Remaining++
	assert.False(t, nearLimit(rule, 0.9), "one request earlier is not near, even at scale")
}

func TestShouldRateLimit_countsTokensSeen(t *testing.T) {
	const domain = "gateway.public"
	ruleStore := store.New()
	ruleStore.Replace(ruleSetWith(t, onePerHourPolicy()))
	log, _ := recordingLogger()
	server := NewServer(ruleStore, log)

	tokens := func() float64 { return testutil.ToFloat64(metrics.TokensSeen) }
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`))

	assert.Equal(t, 1.0, delta(tokens, func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api", "token": "h." + payload + ".s"}))
		require.NoError(t, err)
	}), "a decision that arrived with a token counts, whatever extraction makes of it")

	assert.Zero(t, delta(tokens, func() {
		_, err := server.ShouldRateLimit(context.Background(),
			request(domain, map[string]string{"path": "/api"}))
		require.NoError(t, err)
	}), "a tokenless decision is not evidence about any claim path")
}

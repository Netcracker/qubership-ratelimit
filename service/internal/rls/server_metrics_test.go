package rls

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/identity"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

// deltas reads every series of reads around act and returns how much each one
// grew, under the same names. The series are package-level and accumulate
// across tests, so a test asserts on growth.
func deltas(reads map[string]func() float64, act func()) map[string]float64 {
	before := make(map[string]float64, len(reads))
	for name, read := range reads {
		before[name] = read()
	}
	act()
	grown := make(map[string]float64, len(reads))
	for name, read := range reads {
		grown[name] = read() - before[name]
	}
	return grown
}

// valueOf reads the current value of one counter series.
func valueOf(series prometheus.Collector) func() float64 {
	return func() float64 { return testutil.ToFloat64(series) }
}

// An admission and a refusal of one per hour count one check of each verdict
// and one decision of each outcome for the rule b/all. The admission spends
// the one request, so it is inside the near-limit margin too.
func TestShouldRateLimit_countsAnAdmissionAndARefusalUnderTheirVerdicts(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))

	got := deltas(map[string]func() float64{
		"checks ok":            valueOf(metrics.Checks.WithLabelValues(domain, metrics.VerdictOK)),
		"checks over_limit":    valueOf(metrics.Checks.WithLabelValues(domain, metrics.VerdictOverLimit)),
		"decisions ok":         valueOf(metrics.Decisions.WithLabelValues(domain, "b/all", metrics.OutcomeOK)),
		"decisions over_limit": valueOf(metrics.Decisions.WithLabelValues(domain, "b/all", metrics.OutcomeOverLimit)),
		"near limit":           valueOf(metrics.NearLimit.WithLabelValues(domain, "b/all")),
	}, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
	})

	assert.Equal(t, map[string]float64{
		"checks ok": 1, "checks over_limit": 1, "decisions ok": 1, "decisions over_limit": 1, "near limit": 1,
	}, got)
}

// A shadow rule's refusal counts under its own outcome, shadow_over_limit, and
// a shadow admission stays out of the near-limit series: that series is the
// precursor of refusals a client sees, and a dry run near its experimental
// limit is not one.
func TestShouldRateLimit_countsAShadowRuleApartFromTheEnforcedOutcomes(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, shadowPolicy(1, time.Hour)))

	got := deltas(map[string]func() float64{
		"decisions shadow_over_limit": valueOf(
			metrics.Decisions.WithLabelValues(domain, "b/trial", metrics.OutcomeShadowOverLimit)),
		"near limit": valueOf(metrics.NearLimit.WithLabelValues(domain, "b/trial")),
	}, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
	})

	assert.Equal(t, map[string]float64{"decisions shadow_over_limit": 1, "near limit": 0}, got)
}

// onlyRoutePolicy limits the one path /api/only with the rule b/all of one
// request per hour; no route matches any other path.
func onlyRoutePolicy() model.Policy {
	return model.Policy{Blocks: []model.Block{{
		Name: "b",
		Target: model.Target{Routes: []model.Route{
			{Path: model.PathMatch{Type: model.PathExact, Value: "/api/only"}}}},
		Rules: []model.Rule{{Name: "all", Rates: []model.Rate{{Requests: 1, Period: time.Hour}}}},
	}}}
}

// A check outside every route charges nothing, and the unmatched series counts
// it.
func TestShouldRateLimit_countsAnUnmatchedCheck(t *testing.T) {
	const domain = "gateway.unmatched"
	p := onlyRoutePolicy()
	server, _ := newServerOver(ruleSetOver(t, domain, &p, memory.New()))

	got := deltas(map[string]func() float64{
		"unmatched checks": valueOf(metrics.UnmatchedChecks.WithLabelValues(domain)),
	}, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/elsewhere"}))
	})

	assert.Equal(t, map[string]float64{"unmatched checks": 1}, got)
}

// A check on the route applies its rule, and the unmatched series does not
// count it. TestShouldRateLimit_countsAnUnmatchedCheck is the control, where a
// check of another path counts.
func TestShouldRateLimit_countsNoUnmatchedCheckForACheckOnTheRoute(t *testing.T) {
	const domain = "gateway.unmatched"
	p := onlyRoutePolicy()
	server, _ := newServerOver(ruleSetOver(t, domain, &p, memory.New()))

	got := deltas(map[string]func() float64{
		"unmatched checks": valueOf(metrics.UnmatchedChecks.WithLabelValues(domain)),
	}, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api/only"}))
	})

	assert.Equal(t, map[string]float64{"unmatched checks": 0}, got)
}

func TestShouldRateLimit_countsACheckOfTooManyDescriptorsAsItsOwnRefusalCause(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))

	got := deltas(map[string]func() float64{
		"refusals too_many_descriptors": valueOf(
			metrics.Refusals.WithLabelValues(domain, metrics.CauseTooManyDescriptors)),
	}, func() {
		shouldRateLimit(t, server, checkOfClients(17))
	})

	assert.Equal(t, map[string]float64{"refusals too_many_descriptors": 1}, got)
}

// A cost the engine cannot charge is counted as its own refusal cause, and the
// check as over_limit, not as unavailable.
func TestShouldRateLimit_countsAnInvalidCostAsItsOwnRefusalCause(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))
	req := request(domain, map[string]string{"path": "/api"})
	req.Descriptors[0].HitsAddend = wrapperspb.UInt64(5)
	req.Descriptors[0].IsNegativeHits = true

	got := deltas(map[string]func() float64{
		"refusals invalid_cost": valueOf(metrics.Refusals.WithLabelValues(domain, metrics.CauseInvalidCost)),
		"checks over_limit":     valueOf(metrics.Checks.WithLabelValues(domain, metrics.VerdictOverLimit)),
		"checks unavailable":    valueOf(metrics.Checks.WithLabelValues(domain, metrics.VerdictUnavailable)),
	}, func() {
		shouldRateLimit(t, server, req)
	})

	assert.Equal(t, map[string]float64{"refusals invalid_cost": 1, "checks over_limit": 1, "checks unavailable": 0}, got)
}

// With a violation log budget of one line per second, five violations leave
// one line, or two when the checks straddle a second, while the refusal series
// counts all five. The test lowers the budget of the server's own sampler,
// which NewServer sets to 10 lines per second.
func TestShouldRateLimit_samplesTheViolationLogWhileCountingEveryViolation(t *testing.T) {
	const domain = "gateway.public"
	server, log := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))
	server.violationLog.limit = 1

	got := deltas(map[string]func() float64{
		"refusals too_many_descriptors": valueOf(
			metrics.Refusals.WithLabelValues(domain, metrics.CauseTooManyDescriptors)),
	}, func() {
		for range 5 {
			shouldRateLimit(t, server, checkOfClients(17))
		}
	})

	assert.Equal(t, map[string]float64{"refusals too_many_descriptors": 5}, got)
	lines := strings.Count(log.output(), "descriptors, over the limit")
	assert.Contains(t, []int{1, 2}, lines, "violation log lines of five checks at a budget of one per second")
}

// With a refusal log budget of one line per second, five refusals leave one
// line, or two when the checks straddle a second, while the check series
// counts all five. The test lowers the budget of the server's own sampler,
// which NewServer sets to 10 lines per second.
func TestShouldRateLimit_samplesTheRefusalLogWhileCountingEveryRefusal(t *testing.T) {
	const domain = "gateway.public"
	server, log := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))
	server.refusalLog.limit = 1
	first := shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
	require.Equal(t, envoyratelimit.RateLimitResponse_OK, first.GetOverallCode(), "the first check of one per hour")

	got := deltas(map[string]func() float64{
		"checks over_limit": valueOf(metrics.Checks.WithLabelValues(domain, metrics.VerdictOverLimit)),
	}, func() {
		for range 5 {
			shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
		}
	})

	assert.Equal(t, map[string]float64{"checks over_limit": 5}, got)
	lines := strings.Count(log.output(), "rate limit refused")
	assert.Contains(t, []int{1, 2}, lines, "refusal log lines of five refusals at a budget of one per second")
}

// With an unknown-domain log budget of one line per second, five checks of an
// unknown domain leave one line, or two when the checks straddle a second,
// while the unknown-domain series counts all five. The test lowers the budget
// of the server's own sampler, which NewServer sets to 10 lines per second.
func TestShouldRateLimit_samplesTheUnknownDomainLogWhileCountingEveryCheck(t *testing.T) {
	server, log := newServerOver(nil)
	server.unknownLog.limit = 1

	got := deltas(map[string]func() float64{
		"unknown domain checks": valueOf(metrics.UnknownDomainChecks),
	}, func() {
		for range 5 {
			shouldRateLimit(t, server, request("gateway.typo", map[string]string{"path": "/api"}))
		}
	})

	assert.Equal(t, map[string]float64{"unknown domain checks": 5}, got)
	lines := strings.Count(log.output(), "unknown rate limit domain")
	assert.Contains(t, []int{1, 2}, lines, "unknown-domain log lines of five checks at a budget of one per second")
}

// An unknown domain is counted in its own series, and its check under the
// placeholder domain, never the caller's name.
func TestShouldRateLimit_countsAnUnknownDomainUnderThePlaceholder(t *testing.T) {
	server, _ := newServerOver(nil)

	got := deltas(map[string]func() float64{
		"unknown domain checks": valueOf(metrics.UnknownDomainChecks),
		"checks [unknown] ok":   valueOf(metrics.Checks.WithLabelValues(metrics.UnknownDomain, metrics.VerdictOK)),
	}, func() {
		shouldRateLimit(t, server, request("nobody.claims.this", map[string]string{"path": "/api"}))
	})

	assert.Equal(t, map[string]float64{"unknown domain checks": 1, "checks [unknown] ok": 1}, got)
}

func TestShouldRateLimit_countsAnExtractionForATokenCarryingTheClaim(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(10)))

	got := deltas(map[string]func() float64{
		"extractions sub": valueOf(metrics.Extractions.WithLabelValues(domain, model.KeySub)),
	}, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api", "token": tokenWithSub("alice")}))
	})

	assert.Equal(t, map[string]float64{"extractions sub": 1}, got)
}

// An undecodable token counts as a skip for the key the rule plans to read,
// and as no extraction of it.
func TestShouldRateLimit_countsADecodeFailedSkipForAnUndecodableToken(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(10)))

	got := deltas(map[string]func() float64{
		"skips sub decode_failed": valueOf(metrics.ExtractionSkips.WithLabelValues(domain, model.KeySub, "decode_failed")),
		"extractions sub":         valueOf(metrics.Extractions.WithLabelValues(domain, model.KeySub)),
	}, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api", "token": "garbage"}))
	})

	assert.Equal(t, map[string]float64{"skips sub decode_failed": 1, "extractions sub": 0}, got)
}

// A direct caller's value is held to the identity layer's bounds, as the
// token's would be: a value of MaxValueBytes reaches the decision, and one byte
// more is absent and counted as a too_long skip.
func TestShouldRateLimit_countsADirectValuePastTheLengthBoundAsASkip(t *testing.T) {
	const domain = "gateway.public"
	for _, tc := range []struct {
		name   string
		length int
		want   map[string]float64
	}{
		{"a value at the bound", identity.MaxValueBytes,
			map[string]float64{"skips sub too_long": 0, "extractions sub": 1}},
		{"a value one byte past the bound", identity.MaxValueBytes + 1,
			map[string]float64{"skips sub too_long": 1, "extractions sub": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newServerOver(ruleSetWith(t, perClientPerHourPolicy(10)))

			got := deltas(map[string]func() float64{
				"skips sub too_long": valueOf(metrics.ExtractionSkips.WithLabelValues(domain, model.KeySub, "too_long")),
				"extractions sub":    valueOf(metrics.Extractions.WithLabelValues(domain, model.KeySub)),
			}, func() {
				shouldRateLimit(t, server, request(domain,
					map[string]string{"path": "/api", "sub": strings.Repeat("x", tc.length)}))
			})

			assert.Equal(t, tc.want, got, "series after a sub of %d bytes", tc.length)
		})
	}
}

// A check of an unknown domain is timed too, under the placeholder label and
// never the caller's name.
func TestShouldRateLimit_timesAnUnknownDomainCheckUnderThePlaceholder(t *testing.T) {
	server, _ := newServerOver(nil)
	before := histogramSamples(t, metrics.CheckDuration, metrics.UnknownDomain)

	shouldRateLimit(t, server, request("nobody.claims.this.either", map[string]string{"path": "/api"}))

	assert.Equal(t, before+1, histogramSamples(t, metrics.CheckDuration, metrics.UnknownDomain),
		"observations of ratelimit_check_duration_seconds{domain=%q}", metrics.UnknownDomain)
}

// histogramSamples reads the sample count of one series of a histogram
// vector. Reading through the vector creates the series if absent, which is
// what a before and after comparison needs.
func histogramSamples(t *testing.T, vec *prometheus.HistogramVec, labels ...string) int {
	t.Helper()
	observer, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	var out dto.Metric
	require.NoError(t, observer.(prometheus.Metric).Write(&out))
	return int(out.GetHistogram().GetSampleCount())
}

// An admission is near the limit when the remaining count is at or under a
// tenth of the capacity, with a ratio of 0.9. The margin is a share of the
// capacity remaining counts down from: for a window of 1000 with a burst of
// 100, remaining never exceeds 100, and the margin is 10 whatever the limit
// is. 100*(1-0.9) computes to just under 10 in binary floating point, and at
// a billion the float grid step is coarser than any absolute epsilon; the
// relative epsilon keeps the canonical 90%-consumed request inside the margin
// at every scale.
func TestNearLimit_countsARemainingAtOrUnderATenthOfTheCapacity(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule engine.RuleOutcome
		near bool
	}{
		{"exactly a tenth left", engine.RuleOutcome{Limit: 100, Capacity: 100, Remaining: 10}, true},
		{"one request more than a tenth left", engine.RuleOutcome{Limit: 100, Capacity: 100, Remaining: 11}, false},
		{"a full burst bucket of a wide window", engine.RuleOutcome{Limit: 1000, Capacity: 100, Remaining: 99}, false},
		{"a tenth of the burst left", engine.RuleOutcome{Limit: 1000, Capacity: 100, Remaining: 10}, true},
		{"exactly a tenth of a billion left",
			engine.RuleOutcome{Limit: 1_000_000_000, Capacity: 1_000_000_000, Remaining: 100_000_000}, true},
		{"one request more than a tenth of a billion left",
			engine.RuleOutcome{Limit: 1_000_000_000, Capacity: 1_000_000_000, Remaining: 100_000_001}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.near, nearLimit(tc.rule, 0.9), "nearLimit(%+v, 0.9)", tc.rule)
		})
	}
}

// WithNearLimitRatio sets the margin from a ratio inside (0, 1), and a ratio
// outside it keeps the default of 0.9. Nine admissions of ten per hour leave
// 9 down to 1: a ratio of 0.5 counts the five that leave 5 or fewer, and the
// default counts the one that leaves 1.
func TestShouldRateLimit_countsNearLimitAdmissionsByTheRatioItWasGiven(t *testing.T) {
	const domain = "gateway.public"
	for _, tc := range []struct {
		name string
		opts []Option
		near float64
	}{
		{"no ratio is the default", nil, 1},
		{"a ratio of 0.5", []Option{WithNearLimitRatio(0.5)}, 5},
		{"a ratio of zero keeps the default", []Option{WithNearLimitRatio(0)}, 1},
		{"a ratio of one keeps the default", []Option{WithNearLimitRatio(1)}, 1},
		{"a ratio of NaN keeps the default", []Option{WithNearLimitRatio(math.NaN())}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(10, time.Hour)), tc.opts...)

			got := deltas(map[string]func() float64{
				"near limit": valueOf(metrics.NearLimit.WithLabelValues(domain, "b/all")),
			}, func() {
				for i := range 9 {
					resp := shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
					require.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(),
						"check %d of ten per hour", i+1)
				}
			})

			assert.Equal(t, map[string]float64{"near limit": tc.near}, got)
		})
	}
}

// The first admission of a fresh bucket with a burst of 100 on 1000 requests
// is not near the limit: 99 of a capacity of 100 are left. It used to count,
// because the margin was a tenth of the requests, 100, which every admission
// of such a window satisfies.
func TestShouldRateLimit_aFullBurstBucketIsNotNearItsLimit(t *testing.T) {
	const domain = "gateway.public"
	p := model.Policy{Blocks: []model.Block{{
		Name: "b",
		Rules: []model.Rule{{Name: "wide",
			Rates: []model.Rate{{Requests: 1000, Period: time.Minute, Burst: 100}}}},
	}}}
	server, _ := newServerOver(ruleSetWith(t, p))

	got := deltas(map[string]func() float64{
		"near limit": valueOf(metrics.NearLimit.WithLabelValues(domain, "b/wide")),
	}, func() {
		resp := shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
		require.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode(), "the first check of the bucket")
	})

	assert.Equal(t, map[string]float64{"near limit": 0}, got)
}

// With a store error log budget of one line per second, five failing checks
// leave one line, or two when the checks straddle a second, and the first line
// of a second reports no suppressed lines. The test lowers the budget of the
// server's own sampler, which NewServer sets to 10 lines per second.
func TestShouldRateLimit_samplesTheStoreErrorLog(t *testing.T) {
	const domain = "gateway.public"
	p := domainWidePolicy(1, time.Hour)
	server, log := newServerOver(ruleSetOver(t, domain, &p, failingCounters{}))
	server.storeLog.limit = 1

	for i := range 5 {
		_, err := server.ShouldRateLimit(context.Background(), request(domain, map[string]string{"path": "/api"}))
		require.Error(t, err, "check %d of a failing store", i+1)
	}

	lines := strings.Count(log.output(), "rate limit store error")
	assert.Contains(t, []int{1, 2}, lines, "store error log lines of five checks at a budget of one per second")
	assert.Contains(t, log.output(), "suppressed=0")
}

// A check that carries a token counts as a token seen, whatever extraction
// makes of it; a check without one is no evidence about any claim path.
func TestShouldRateLimit_countsATokenSeenOnlyForACheckThatCarriesOne(t *testing.T) {
	const domain = "gateway.public"
	server, _ := newServerOver(ruleSetWith(t, domainWidePolicy(1, time.Hour)))
	tokensSeen := map[string]func() float64{"tokens seen": valueOf(metrics.TokensSeen.WithLabelValues(domain))}

	withToken := deltas(tokensSeen, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api", "token": tokenWithSub("alice")}))
	})
	withoutToken := deltas(tokensSeen, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/api"}))
	})

	assert.Equal(t, map[string]float64{"tokens seen": 1}, withToken, "a check with a token")
	assert.Equal(t, map[string]float64{"tokens seen": 0}, withoutToken, "a check without a token")
}

// A token on a request that no block targets is not counted: the engine does
// not read it, so the extraction series cannot count it either. Counting it
// used to fire RatelimitKeyDeclaredNotExtracted on a domain whose blocks
// target part of its routes, for a quiet night on the routes they do target.
func TestShouldRateLimit_countsATokenSeenOnlyWhereABlockTargetsTheRequest(t *testing.T) {
	const domain = "gateway.public"
	orders := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name:   "orders",
		Target: model.Target{Routes: []model.Route{{Path: model.PathMatch{Type: model.PathPrefix, Value: "/orders"}}}},
		Rules:  []model.Rule{{Name: "total", Rates: []model.Rate{{Requests: 100, Period: time.Hour}}}},
	}}}
	server, _ := newServerOver(ruleSetWith(t, orders))
	tokensSeen := map[string]func() float64{"tokens seen": valueOf(metrics.TokensSeen.WithLabelValues(domain))}

	targeted := deltas(tokensSeen, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/orders", "token": tokenWithSub("alice")}))
	})
	untargeted := deltas(tokensSeen, func() {
		shouldRateLimit(t, server, request(domain, map[string]string{"path": "/other", "token": tokenWithSub("alice")}))
	})

	assert.Equal(t, map[string]float64{"tokens seen": 1}, targeted, "a check a block targets")
	assert.Equal(t, map[string]float64{"tokens seen": 0}, untargeted, "a check no block targets")
}

// The bucket budget binds one decision, and a check is one decision per
// descriptor: two descriptors that each fill the budget are two atomic store
// scripts of 128 buckets, not one of 256, and the check is admitted. The rules
// count by sub, so the two descriptors address disjoint buckets. The
// descriptor cap bounds the check as a whole.
func TestShouldRateLimit_appliesTheBucketBudgetToEachDecisionOnItsOwn(t *testing.T) {
	const domain = "gateway.public"
	atTheBudget := model.Policy{Domain: domain, Blocks: []model.Block{{
		Name: "b", Rules: rulesFillingTheBucketBudget(model.KeySub),
	}}}
	snap, problems := compile.Compile(testNamespace, domain, &atTheBudget)
	require.Empty(t, problems)
	require.Equal(t, engine.MaxDecisionBuckets, snap.DecisionBuckets, "buckets of one decision of the fixture")
	server, _ := newServerOver(store.NewRuleSet(map[string]store.Domain{
		domain: {Engine: engine.New(snap, memory.New()), Snapshot: snap},
	}))

	var resp *envoyratelimit.RateLimitResponse
	got := deltas(map[string]func() float64{
		"refusals too_many_buckets": valueOf(metrics.Refusals.WithLabelValues(domain, metrics.CauseTooManyBuckets)),
	}, func() {
		resp = shouldRateLimit(t, server, request(domain,
			map[string]string{"path": "/any", model.KeySub: "alice"},
			map[string]string{"path": "/any", model.KeySub: "bob"}))
	})

	assert.Equal(t, envoyratelimit.RateLimitResponse_OK, resp.GetOverallCode())
	assert.Equal(t, map[string]float64{"refusals too_many_buckets": 0}, got)
}

// An exempt check is counted under its own verdict, in its domain, and not as
// ok: ok stays the count of checks the engine decided.
func TestShouldRateLimit_countsAnExemptCheckUnderItsOwnVerdict(t *testing.T) {
	server, _ := newServerOver(exemptDomainRules(t, memory.New()),
		WithExemptPath(exemptPrefix, []string{exemptDomain}))

	got := deltas(map[string]func() float64{
		"checks exempt": valueOf(metrics.Checks.WithLabelValues(exemptDomain, metrics.VerdictExempt)),
		"checks ok":     valueOf(metrics.Checks.WithLabelValues(exemptDomain, metrics.VerdictOK)),
	}, func() {
		shouldRateLimit(t, server, request(exemptDomain, map[string]string{"path": "/ratelimit/v1/status"}))
	})

	assert.Equal(t, map[string]float64{"checks exempt": 1, "checks ok": 0}, got)
}

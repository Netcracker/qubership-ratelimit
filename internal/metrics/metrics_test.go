package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// sampleCount reads how many observations the series of labels holds in a
// histogram vector. Reading a series the vector does not hold creates it
// empty.
func sampleCount(t *testing.T, vec *prometheus.HistogramVec, labels ...string) int {
	t.Helper()
	metric, ok := vec.WithLabelValues(labels...).(prometheus.Metric)
	require.True(t, ok, "the histogram series %v is not a prometheus.Metric", labels)
	var out dto.Metric
	require.NoError(t, metric.Write(&out))
	return int(out.GetHistogram().GetSampleCount())
}

// The collector emits exactly the current view of the domains and the
// policies published one at a time, which is the property a plain gauge
// vector could not give.
func TestStateCollector_rendersThePublishedDomainsAndPolicies(t *testing.T) {
	t.Cleanup(func() {
		PublishState(nil)
		DropPolicy("gateway.public")
		DropPolicy("gateway.private")
	})
	PublishState(&StateView{
		Domains: []DomainView{{
			Domain: "gateway.public", Blocks: 3, Rules: 5, DecisionBuckets: 65, AppliedGeneration: 7,
		}},
	})
	PublishPolicy(PolicyView{Domain: "gateway.public", Ready: true, Enforced: true, InfoProblems: 1})
	PublishPolicy(PolicyView{Domain: "gateway.private", Reason: "NotCompiled", Enforced: true,
		GenerationLag: 1, BlockingProblems: 2})

	expected := `
# HELP ratelimit_domain_blocks Compiled blocks of the domain. Observed rather than bounded: watch the target scan, do not cap it.
# TYPE ratelimit_domain_blocks gauge
ratelimit_domain_blocks{domain="gateway.public"} 3
# HELP ratelimit_domain_decision_buckets Worst-case buckets one decision can collect across the domain, against the budget of 128.
# TYPE ratelimit_domain_decision_buckets gauge
ratelimit_domain_decision_buckets{domain="gateway.public"} 65
# HELP ratelimit_domain_rules Compiled rules of the domain across its blocks.
# TYPE ratelimit_domain_rules gauge
ratelimit_domain_rules{domain="gateway.public"} 5
# HELP ratelimit_policy_applied_generation The generation of the domain this replica enforces.
# TYPE ratelimit_policy_applied_generation gauge
ratelimit_policy_applied_generation{domain="gateway.public"} 7
# HELP ratelimit_policy_enforced Whether any generation of the policy is enforced at all.
# TYPE ratelimit_policy_enforced gauge
ratelimit_policy_enforced{domain="gateway.private"} 1
ratelimit_policy_enforced{domain="gateway.public"} 1
# HELP ratelimit_policy_generation_lag How far the enforced generation trails the latest one.
# TYPE ratelimit_policy_generation_lag gauge
ratelimit_policy_generation_lag{domain="gateway.private"} 1
ratelimit_policy_generation_lag{domain="gateway.public"} 0
# HELP ratelimit_policy_ready Whether the latest generation of the policy is the one enforced; reason is empty when it is.
# TYPE ratelimit_policy_ready gauge
ratelimit_policy_ready{domain="gateway.private",reason="NotCompiled"} 0
ratelimit_policy_ready{domain="gateway.public",reason=""} 1
# HELP ratelimit_policy_rule_problems Rule diagnostics reported for the latest generation of the policy. Severity blocking means the generation is not enforced; info is a note about one that is.
# TYPE ratelimit_policy_rule_problems gauge
ratelimit_policy_rule_problems{domain="gateway.private",severity="blocking"} 2
ratelimit_policy_rule_problems{domain="gateway.private",severity="info"} 0
ratelimit_policy_rule_problems{domain="gateway.public",severity="blocking"} 0
ratelimit_policy_rule_problems{domain="gateway.public",severity="info"} 1
`
	assert.NoError(t, testutil.CollectAndCompare(stateCollector{}, strings.NewReader(expected)))
}

// A policy that disappeared leaves no stale series, and the domain series,
// which a dropped policy does not own, stay.
func TestStateCollector_dropsTheSeriesOfADroppedPolicy(t *testing.T) {
	t.Cleanup(func() { PublishState(nil) })
	PublishState(&StateView{Domains: []DomainView{{Domain: "gateway.public", Blocks: 3, Rules: 5}}})
	PublishPolicy(PolicyView{Domain: "gateway.public", Ready: true, Enforced: true})
	PublishPolicy(PolicyView{Domain: "gateway.private", Reason: "NotCompiled", Enforced: true})

	DropPolicy("gateway.private")
	DropPolicy("gateway.public")

	assert.NoError(t, testutil.CollectAndCompare(stateCollector{}, strings.NewReader(""),
		"ratelimit_policy_ready", "ratelimit_policy_enforced", "ratelimit_policy_generation_lag",
		"ratelimit_policy_rule_problems"), "the series of the dropped policies")
	assert.Equal(t, 4, testutil.CollectAndCount(stateCollector{},
		"ratelimit_domain_blocks", "ratelimit_domain_rules", "ratelimit_domain_decision_buckets",
		"ratelimit_policy_applied_generation"), "the series of the published domain")
}

// The operator's scrape carries no domains at all, and a policy is reported
// there all the same.
func TestStateCollector_reportsAPolicyWithoutADomainView(t *testing.T) {
	t.Cleanup(func() { DropPolicy("gateway.lonely") })
	PublishState(nil)

	PublishPolicy(PolicyView{Domain: "gateway.lonely", Ready: true})

	assert.Equal(t, 5, testutil.CollectAndCount(stateCollector{}),
		"ready, enforced, lag, and two problem severities")
}

// The collector emits no series while no view and no policy is published. Its
// control is TestStateCollector_rendersThePublishedDomainsAndPolicies.
func TestStateCollector_isSilentBeforeTheFirstRebuild(t *testing.T) {
	PublishState(nil)
	assert.Zero(t, testutil.CollectAndCount(stateCollector{}))
}

// stubStore returns one allowed verdict at once, or the given error.
type stubStore struct {
	err error
}

func (s stubStore) Decide(context.Context, []store.Bucket, int64) ([]store.Verdict, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []store.Verdict{{Allowed: true}}, nil
}

func (s stubStore) Peek(context.Context, []store.Bucket, int64) ([]store.Verdict, error) {
	return nil, s.err
}

func (s stubStore) Reset(context.Context, []string) error { return s.err }

func TestInstrumentStore_observesTheRoundtripOfADecision(t *testing.T) {
	instrumented := InstrumentStore("roundtrip.domain", stubStore{})
	before := sampleCount(t, StoreRoundtrip, "roundtrip.domain")

	_, err := instrumented.Decide(context.Background(), nil, 1)

	require.NoError(t, err)
	assert.Equal(t, before+1, sampleCount(t, StoreRoundtrip, "roundtrip.domain"),
		"observations of roundtrip.domain")
}

// The reason separates what an operator does about a failed decision: timeout
// is load or distance, server is the store answering an error, which no retry
// cures, and other is connectivity. A new reason adds a row.
func TestInstrumentStore_countsAFailedDecisionByReason(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		err    error
		reason string
	}{
		{"a deadline is a timeout", "errors.deadline", context.DeadlineExceeded, "timeout"},
		{"a network timeout is a timeout", "errors.net-timeout",
			fmt.Errorf("dial: %w", &net.DNSError{IsTimeout: true}), "timeout"},
		{"a redis error is a server answer", "errors.redis", goredis.ErrNoScript, "server"},
		{"a wrapped redis error is a server answer", "errors.wrapped-redis",
			fmt.Errorf("decide: %w", goredis.ErrNoScript), "server"},
		{"any other error is other", "errors.refused", errors.New("connection refused"), "other"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			instrumented := InstrumentStore(c.domain, stubStore{err: c.err})
			before := testutil.ToFloat64(StoreErrors.WithLabelValues(c.domain, c.reason))

			_, err := instrumented.Decide(context.Background(), nil, 1)

			require.ErrorIs(t, err, c.err)
			assert.Equal(t, before+1, testutil.ToFloat64(StoreErrors.WithLabelValues(c.domain, c.reason)),
				"store errors of reason %s after a decision failing with %v", c.reason, c.err)
		})
	}
}

// Peek and Reset belong to the management API, not to the traffic the store
// series describe: their errors reach the caller and leave the error counter
// alone. The decision that does count is in
// TestInstrumentStore_countsAFailedDecisionByReason.
func TestInstrumentStore_passesAFailedPeekThroughUncounted(t *testing.T) {
	failure := errors.New("management path")
	instrumented := InstrumentStore("peek.domain", stubStore{err: failure})

	_, err := instrumented.Peek(context.Background(), nil, 1)

	assert.ErrorIs(t, err, failure)
	assert.Zero(t, testutil.ToFloat64(StoreErrors.WithLabelValues("peek.domain", "other")),
		"store errors of peek.domain")
}

// Reset belongs to the management API as Peek does: its error reaches the
// caller and leaves the error counter alone.
func TestInstrumentStore_passesAFailedResetThroughUncounted(t *testing.T) {
	failure := errors.New("management path")
	instrumented := InstrumentStore("reset.domain", stubStore{err: failure})

	err := instrumented.Reset(context.Background(), nil)

	assert.ErrorIs(t, err, failure)
	assert.Zero(t, testutil.ToFloat64(StoreErrors.WithLabelValues("reset.domain", "other")),
		"store errors of reset.domain")
}

func TestCacheStatsCollectors_startAtZero(t *testing.T) {
	collectors := CacheStatsCollectors(&engine.CacheStats{})
	require.Len(t, collectors, 2)
	for _, c := range collectors {
		assert.Zero(t, testutil.ToFloat64(c), "%v", c.(prometheus.Metric).Desc())
	}
}

// A dead claim path never increments, so an unseeded key has no series to
// alert on.
func TestSeedExtractions_createsAZeroSeriesForEveryDeclaredKey(t *testing.T) {
	before := testutil.CollectAndCount(Extractions)

	SeedExtractions(map[string][]string{"seed.domain": {"seeded_dead", "seeded_quiet"}})

	assert.Equal(t, before+2, testutil.CollectAndCount(Extractions), "series of the extraction counter")
	assert.Zero(t, testutil.ToFloat64(Extractions.WithLabelValues("seed.domain", "seeded_dead")), "seeded_dead")
	assert.Zero(t, testutil.ToFloat64(Extractions.WithLabelValues("seed.domain", "seeded_quiet")), "seeded_quiet")
}

func TestSeedExtractions_keepsTheValueOfASeriesItSeedsAgain(t *testing.T) {
	SeedExtractions(map[string][]string{"reseed.domain": {"seeded_live"}})
	Extractions.WithLabelValues("reseed.domain", "seeded_live").Inc()
	before := testutil.ToFloat64(Extractions.WithLabelValues("reseed.domain", "seeded_live"))

	SeedExtractions(map[string][]string{"reseed.domain": {"seeded_live"}})

	assert.Equal(t, before, testutil.ToFloat64(Extractions.WithLabelValues("reseed.domain", "seeded_live")),
		"reseeding an existing series is a no-op, not a reset")
}

// The operator's series. The service's scrape carries none of them. An
// operator pod without the Lease carries ratelimit_leader 0 and no fleet
// series, so a query finds the scrape that carries them by ratelimit_leader.
func TestFleetCollector_reportsWhatTheOperatorSaw(t *testing.T) {
	t.Cleanup(func() {
		DropFleet("gateway.public")
		DropFleet("gateway.private")
		SetLeader(false)
	})

	SetLeader(true)
	PublishFleet("gateway.public", FleetSample{Applied: 3, Total: 3, Reason: "Progressing"})
	PublishFleet("gateway.private", FleetSample{
		Applied: 1, Total: 3, Stalled: true, Reason: "ReplicaStale"})

	expected := `
# HELP ratelimit_leader Whether this operator pod holds the Lease. The status series are only written by the pod reporting 1.
# TYPE ratelimit_leader gauge
ratelimit_leader 1
# HELP ratelimit_policy_replicas Replicas of the domain by state: total is the ready fleet, applied is how many of it enforce the active generation.
# TYPE ratelimit_policy_replicas gauge
ratelimit_policy_replicas{domain="gateway.private",state="applied"} 1
ratelimit_policy_replicas{domain="gateway.private",state="total"} 3
ratelimit_policy_replicas{domain="gateway.public",state="applied"} 3
ratelimit_policy_replicas{domain="gateway.public",state="total"} 3
# HELP ratelimit_policy_stalled Whether the domain is stuck rather than progressing; reason names which way.
# TYPE ratelimit_policy_stalled gauge
ratelimit_policy_stalled{domain="gateway.private",reason="ReplicaStale"} 1
ratelimit_policy_stalled{domain="gateway.public",reason="Progressing"} 0
`
	assert.NoError(t, testutil.CollectAndCompare(fleetCollector{}, strings.NewReader(expected)))
}

// A deleted policy has to take its series with it: an alert on a stalled
// domain would otherwise fire forever on an object nobody can fix. The leader
// series stays, at 0 on a pod that does not hold the Lease.
func TestFleetCollector_forgetsADeletedDomain(t *testing.T) {
	SetLeader(false)
	PublishFleet("gateway.retired", FleetSample{Applied: 1, Total: 1, Reason: "Progressing"})

	DropFleet("gateway.retired")

	expected := `
# HELP ratelimit_leader Whether this operator pod holds the Lease. The status series are only written by the pod reporting 1.
# TYPE ratelimit_leader gauge
ratelimit_leader 0
`
	assert.NoError(t, testutil.CollectAndCompare(fleetCollector{}, strings.NewReader(expected)))
}

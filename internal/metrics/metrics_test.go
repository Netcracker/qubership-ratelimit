package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/store"
)

func TestStateCollector_rendersThePublishedView(t *testing.T) {
	// The collector emits exactly the current view: a policy that changed its
	// reason or disappeared leaves no stale series, which is the property a
	// plain gauge vector could not give.
	PublishState(&StateView{
		Domains: []DomainView{{Domain: "gateway.public", Blocks: 3, DecisionBuckets: 65}},
		Policies: []PolicyView{
			{Policy: "biz/good", Ready: true, Enforced: true, Buckets: 64},
			{Policy: "biz/gated", Reason: "RejectedByDomainBudget", Enforced: true,
				GenerationLag: 1, RuleProblems: 0, Buckets: 1},
		},
		Mappings: []MappingView{{Mapping: "biz/gateway.public", Ready: true}},
	})
	defer PublishState(nil)

	expected := `
# HELP ratelimit_domain_blocks Compiled blocks of the domain, against the reference bound of 256.
# TYPE ratelimit_domain_blocks gauge
ratelimit_domain_blocks{domain="gateway.public"} 3
# HELP ratelimit_domain_decision_buckets Worst-case buckets one request can collect across the domain, against the runtime backstop of 128.
# TYPE ratelimit_domain_decision_buckets gauge
ratelimit_domain_decision_buckets{domain="gateway.public"} 65
# HELP ratelimit_mapping_ready Whether the latest generation of the mapping is the one enforced.
# TYPE ratelimit_mapping_ready gauge
ratelimit_mapping_ready{mapping="biz/gateway.public"} 1
# HELP ratelimit_policy_buckets Worst-case decision buckets this policy contributes to its domain budget.
# TYPE ratelimit_policy_buckets gauge
ratelimit_policy_buckets{policy="biz/gated"} 1
ratelimit_policy_buckets{policy="biz/good"} 64
# HELP ratelimit_policy_enforced Whether any generation of the policy is enforced at all.
# TYPE ratelimit_policy_enforced gauge
ratelimit_policy_enforced{policy="biz/gated"} 1
ratelimit_policy_enforced{policy="biz/good"} 1
# HELP ratelimit_policy_generation_lag How far the enforced generation trails the latest one.
# TYPE ratelimit_policy_generation_lag gauge
ratelimit_policy_generation_lag{policy="biz/gated"} 1
ratelimit_policy_generation_lag{policy="biz/good"} 0
# HELP ratelimit_policy_ready Whether the latest generation of the policy is the one enforced; reason is empty when it is.
# TYPE ratelimit_policy_ready gauge
ratelimit_policy_ready{policy="biz/gated",reason="RejectedByDomainBudget"} 0
ratelimit_policy_ready{policy="biz/good",reason=""} 1
# HELP ratelimit_policy_rule_problems Rule diagnostics reported for the latest generation of the policy.
# TYPE ratelimit_policy_rule_problems gauge
ratelimit_policy_rule_problems{policy="biz/gated"} 0
ratelimit_policy_rule_problems{policy="biz/good"} 0
`
	require.NoError(t, testutil.CollectAndCompare(stateCollector{}, strings.NewReader(expected)))
}

func TestStateCollector_isSilentBeforeTheFirstRebuild(t *testing.T) {
	PublishState(nil)
	assert.Zero(t, testutil.CollectAndCount(stateCollector{}))
}

// stubStore answers immediately, or fails with the given error.
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

func TestInstrumentStore_observesTheRoundtrip(t *testing.T) {
	instrumented := InstrumentStore("roundtrip.domain", stubStore{})

	before := testutil.CollectAndCount(StoreRoundtrip)
	_, err := instrumented.Decide(context.Background(), nil, 1)
	require.NoError(t, err)

	assert.Equal(t, before+1, testutil.CollectAndCount(StoreRoundtrip),
		"the domain's roundtrip series must appear after the first decision")
}

func TestInstrumentStore_classifiesErrors(t *testing.T) {
	cases := []struct {
		err    error
		reason string
	}{
		{context.DeadlineExceeded, "timeout"},
		{fmt.Errorf("dial: %w", &net.DNSError{IsTimeout: true}), "timeout"},
		{goredis.ErrNoScript, "server"},
		{errors.New("connection refused"), "other"},
	}
	for _, c := range cases {
		domain := fmt.Sprintf("errors.%s", c.reason)
		instrumented := InstrumentStore(domain, stubStore{err: c.err})
		before := testutil.ToFloat64(StoreErrors.WithLabelValues(domain, c.reason))

		_, err := instrumented.Decide(context.Background(), nil, 1)
		require.Error(t, err)

		got := testutil.ToFloat64(StoreErrors.WithLabelValues(domain, c.reason))
		assert.Equal(t, before+1, got, "error %v must count as %s", c.err, c.reason)
	}
}

func TestStoreErrorReason_reportsAServerAnswer(t *testing.T) {
	// A redis error value is the store answering an error — a script or
	// command problem no retry cures — and must not read as connectivity.
	assert.Equal(t, "server", storeErrorReason(fmt.Errorf("decide: %w", goredis.ErrNoScript)))
}

func TestCacheStatsCollectors_startAtZero(t *testing.T) {
	collectors := CacheStatsCollectors(&engine.CacheStats{})
	require.Len(t, collectors, 2)
	for _, c := range collectors {
		assert.Zero(t, testutil.ToFloat64(c))
	}
}

func TestInstrumentStore_delegatesTheManagementPath(t *testing.T) {
	failure := errors.New("management path")
	instrumented := InstrumentStore("mgmt.domain", stubStore{err: failure})

	_, peekErr := instrumented.Peek(context.Background(), nil, 1)
	assert.ErrorIs(t, peekErr, failure)
	assert.ErrorIs(t, instrumented.Reset(context.Background(), nil), failure)
	// Neither call is traffic: the error counter must not move.
	assert.Zero(t, testutil.ToFloat64(StoreErrors.WithLabelValues("mgmt.domain", "other")))
}

func TestSeedExtractions_makesZeroObservableWithoutResettingLiveSeries(t *testing.T) {
	before := testutil.CollectAndCount(Extractions)
	SeedExtractions([]string{"seeded_dead", "seeded_live"})
	assert.Equal(t, before+2, testutil.CollectAndCount(Extractions),
		"seeding has to create the series: a dead claim path never increments, so an unseeded key has no series to alert on")
	assert.Zero(t, testutil.ToFloat64(Extractions.WithLabelValues("seeded_dead")))

	Extractions.WithLabelValues("seeded_live").Inc()
	SeedExtractions([]string{"seeded_live"})
	assert.Equal(t, 1.0, testutil.ToFloat64(Extractions.WithLabelValues("seeded_live")),
		"reseeding an existing series is a no-op, not a reset")
}

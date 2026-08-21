package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

// ruleSetOf compiles the objects and binds each domain to a counter store, which
// is what the updater does on every rebuild.
func ruleSetOf(t *testing.T, objects ...*v1alpha1.RateLimitPolicy) *RuleSet {
	t.Helper()
	input := policy.Input{}
	for _, object := range objects {
		input.Policies = append(input.Policies, *object)
	}
	counters := memory.New()
	domains := map[string]Domain{}
	for domain, snapshot := range policy.Compile(input).Snapshots {
		domains[domain] = Domain{Engine: engine.New(snapshot, counters), Snapshot: snapshot}
	}
	return NewRuleSet(domains)
}

func TestNew_emptyStoreKnowsNoDomain(t *testing.T) {
	s := New()

	require.NotNil(t, s.Load())
	assert.False(t, s.Load().Has("gateway.public"))
}

func TestReplace_swapsSnapshot(t *testing.T) {
	s := New()

	s.Replace(ruleSetOf(t, policyObject("private", "gateway.private")))

	assert.True(t, s.Load().Has("gateway.private"))
	assert.False(t, s.Load().Has("gateway.public"))
}

func TestReplace_nilYieldsEmptySnapshot(t *testing.T) {
	s := New()
	s.Replace(ruleSetOf(t, policyObject("private", "gateway.private")))

	s.Replace(nil)

	require.NotNil(t, s.Load(), "a nil replacement must not leave readers with a nil snapshot")
	assert.False(t, s.Load().Has("gateway.private"))
}

func TestHasDomain_twoPoliciesNamingOneDomainAreOneDomain(t *testing.T) {
	s := New()

	s.Replace(ruleSetOf(t,
		policyObject("alpha", "gateway.public"),
		policyObject("zeta", "gateway.public"),
	))

	require.True(t, s.Load().Has("gateway.public"))
	assert.Equal(t, 1, s.Load().Len(), "two policies naming one domain share one engine")
}

func TestNeedLeaderElection_updaterRunsOnEveryReplica(t *testing.T) {
	// Every replica answers rate limit checks, so every replica needs a populated
	// store. A store filled only on the leader would make limits apply on some
	// pods and not others.
	updater := &Updater{}

	assert.False(t, updater.NeedLeaderElection())
}

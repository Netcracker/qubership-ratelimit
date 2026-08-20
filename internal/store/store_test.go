package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
)

// testEngines builds one empty-snapshot engine per domain over private
// in-memory counters, mirroring what BuildRuleSet does for the stub CRD.
func testEngines(t *testing.T, domains ...string) map[string]*engine.Engine {
	t.Helper()
	out := make(map[string]*engine.Engine, len(domains))
	for _, d := range domains {
		snap, problems := compile.Compile(d, nil, nil)
		require.Empty(t, problems)
		out[d] = engine.New(snap, memory.New())
	}
	return out
}

func TestNew_emptyStoreKnowsNoDomain(t *testing.T) {
	s := New()

	require.NotNil(t, s.Load())
	assert.False(t, s.HasDomain("gateway.public"))
}

func TestReplace_swapsSnapshot(t *testing.T) {
	s := New()

	s.Replace(NewRuleSet(testEngines(t, "gateway.private")))

	assert.True(t, s.HasDomain("gateway.private"))
	assert.False(t, s.HasDomain("gateway.public"))
}

func TestReplace_nilYieldsEmptySnapshot(t *testing.T) {
	s := New()
	s.Replace(NewRuleSet(testEngines(t, "gateway.private")))

	s.Replace(nil)

	require.NotNil(t, s.Load(), "a nil replacement must not leave readers with a nil snapshot")
	assert.False(t, s.HasDomain("gateway.private"))
}

func TestNeedLeaderElection_updaterRunsOnEveryReplica(t *testing.T) {
	// Every replica answers rate limit checks, so every replica needs a populated
	// store. A store filled only on the leader would make limits apply on some
	// pods and not others.
	updater := &Updater{}

	assert.False(t, updater.NeedLeaderElection())
}

func TestRuleSet_returnsTheDomainsOwnEngine(t *testing.T) {
	engines := testEngines(t, "gateway.public", "gateway.private")
	ruleSet := NewRuleSet(engines)

	assert.Same(t, engines["gateway.public"], ruleSet.Engine("gateway.public"))
	assert.Nil(t, ruleSet.Engine("gateway.absent"), "an unbound domain has no engine")
	assert.Equal(t, 2, ruleSet.Len())
}

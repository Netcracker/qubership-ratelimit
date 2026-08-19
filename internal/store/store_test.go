package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

func snapshotOf(t *testing.T, objects ...*v1alpha1.RateLimitPolicy) *policy.Snapshot {
	t.Helper()
	input := policy.Input{}
	for _, object := range objects {
		input.Policies = append(input.Policies, *object)
	}
	return policy.Compile(input).Snapshot
}

func TestNew_emptyStoreKnowsNoDomain(t *testing.T) {
	s := New()

	require.NotNil(t, s.Load())
	assert.False(t, s.HasDomain("gateway.public"))
}

func TestReplace_swapsSnapshot(t *testing.T) {
	s := New()

	s.Replace(snapshotOf(t, policyObject("private", "gateway.private")))

	assert.True(t, s.HasDomain("gateway.private"))
	assert.False(t, s.HasDomain("gateway.public"))
}

func TestReplace_nilYieldsEmptySnapshot(t *testing.T) {
	s := New()
	s.Replace(snapshotOf(t, policyObject("private", "gateway.private")))

	s.Replace(nil)

	require.NotNil(t, s.Load(), "a nil replacement must not leave readers with a nil snapshot")
	assert.False(t, s.HasDomain("gateway.private"))
}

func TestHasDomain_twoPoliciesNamingOneDomainAreOneDomain(t *testing.T) {
	s := New()

	s.Replace(snapshotOf(t,
		policyObject("alpha", "gateway.public"),
		policyObject("zeta", "gateway.public"),
	))

	require.True(t, s.HasDomain("gateway.public"))
	assert.Len(t, s.Load().Names(), 1)
	assert.Len(t, s.Load().Domain("gateway.public").Blocks, 2,
		"both policies contribute their blocks to the one domain")
}

func TestNeedLeaderElection_updaterRunsOnEveryReplica(t *testing.T) {
	// Every replica answers rate limit checks, so every replica needs a populated
	// store. A store filled only on the leader would make limits apply on some
	// pods and not others.
	updater := &Updater{}

	assert.False(t, updater.NeedLeaderElection())
}

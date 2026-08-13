package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_emptyStoreKnowsNoDomain(t *testing.T) {
	s := New()

	require.NotNil(t, s.Load())
	assert.False(t, s.HasDomain("gateway.public"))
}

func TestReplace_swapsSnapshot(t *testing.T) {
	s := New()

	s.Replace(NewRuleSet([]string{"gateway.private"}))

	assert.True(t, s.HasDomain("gateway.private"))
	assert.False(t, s.HasDomain("gateway.public"))
}

func TestReplace_nilYieldsEmptySnapshot(t *testing.T) {
	s := New()
	s.Replace(NewRuleSet([]string{"gateway.private"}))

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

func TestNewRuleSet_collapsesDuplicateDomains(t *testing.T) {
	// Two policies may bind to the same domain; the set holds it once.
	ruleSet := NewRuleSet([]string{"gateway.public", "gateway.public", "gateway.private"})

	assert.Len(t, ruleSet.Domains, 2)
	assert.True(t, ruleSet.Has("gateway.public"))
	assert.True(t, ruleSet.Has("gateway.private"))
}

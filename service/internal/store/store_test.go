package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/convert"
)

// policySpec is the spec of one domain, as the service reads it off its
// volume.
func policySpec(domain string) v1.RateLimitPolicySpec {
	return v1.RateLimitPolicySpec{
		Domain: domain,
		Limits: []v1.LimitBlock{{
			Name: "api",
			Rules: []v1.Rule{{
				Name:  "total",
				Rates: []v1.Rate{{Requests: 100, PeriodSeconds: 60}},
			}},
		}},
	}
}

// boundDomain compiles the spec and binds it to a counter store, which is
// what the service's applier does for every domain on every apply.
func boundDomain(t *testing.T, spec v1.RateLimitPolicySpec) Domain {
	t.Helper()
	snapshot, problems := compile.Compile("biz", spec.Domain, convert.Policy(&spec))
	require.Empty(t, problems)
	return Domain{Engine: engine.New(snapshot, memory.New()), Snapshot: snapshot}
}

// ruleSetOf binds every spec to an engine and builds the set of them.
func ruleSetOf(t *testing.T, specs ...v1.RateLimitPolicySpec) *RuleSet {
	t.Helper()
	domains := map[string]Domain{}
	for _, spec := range specs {
		domains[spec.Domain] = boundDomain(t, spec)
	}
	return NewRuleSet(domains)
}

func TestNew_emptyStoreKnowsNoDomain(t *testing.T) {
	s := New()

	require.NotNil(t, s.Load())
	assert.False(t, s.Load().Has("gateway.public"))
}

func TestReplace_makesTheDomainsOfTheNewSetCurrent(t *testing.T) {
	s := New()

	s.Replace(ruleSetOf(t, policySpec("gateway.private")))

	assert.True(t, s.Load().Has("gateway.private"))
	assert.False(t, s.Load().Has("gateway.public"))
}

func TestReplace_nilYieldsEmptySnapshot(t *testing.T) {
	s := New()
	s.Replace(ruleSetOf(t, policySpec("gateway.private")))

	s.Replace(nil)

	require.NotNil(t, s.Load(), "a nil replacement must not leave readers with a nil snapshot")
	assert.False(t, s.Load().Has("gateway.private"))
}

func TestHasDomain_isTrueForEveryDomainOfTheSet(t *testing.T) {
	s := New()

	s.Replace(ruleSetOf(t,
		policySpec("gateway.public"),
		policySpec("gateway.private"),
	))

	assert.True(t, s.Load().Has("gateway.public"))
	assert.True(t, s.Load().Has("gateway.private"))
	assert.Equal(t, 2, s.Load().Len())
}

func TestSwappedAt_isZeroBeforeTheFirstSwap(t *testing.T) {
	assert.Zero(t, New().SwappedAt())
}

// The set is the one thing a reader loads, and everything a reader pairs
// with the rules rides on it, the time of the swap that made it current
// included.
func TestReplace_stampsTheSwapTimeOnTheSetItSwapsIn(t *testing.T) {
	s := New()
	set := ruleSetOf(t, policySpec("gateway.private"))
	before := time.Now()

	s.Replace(set)

	assert.WithinRange(t, set.SwappedAt(), before, time.Now(), "the swap time on the set")
	assert.Equal(t, set.SwappedAt(), s.SwappedAt(), "the swap time the store reports")
}

func TestReplace_leavesTheSwapTimeOfTheSetItRetires(t *testing.T) {
	s := New()
	retired := ruleSetOf(t, policySpec("gateway.private"))
	s.Replace(retired)
	swapped := retired.SwappedAt()

	s.Replace(ruleSetOf(t, policySpec("gateway.public")))

	assert.Equal(t, swapped, retired.SwappedAt(), "the swap time of the retired set")
	assert.False(t, s.SwappedAt().Before(swapped), "the swap time %v of the current set precedes %v of the retired one",
		s.SwappedAt(), swapped)
}

// Every accessor of the set reads the domain that was bound.
func TestRuleSet_returnsTheBoundDomainThroughEveryAccessor(t *testing.T) {
	bound := boundDomain(t, policySpec("gateway.private"))
	bound.Version = "a1b2c3d4e5f6"
	bound.Generation = 3
	bound.UID = "uid-3"
	bound.AppliedAt = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	set := NewRuleSet(map[string]Domain{"gateway.private": bound})

	d, ok := set.Domain("gateway.private")

	require.True(t, ok)
	assert.Equal(t, bound, d)
	assert.Same(t, bound.Engine, set.Engine("gateway.private"))
	assert.Same(t, bound.Snapshot, set.Snapshot("gateway.private"))
	assert.Equal(t, "a1b2c3d4e5f6", set.Version("gateway.private"))
}

// An unbound domain is reported as such rather than as a zero value to read
// fields off.
func TestRuleSet_reportsAnUnboundDomainAsNotFound(t *testing.T) {
	set := ruleSetOf(t, policySpec("gateway.private"))

	_, ok := set.Domain("gateway.public")

	assert.False(t, ok)
}

// A refusal is not a swap: the rules and the swap time stay as they were, and
// the set a reader already holds is not rewritten under it.
func TestRefuse_publishesTheRefusalOnTheCurrentRules(t *testing.T) {
	s := New()
	s.Replace(ruleSetOf(t, policySpec("gateway.private")))
	before := s.Load()

	s.Refuse(&applied.Refusal{FormatVersion: 9, Reason: "unsupported"})

	refused := s.Load()
	assert.Equal(t, &applied.Refusal{FormatVersion: 9, Reason: "unsupported"}, refused.Refusal())
	assert.True(t, refused.Has("gateway.private"), "the rules stay as they were")
	assert.Equal(t, before.SwappedAt(), refused.SwappedAt())
	assert.Nil(t, before.Refusal(), "the refusal of the set a reader already held")
}

// A set swapped in after a refusal carries no refusal.
func TestReplace_swapsInASetWithoutTheRefusal(t *testing.T) {
	s := New()
	s.Replace(ruleSetOf(t, policySpec("gateway.private")))
	s.Refuse(&applied.Refusal{FormatVersion: 9, Reason: "unsupported"})

	s.Replace(ruleSetOf(t, policySpec("gateway.public")))

	assert.Nil(t, s.Load().Refusal())
}

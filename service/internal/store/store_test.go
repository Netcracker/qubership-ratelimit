package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/convert"
)

// policySpec is the spec of one domain, as the service reads it off its
// volume.
func policySpec(domain string) v1alpha1.RateLimitPolicySpec {
	return v1alpha1.RateLimitPolicySpec{
		Domain: domain,
		Limits: []v1alpha1.LimitBlock{{
			Name: "api",
			Rules: []v1alpha1.Rule{{
				Name:  "total",
				Rates: []v1alpha1.Rate{{Requests: 100, PeriodSeconds: 60}},
			}},
		}},
	}
}

// ruleSetOf compiles the specs and binds each domain to a counter store,
// which is what the service's applier does on every apply.
func ruleSetOf(t *testing.T, specs ...v1alpha1.RateLimitPolicySpec) *RuleSet {
	t.Helper()
	counters := memory.New()
	domains := map[string]Domain{}
	for _, spec := range specs {
		snapshot, problems := compile.Compile("biz", spec.Domain, convert.Policy(&spec))
		require.Empty(t, problems)
		domains[spec.Domain] = Domain{Engine: engine.New(snapshot, counters), Snapshot: snapshot}
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

func TestHasDomain_eachDomainCarriesItsOwnEngine(t *testing.T) {
	s := New()

	s.Replace(ruleSetOf(t,
		policySpec("gateway.public"),
		policySpec("gateway.private"),
	))

	require.True(t, s.Load().Has("gateway.public"))
	require.True(t, s.Load().Has("gateway.private"))
	assert.Equal(t, 2, s.Load().Len())
}

// The set is the one thing a reader loads, and everything a reader pairs
// with the rules rides on it: the domain's applied facts and the time of
// the swap that made the set current.
func TestReplace_stampsTheSwapTimeOnTheSetItSwapsIn(t *testing.T) {
	s := New()
	assert.True(t, s.SwappedAt().IsZero(), "nothing was swapped in yet")

	first := ruleSetOf(t, policySpec("gateway.private"))
	s.Replace(first)
	swapped := s.SwappedAt()
	assert.False(t, swapped.IsZero())
	assert.Equal(t, swapped, first.SwappedAt(), "the time is on the set, where a reader of the set finds it")

	s.Replace(ruleSetOf(t, policySpec("gateway.public")))
	assert.Equal(t, swapped, first.SwappedAt(), "a later swap does not touch the set it retired")
	assert.False(t, s.SwappedAt().Before(swapped))
}

func TestDomain_returnsTheWholeBoundDomain(t *testing.T) {
	set := ruleSetOf(t, policySpec("gateway.private"))
	d, ok := set.Domain("gateway.private")
	require.True(t, ok)
	assert.Same(t, set.Engine("gateway.private"), d.Engine)
	assert.Same(t, set.Snapshot("gateway.private"), d.Snapshot)
	assert.Equal(t, set.Version("gateway.private"), d.Version)

	_, ok = set.Domain("gateway.public")
	assert.False(t, ok, "an unbound domain is reported as such rather than as a zero value to read fields off")
}

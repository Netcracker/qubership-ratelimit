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

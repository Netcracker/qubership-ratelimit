package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/policy"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	return s
}

// testNamespace is the single business namespace an installation serves.
const testNamespace = "biz"

func policyObject(name, domain string) *v1alpha1.RateLimitPolicy {
	return &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain: domain,
			Limits: []v1alpha1.LimitBlock{{
				Name: "api",
				Rules: []v1alpha1.Rule{{
					Name:  "total",
					Rates: []v1alpha1.Rate{{Requests: 100, Period: "1m"}},
				}},
			}},
		},
	}
}

func mappingObject(domain string) *v1alpha1.RateLimitMapping {
	return &v1alpha1.RateLimitMapping{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: domain},
		Spec: v1alpha1.RateLimitMappingSpec{
			Domain:   domain,
			Mappings: []v1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}},
		},
	}
}

func TestRuleSet_reusesTheEngineOfAnUnchangedDomain(t *testing.T) {
	// The snapshot is a pure function of the bundle, so an unchanged bundle must
	// keep its engine — and with it the warm token cache — while a changed one
	// must get a fresh engine compiled from the new rules.
	updater := &Updater{Counters: memory.New()}

	first := policy.Compile(policy.Input{Policies: []v1alpha1.RateLimitPolicy{
		policyWith("stable", 10), policyWith("moving", 10),
	}})
	// Both objects bind to one domain, so both live in one bundle: reuse is per
	// domain. A second domain gives the test its unchanged half.
	second := policy.Compile(policy.Input{Policies: []v1alpha1.RateLimitPolicy{
		policyWith("stable", 10), policyWith("moving", 20),
	}})

	firstSet := updater.ruleSet(first, nil)
	secondSet := updater.ruleSet(second, first.State)

	require.NotNil(t, firstSet.Engine("gateway.public"))
	assert.NotSame(t, firstSet.Engine("gateway.public"), secondSet.Engine("gateway.public"),
		"a changed bundle must produce a fresh engine")

	third := policy.Compile(policy.Input{Policies: []v1alpha1.RateLimitPolicy{
		policyWith("stable", 10), policyWith("moving", 20),
	}})
	thirdSet := updater.ruleSet(third, second.State)
	assert.Same(t, secondSet.Engine("gateway.public"), thirdSet.Engine("gateway.public"),
		"an unchanged bundle must keep its engine")
}

// policyWith is a one-rule policy whose limit is its only moving part.
func policyWith(name string, requests int32) v1alpha1.RateLimitPolicy {
	return v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "biz", Name: name, Generation: 1},
		Spec: v1alpha1.RateLimitPolicySpec{
			Domain: "gateway.public",
			Limits: []v1alpha1.LimitBlock{{Name: "b", Rules: []v1alpha1.Rule{{
				Name:  "all",
				Rates: []v1alpha1.Rate{{Requests: requests, Period: "1m"}},
			}}}},
		},
	}
}

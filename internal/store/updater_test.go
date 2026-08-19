package store

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
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

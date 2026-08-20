package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, ratelimitv1alpha1.AddToScheme(s))
	return s
}

// testNamespace is the single business namespace an installation serves.
const testNamespace = "biz"

func policy(name, domain string) *ratelimitv1alpha1.RateLimitPolicy {
	return &ratelimitv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Spec:       ratelimitv1alpha1.RateLimitPolicySpec{Domain: domain},
	}
}

func TestBuildRuleSet_groupsPoliciesByDomain(t *testing.T) {
	reader := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(
			policy("zeta", "gateway.public"),
			policy("alpha", "gateway.public"),
			policy("private", "gateway.private"),
		).
		Build()

	ruleSet, err := BuildRuleSet(context.Background(), reader, memory.New())
	require.NoError(t, err)

	// Two policies naming one domain collapse into a single entry.
	assert.True(t, ruleSet.Has("gateway.public"))
	assert.True(t, ruleSet.Has("gateway.private"))
	assert.False(t, ruleSet.Has("gateway.absent"))
	assert.NotNil(t, ruleSet.Engine("gateway.public"), "a bound domain carries a ready engine")
	assert.Equal(t, 2, ruleSet.Len())
}

func TestBuildRuleSet_noPoliciesYieldsEmptyRuleSet(t *testing.T) {
	reader := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	ruleSet, err := BuildRuleSet(context.Background(), reader, memory.New())
	require.NoError(t, err)

	assert.Equal(t, 0, ruleSet.Len())
}

func TestBuildRuleSet_skipsPolicyWithoutDomain(t *testing.T) {
	// The CRD requires a non-empty domain, so this only happens through a client
	// that bypasses validation. Grouping such an object under "" would make the
	// empty domain look configured.
	reader := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(policy("broken", "")).
		Build()

	ruleSet, err := BuildRuleSet(context.Background(), reader, memory.New())
	require.NoError(t, err)

	assert.Equal(t, 0, ruleSet.Len())
}

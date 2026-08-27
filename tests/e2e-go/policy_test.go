//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The CR contract: what the API server accepts, what the reconciler writes
// back, and what the store does when a policy comes and goes. The envtest
// suite covers the reconciler against a real API server already; what only a
// cluster shows is the other half - that the CRD installed HERE carries the
// validations, and that a policy event reaches the store in the running pod.
var _ = Describe("policy lifecycle", Ordered, Label("policy"), func() {
	const (
		policyName = "e2e-policy"
		deadRule   = "e2e-policy-dead-rule"
		domain     = "gateway.e2e"
	)

	typeMeta := func(kind string) metav1.TypeMeta {
		return metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: kind}
	}
	newPolicy := func(name string, limits []v1alpha1.LimitBlock) *v1alpha1.RateLimitPolicy {
		return &v1alpha1.RateLimitPolicy{
			TypeMeta:   typeMeta("RateLimitPolicy"),
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec:       v1alpha1.RateLimitPolicySpec{Domain: domain, Limits: limits},
		}
	}
	oneTotalRule := func(requests int32, period string) []v1alpha1.LimitBlock {
		return []v1alpha1.LimitBlock{{Name: "everything", Rules: []v1alpha1.Rule{{
			Name:  "total",
			Rates: []v1alpha1.Rate{{Requests: requests, Period: period, Algorithm: v1alpha1.AlgorithmFixedWindow}},
		}}}}
	}
	tenantRule := func() []v1alpha1.LimitBlock {
		return []v1alpha1.LimitBlock{{Name: "api", Rules: []v1alpha1.Rule{{
			Name:  "per-tenant",
			When:  []v1alpha1.Predicate{{Key: "tenant", Operator: v1alpha1.OperatorExists}},
			Rates: []v1alpha1.Rate{{Requests: 10, Period: "1m"}},
		}}}}
	}

	AfterAll(func() {
		for _, name := range []string{policyName, deadRule} {
			_ = k8s.Delete(ctx, newPolicy(name, nil))
		}
		_ = k8s.Delete(ctx, &v1alpha1.RateLimitMapping{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: domain}})
	})

	// The envtest suite covers each rule; a cluster adds the proof that the
	// CRD carrying them is the one installed here. A cluster with an older CRD
	// would accept every spec below and the operator would compile nonsense.
	DescribeTable("the installed CRD rejects",
		func(mutate func(*v1alpha1.RateLimitPolicy)) {
			p := newPolicy("e2e-policy-invalid", oneTotalRule(1, "1s"))
			mutate(p)
			err := k8s.Create(ctx, p, client.DryRunAll)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected an Invalid rejection, got: %v", err)
		},
		Entry("an empty spec.domain", func(p *v1alpha1.RateLimitPolicy) { p.Spec.Domain = "" }),
		Entry("a policy with no blocks", func(p *v1alpha1.RateLimitPolicy) { p.Spec.Limits = nil }),
		Entry("a path predicate in when", func(p *v1alpha1.RateLimitPolicy) {
			p.Spec.Limits[0].Rules[0].When = []v1alpha1.Predicate{{Key: "path", Operator: v1alpha1.OperatorExists}}
		}),
		Entry("a period above one day", func(p *v1alpha1.RateLimitPolicy) {
			p.Spec.Limits[0].Rules[0].Rates[0].Period = "2d"
		}),
		Entry("burst on a fixed window", func(p *v1alpha1.RateLimitPolicy) {
			burst := int32(5)
			p.Spec.Limits[0].Rules[0].Rates[0] = v1alpha1.Rate{
				Requests: 10, Period: "1m", Burst: &burst, Algorithm: v1alpha1.AlgorithmFixedWindow}
		}),
	)

	It("accepts a valid policy and tracks its generation", func() {
		Expect(apply(newPolicy(policyName, oneTotalRule(1, "1s")))).To(Succeed())
		Eventually(policyCondition(policyName, v1alpha1.ConditionAccepted)).Should(Equal("True"),
			"policy not accepted; is a reconciler holding the lease?")

		// observedGeneration proves the status was written for the spec that
		// exists now, not left over from an earlier generation.
		p, err := getPolicy(policyName)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ObservedGeneration).To(Equal(p.Generation))
		Eventually(policyCondition(policyName, v1alpha1.ConditionReady)).Should(Equal("True"),
			"the policy compiled but is not Ready")
	})

	It("shows the binding in the printer columns", func() {
		row := printedRow("ratelimitpolicies", policyName)
		Expect(row).To(ContainSubstring(domain), "kubectl output does not show the domain")
		Expect(row).To(ContainSubstring("True"), "kubectl output does not show the Ready status")
	})

	It("reports a rule nothing can produce a key for, and blocks its generation", func() {
		// A typo in a key has to give a rule that does nothing. The status is
		// where that becomes visible, and the mapping is what revives it.
		Expect(apply(newPolicy(deadRule, tenantRule()))).To(Succeed())

		Eventually(func() string {
			p, err := getPolicy(deadRule)
			if err != nil || len(p.Status.RuleProblems) == 0 {
				return ""
			}
			return p.Status.RuleProblems[0].Reason
		}).Should(Equal(v1alpha1.ProblemUnresolvedKeyReference))

		// Enforced as written or not at all: Ready has to say so, and nothing
		// may be active.
		Expect(policyCondition(deadRule, v1alpha1.ConditionReady)()).To(Equal("False"),
			"a blocking problem left Ready true; the generation must not be enforced")
		p, err := getPolicy(deadRule)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ActiveGeneration).To(BeZero(),
			"a policy with no valid generation enforces nothing")
	})

	It("revives that policy when a mapping declares the key", func() {
		Expect(apply(&v1alpha1.RateLimitMapping{
			TypeMeta:   typeMeta("RateLimitMapping"),
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: domain},
			Spec: v1alpha1.RateLimitMappingSpec{
				Domain: domain,
				Mappings: []v1alpha1.ClaimMapping{{
					Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}}},
			},
		})).To(Succeed())

		Eventually(func() []string {
			var m v1alpha1.RateLimitMapping
			if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: domain}, &m); err != nil {
				return nil
			}
			return m.Status.EffectiveKeys
		}).Should(ContainElement("tenant"), "the mapping did not publish tenant in status.effectiveKeys")

		Eventually(policyCondition(deadRule, v1alpha1.ConditionReady)).Should(Equal("True"),
			"the policy stayed invalid after the mapping appeared; the mapping watch is not wired")
	})

	It("keeps the last-good generation running when an edit is invalid", func() {
		// The half a unit test cannot show: the state survives in a ConfigMap,
		// so the generation being enforced outlives the edit that broke it.
		// Breaking the policy before its good generation reached the ConfigMap
		// would leave nothing to fall back to - the waits ARE the test.
		Eventually(func() error {
			return k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "ratelimit-state-" + domain},
				&corev1.ConfigMap{})
		}).Should(Succeed(), "the last-good state was never written to ratelimit-state-%s", domain)

		Eventually(generations(deadRule)).Should(WithTransform(
			func(g [2]int64) bool { return g[1] > 0 && g[0] == g[1] }, BeTrue()),
			"the policy never reached an active generation to fall back to")

		// The edit references a key nothing declares, so it must be rejected
		// while the earlier generation keeps running.
		p, err := getPolicy(deadRule)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Limits = []v1alpha1.LimitBlock{{Name: "api", Rules: []v1alpha1.Rule{{
			Name:  "per-plan",
			When:  []v1alpha1.Predicate{{Key: "plan", Operator: v1alpha1.OperatorExists}},
			Rates: []v1alpha1.Rate{{Requests: 10, Period: "1m"}},
		}}}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(generations(deadRule)).Should(WithTransform(
			func(g [2]int64) bool { return g[1] > 0 && g[0] != g[1] }, BeTrue()),
			"expected an earlier generation to stay active while the edit is rejected")
	})

	It("vetoes a mapping edit that would stop running rules", func() {
		// The gate protects policies from the mapping: dropping the key the
		// running rule depends on is refused, with the culprit named.
		var m v1alpha1.RateLimitMapping
		Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: domain}, &m)).To(Succeed())
		m.Spec.Mappings = []v1alpha1.ClaimMapping{{Key: "region", Claim: "region"}}
		Expect(k8s.Update(ctx, &m)).To(Succeed())

		Eventually(func() string {
			var current v1alpha1.RateLimitMapping
			if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: domain}, &current); err != nil {
				return ""
			}
			if len(current.Status.RejectedBy) == 0 {
				return ""
			}
			return current.Status.RejectedBy[0].Policy
		}).ShouldNot(BeEmpty(), "the mapping change was accepted even though it would stop a running rule")

		var current v1alpha1.RateLimitMapping
		Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: domain}, &current)).To(Succeed())
		ready := meta.FindStatusCondition(current.Status.Conditions, v1alpha1.ConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Reason).To(Equal(v1alpha1.ReasonRejectedByPolicies))
		Expect(current.Status.EffectiveKeys).To(ContainElement("tenant"),
			"effectiveKeys must report the active generation, which still declares tenant")
	})

	It("rebuilds the store in the running pod when a policy is deleted", func() {
		since := time.Now().Add(-time.Second)
		Expect(k8s.Delete(ctx, newPolicy(policyName, nil))).To(Succeed())
		Eventually(operatorLogsSince(since)).Should(ContainSubstring("rate limit store rebuilt"),
			"no store rebuild logged after the policy was deleted")
	})
})

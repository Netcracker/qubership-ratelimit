//go:build e2e

package e2e

import (
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The CR contract: what the API server accepts, what the reconciler writes
// back, and what the store does when a policy comes and goes. The envtest
// suite covers the reconciler against a real API server already; what only a
// cluster shows is the other half - that the CRD installed HERE carries the
// validations, and that a policy event reaches the store in the running pod.
var _ = Describe("policy lifecycle", Ordered, Label("policy"), func() {
	const domain = "gateway.e2e"

	tenantRule := func() []v1alpha1.LimitBlock {
		return []v1alpha1.LimitBlock{{Name: "api", Rules: []v1alpha1.Rule{{
			Name:    "per-tenant",
			Matches: []v1alpha1.Predicate{{Key: "tenant", Operator: v1alpha1.OperatorExists}},
			Rates:   []v1alpha1.Rate{{Requests: 10, PeriodSeconds: 60}},
		}}}}
	}

	AfterAll(func() { deletePolicies(domain) })

	// The envtest suite covers each rule; a cluster adds the proof that the
	// CRD carrying them is the one installed here. A cluster with an older CRD
	// would accept every spec below and the operator would compile nonsense.
	DescribeTable("the installed CRD rejects",
		func(mutate func(*v1alpha1.RateLimitPolicy)) {
			p := newPolicy(domain, totalLimits(1, 1))
			mutate(p)
			err := k8s.Create(ctx, p, client.DryRunAll)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected an Invalid rejection, got: %v", err)
		},
		Entry("a name that is not the domain", func(p *v1alpha1.RateLimitPolicy) {
			p.Name = "something-else"
		}),
		Entry("a policy with no blocks", func(p *v1alpha1.RateLimitPolicy) { p.Spec.Limits = nil }),
		Entry("a period above one day", func(p *v1alpha1.RateLimitPolicy) {
			p.Spec.Limits[0].Rules[0].Rates[0].PeriodSeconds = 86401
		}),
		Entry("two windows of one period", func(p *v1alpha1.RateLimitPolicy) {
			p.Spec.Limits[0].Rules[0].Rates = []v1alpha1.Rate{
				{Requests: 10, PeriodSeconds: 60},
				{Requests: 20, PeriodSeconds: 60},
			}
		}),
	)

	It("accepts a valid policy and tracks its generation", func() {
		Expect(apply(newPolicy(domain, totalLimits(1, 1)))).To(Succeed())
		Eventually(policyCondition(domain, v1alpha1.ConditionAccepted)).Should(Equal("True"),
			"policy not accepted; is a reconciler holding the lease?")

		// observedGeneration proves the status was written for the spec that
		// exists now, not left over from an earlier generation.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ObservedGeneration).To(Equal(p.Generation))
		Expect(p.Status.ActiveGeneration).To(Equal(p.Generation))
		Expect(p.Status.EffectiveKeys).To(ContainElement("client"),
			"the status must publish the key set the rules resolve against")
	})

	// The one property no unit test can show: a leader in a real cluster
	// reaching /debug/applied on the other pods. Everything below reads the
	// status that probe writes.
	It("reports every ready replica enforcing the generation", func() {
		Eventually(policyCondition(domain, v1alpha1.ConditionReady)).Should(Equal("True"),
			"Ready never went true; can the leader reach /debug/applied on the other replicas?")
		Expect(policyCondition(domain, v1alpha1.ConditionStalled)()).To(Equal("False"),
			"a fleet that agrees is not stalled")

		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.Replicas.Total).To(BeNumerically(">", 0),
			"the leader saw no ready endpoint of its own Service")
		Expect(p.Status.Replicas.Applied).To(Equal(p.Status.Replicas.Total),
			"Ready is true while %d of %d replicas enforce the generation",
			p.Status.Replicas.Applied, p.Status.Replicas.Total)
		Expect(p.Status.Replicas.LastCheckTime).NotTo(BeNil(),
			"the status carries no probe time, so nothing says the leader is alive")
	})

	It("shows the fleet in the printer columns", func() {
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())

		// JSONPath cannot join the two into "3/3", so the fraction is two
		// columns and the row has to carry both numbers along with Ready.
		row := printedRow("ratelimitpolicies", domain)
		Expect(row).To(ContainSubstring("True"), "the row does not show the Ready condition")
		Expect(row).To(ContainSubstring(strconv.Itoa(int(p.Status.Replicas.Applied))),
			"the row does not show how many replicas enforce the generation")
		Expect(row).To(ContainSubstring(strconv.Itoa(int(p.Status.Replicas.Total))),
			"the row does not show the ready replica count")
	})

	It("reports a rule nothing can produce a key for, and blocks its generation", func() {
		// A typo in a key has to give a rule that does nothing. The status is
		// where that becomes visible, and the mapping in the same object is
		// what revives it.
		Expect(apply(newPolicy(domain, tenantRule()))).To(Succeed())

		Eventually(func() string {
			p, err := getPolicy(domain)
			if err != nil || len(p.Status.RuleProblems) == 0 {
				return ""
			}
			return p.Status.RuleProblems[0].Reason
		}).Should(Equal(v1alpha1.ProblemUnresolvedKeyReference))

		// Enforced as written or not at all: the conditions have to say so, and
		// the generation must not be the active one.
		Expect(policyCondition(domain, v1alpha1.ConditionAccepted)()).To(Equal("False"),
			"a blocking problem left Accepted true")
		Expect(policyCondition(domain, v1alpha1.ConditionReady)()).To(Equal("False"),
			"a blocking problem left Ready true; the generation must not be enforced")
		Expect(policyCondition(domain, v1alpha1.ConditionStalled)()).To(Equal("True"),
			"a generation that does not compile is stuck, not merely in progress")

		// The base asserted activeGeneration == 0 here, which a separate
		// never-valid object made true. One policy per domain means this is an
		// edit to an object that already has a good generation, so the honest
		// assertion is that the broken one is not the enforced one.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ObservedGeneration).To(Equal(p.Generation))
		Expect(p.Status.ActiveGeneration).NotTo(Equal(p.Status.ObservedGeneration),
			"a generation with a blocking problem was enforced")
	})

	It("revives that rule when the same object declares the key", func() {
		// Extraction and rules live in one object, so this is one edit and one
		// generation: a request never sees new rules over old extraction.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Mappings = []v1alpha1.ClaimMapping{{
			Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(policyCondition(domain, v1alpha1.ConditionAccepted)).Should(Equal("True"),
			"the generation stayed invalid after its own mapping declared the key")
		Eventually(func() []string {
			current, err := getPolicy(domain)
			if err != nil {
				return nil
			}
			return current.Status.EffectiveKeys
		}).Should(ContainElement("tenant"), "the status did not publish tenant in effectiveKeys")
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

		Eventually(generations(domain)).Should(WithTransform(
			func(g [2]int64) bool { return g[1] > 0 && g[0] == g[1] }, BeTrue()),
			"the policy never reached an active generation to fall back to")

		// The edit references a key nothing declares, so it must be refused
		// while the earlier generation keeps running.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Limits = []v1alpha1.LimitBlock{{Name: "api", Rules: []v1alpha1.Rule{{
			Name:    "per-plan",
			Matches: []v1alpha1.Predicate{{Key: "plan", Operator: v1alpha1.OperatorExists}},
			Rates:   []v1alpha1.Rate{{Requests: 10, PeriodSeconds: 60}},
		}}}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(generations(domain)).Should(WithTransform(
			func(g [2]int64) bool { return g[1] > 0 && g[0] != g[1] }, BeTrue()),
			"expected an earlier generation to stay active while the edit is refused")

		// Enforcing an earlier generation is not being ready, and it is a
		// breakage rather than a rollout: last-good converges on nothing.
		Expect(policyCondition(domain, v1alpha1.ConditionReady)()).To(Equal("False"),
			"a policy running last-good reported itself ready")
		Expect(policyCondition(domain, v1alpha1.ConditionStalled)()).To(Equal("True"),
			"a generation that does not compile is stuck, not in progress")
	})

	It("rebuilds the store in the running pod when a policy is deleted", func() {
		since := time.Now().Add(-time.Second)
		Expect(k8s.Delete(ctx, newPolicy(domain, nil))).To(Succeed())
		Eventually(operatorLogsSince(since)).Should(ContainSubstring("rate limit store rebuilt"),
			"no store rebuild logged after the policy was deleted")
	})
})

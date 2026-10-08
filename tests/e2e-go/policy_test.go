//go:build e2e

package e2e

import (
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// The CR contract: what the API server accepts, what the reconciler writes
// back, and what the store does when a policy comes and goes. The envtest
// suite covers the reconciler against a real API server already; what only a
// cluster shows is the other half - that the CRD installed HERE carries the
// validations, and that a policy event reaches the store in the running pod.
var _ = Describe("policy lifecycle", Ordered, Label("policy"), func() {
	const domain = "gateway.e2e"

	tenantRule := func() []v1.LimitBlock {
		return []v1.LimitBlock{{Name: "api", Rules: []v1.Rule{{
			Name:    "per-tenant",
			Matches: []v1.Predicate{{Key: "tenant", Operator: v1.OperatorExists}},
			Rates:   []v1.Rate{{Requests: 10, PeriodSeconds: 60}},
		}}}}
	}

	AfterAll(func() { deletePolicies(domain) })

	// The envtest suite covers each rule; a cluster adds the proof that the
	// CRD carrying them is the one installed here. A cluster with an older CRD
	// would accept every spec below and the operator would compile nonsense.
	DescribeTable("the installed CRD rejects",
		func(mutate func(*v1.RateLimitPolicy)) {
			p := newPolicy(domain, totalLimits(1, 1))
			mutate(p)
			Expect(k8s.Create(ctx, p, client.DryRunAll)).To(Satisfy(apierrors.IsInvalid),
				"a dry-run Create of the policy, which has to be refused as Invalid")
		},
		Entry("a name that is not the domain", func(p *v1.RateLimitPolicy) {
			p.Name = "something-else"
		}),
		Entry("a policy with no blocks", func(p *v1.RateLimitPolicy) { p.Spec.Limits = nil }),
		Entry("a period above one day", func(p *v1.RateLimitPolicy) {
			p.Spec.Limits[0].Rules[0].Rates[0].PeriodSeconds = 86401
		}),
		Entry("two windows of one period", func(p *v1.RateLimitPolicy) {
			p.Spec.Limits[0].Rules[0].Rates = []v1.Rate{
				{Requests: 10, PeriodSeconds: 60},
				{Requests: 20, PeriodSeconds: 60},
			}
		}),
	)

	It("accepts a valid policy and tracks its generation", func() {
		Expect(apply(newPolicy(domain, totalLimits(1, 1)))).To(Succeed())
		Eventually(policyCondition(domain, v1.ConditionAccepted)).Should(Equal("True"),
			"policy not accepted; is the operator running?")

		// observedGeneration proves the status was written for the spec that
		// exists now, not left over from an earlier generation, and the status
		// publishes the key set the rules resolve against.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"ObservedGeneration": Equal(p.Generation),
			"ActiveGeneration":   Equal(p.Generation),
			"EffectiveKeys":      ContainElement("sub"),
		}), "the status of generation %d", p.Generation)
	})

	// The one property no unit test can show: the operator in a real cluster
	// reaching /debug/applied on the service pods through the Service.
	// Everything below reads the status that probe writes.
	It("reports every ready replica enforcing the generation", func() {
		Eventually(policyCondition(domain, v1.ConditionReady)).Should(Equal("True"),
			"Ready never went true; can the operator reach /debug/applied on the service replicas?")
		Expect(policyCondition(domain, v1.ConditionStalled)()).To(Equal("False"),
			"a fleet that agrees is not stalled")

		// Total counts the ready endpoints of the Service the operator saw,
		// Applied the ones enforcing the generation, and the probe time says
		// the operator is alive.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.Replicas).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"Total":         BeNumerically(">", 0),
			"Applied":       Equal(p.Status.Replicas.Total),
			"LastCheckTime": Not(BeNil()),
		}), "the replicas of a Ready policy")
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
		}).Should(Equal(v1.ProblemUnresolvedKeyReference),
			"the reason of the first rule problem of a rule over the undeclared key tenant")

		// Enforced as written or not at all: the conditions have to say so, and
		// the generation must not be the active one.
		Expect(policyCondition(domain, v1.ConditionAccepted)()).To(Equal("False"),
			"a blocking problem left Accepted true")
		Expect(policyCondition(domain, v1.ConditionReady)()).To(Equal("False"),
			"a blocking problem left Ready true; the generation must not be enforced")
		Expect(policyCondition(domain, v1.ConditionStalled)()).To(Equal("True"),
			"a generation that does not compile is stuck, not merely in progress")

		// One policy per domain makes this an edit to an object that already
		// has a good generation, so the active generation is that earlier one
		// rather than zero: what has to hold is that the broken generation is
		// not the enforced one.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"ObservedGeneration": Equal(p.Generation),
			"ActiveGeneration":   Not(Equal(p.Generation)),
		}), "a generation with a blocking problem was enforced; the status of generation %d", p.Generation)
	})

	It("revives a rule over an undeclared key once the same object maps the key", func() {
		// Extraction and rules live in one object, so this is one edit and one
		// generation: a request never sees new rules over old extraction.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Mappings = []v1.ClaimMapping{{
			Key: "tenant", Claim: "org_id", Fallbacks: []string{"sub"}}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(policyCondition(domain, v1.ConditionAccepted)).Should(Equal("True"),
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
		// The half a unit test cannot show: the last-good state is the
		// ConfigMap the service mounts, so the generation being enforced
		// outlives the edit that broke it. Breaking the policy before its
		// good generation reached the ConfigMap would leave nothing to fall
		// back to; the waits ARE the test.
		Eventually(generations(domain)).Should(Satisfy(
			func(g [2]int64) bool { return g[1] > 0 && g[0] == g[1] }),
			"the policy never reached an active generation to fall back to; (observed, active)")
		Eventually(manifestGeneration(domain)).Should(Equal(generations(domain)()[1]),
			"the last-good generation was never written to %s", contract.ConfigMapName)

		// The edit references a key nothing declares, so it must be refused
		// while the earlier generation keeps running.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Limits = []v1.LimitBlock{{Name: "api", Rules: []v1.Rule{{
			Name:    "per-plan",
			Matches: []v1.Predicate{{Key: "plan", Operator: v1.OperatorExists}},
			Rates:   []v1.Rate{{Requests: 10, PeriodSeconds: 60}},
		}}}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(generations(domain)).Should(Satisfy(
			func(g [2]int64) bool { return g[1] > 0 && g[0] != g[1] }),
			"expected an earlier generation to stay active while the edit is refused; (observed, active)")
		Expect(manifestGeneration(domain)()).To(Equal(generations(domain)()[1]),
			"the ConfigMap carries a generation other than the active one")

		// Enforcing an earlier generation is not being ready, and it is a
		// breakage rather than a rollout: last-good converges on nothing.
		Expect(policyCondition(domain, v1.ConditionReady)()).To(Equal("False"),
			"a policy running last-good reported itself ready")
		Expect(policyCondition(domain, v1.ConditionStalled)()).To(Equal("True"),
			"a generation that does not compile is stuck, not in progress")
	})

	It("drops the domain from every running pod when a policy is deleted", func() {
		Expect(k8s.Delete(ctx, newPolicy(domain, nil))).To(Succeed())
		Eventually(func() []string {
			return replicasReporting(domain, func(d applied.Domain, ok bool) bool { return ok })
		}).WithTimeout(propagationTimeout).WithPolling(2*time.Second).Should(BeEmpty(),
			"replicas that still report %s after the policy was deleted", domain)
	})
})

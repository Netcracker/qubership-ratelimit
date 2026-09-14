//go:build e2e

package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The decision budget: a generation whose worst-case request would collect
// more buckets than one decision may carry does not compile, and the last-good
// generation keeps serving in its place. The alternative would be a generation
// whose widest paths the runtime backstop refuses outright, which is a limit
// nobody asked for. Pure status mechanics: the domain needs no gateway, so this
// suite sends no traffic.
var _ = Describe("the decision budget", Ordered, Label("budget"), func() {
	const domain = "gateway.e2e-budget"

	// rules builds n unconditional rules of four windows each, so the
	// worst-case decision is 4n buckets.
	rules := func(n int) []v1alpha1.LimitBlock {
		out := make([]v1alpha1.Rule, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, v1alpha1.Rule{
				Name: fmt.Sprintf("r%02d", i),
				Rates: []v1alpha1.Rate{
					{Requests: 100, PeriodSeconds: 10, Algorithm: v1alpha1.AlgorithmFixedWindow},
					{Requests: 100, PeriodSeconds: 60, Algorithm: v1alpha1.AlgorithmFixedWindow},
					{Requests: 100, PeriodSeconds: 3600, Algorithm: v1alpha1.AlgorithmFixedWindow},
					{Requests: 100, PeriodSeconds: 86400, Algorithm: v1alpha1.AlgorithmFixedWindow},
				},
			})
		}
		return []v1alpha1.LimitBlock{{Name: "heavy", Rules: out}}
	}

	AfterAll(func() { deletePolicies(domain) })

	It("accepts a generation at the budget", func() {
		// 32 rules of 4 windows is exactly 128, the budget itself.
		Expect(apply(newPolicy(domain, rules(32)))).To(Succeed())

		Eventually(policyCondition(domain, v1alpha1.ConditionAccepted)).Should(Equal("True"),
			"a generation at the budget must compile")
	})

	It("refuses a generation over it and keeps the last good one", func() {
		Expect(apply(newPolicy(domain, rules(33)))).To(Succeed())

		Eventually(func() string {
			p, err := getPolicy(domain)
			if err != nil {
				return ""
			}
			c := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionAccepted)
			if c == nil || c.Status != "False" {
				return ""
			}
			return c.Reason
		}).Should(Equal(v1alpha1.ReasonCompilationFailed),
			"a generation over the budget must not compile")

		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ActiveGeneration).NotTo(BeZero(),
			"the last-good generation keeps serving: a bad edit costs an answer, not the limits")
		Expect(p.Status.ActiveGeneration).To(BeNumerically("<", p.Status.ObservedGeneration),
			"the two generations must diverge while the latest one is refused")

		Expect(p.Status.RuleProblems).NotTo(BeEmpty())
		Expect(p.Status.RuleProblems[0].Reason).To(Equal(v1alpha1.ProblemDomainBudgetExceeded))

		Eventually(policyCondition(domain, v1alpha1.ConditionStalled)).Should(Equal("True"),
			"a generation stuck on last-good is what Stalled is for")
	})

	It("takes the generation back once it fits again", func() {
		Expect(apply(newPolicy(domain, rules(16)))).To(Succeed())

		Eventually(policyCondition(domain, v1alpha1.ConditionAccepted)).Should(Equal("True"))
		Eventually(policyCondition(domain, v1alpha1.ConditionStalled)).Should(Equal("False"),
			"a generation that compiles again is no longer stuck")

		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ActiveGeneration).To(Equal(p.Status.ObservedGeneration))
	})
})

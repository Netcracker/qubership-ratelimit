//go:build e2e

package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
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
	rules := func(n int) []v1.LimitBlock {
		out := make([]v1.Rule, 0, n)
		for i := range n {
			out = append(out, v1.Rule{
				Name: fmt.Sprintf("r%02d", i),
				Rates: []v1.Rate{
					{Requests: 100, PeriodSeconds: 10, Algorithm: v1.AlgorithmFixedWindow},
					{Requests: 100, PeriodSeconds: 60, Algorithm: v1.AlgorithmFixedWindow},
					{Requests: 100, PeriodSeconds: 3600, Algorithm: v1.AlgorithmFixedWindow},
					{Requests: 100, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow},
				},
			})
		}
		return []v1.LimitBlock{{Name: "heavy", Rules: out}}
	}

	AfterAll(func() { deletePolicies(domain) })

	It("accepts a generation at the budget", func() {
		// 32 rules of 4 windows is exactly 128, the budget itself.
		Expect(apply(newPolicy(domain, rules(32)))).To(Succeed())

		Eventually(policyCondition(domain, v1.ConditionAccepted)).Should(Equal("True"),
			"a generation at the budget must compile")
	})

	It("refuses a generation over it and keeps the last good one", func() {
		Expect(apply(newPolicy(domain, rules(33)))).To(Succeed())

		Eventually(conditionOf(domain, v1.ConditionAccepted)).Should(
			gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"Status": Equal(metav1.ConditionFalse),
				"Reason": Equal(v1.ReasonCompilationFailed),
			}), "a generation over the budget must not compile")

		// The last-good generation keeps serving behind the refused latest one,
		// so the two generations diverge: a bad edit costs an answer, not the
		// limits. The first rule problem names the budget.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"ActiveGeneration": And(Not(BeZero()), BeNumerically("<", p.Status.ObservedGeneration)),
			"RuleProblems": gstruct.MatchElementsWithIndex(gstruct.IndexIdentity, gstruct.IgnoreExtras, gstruct.Elements{
				"0": gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
					"Reason": Equal(v1.ProblemDomainBudgetExceeded),
				}),
			}),
		}), "the status of the refused generation %d", p.Status.ObservedGeneration)

		Eventually(policyCondition(domain, v1.ConditionStalled)).Should(Equal("True"),
			"a generation stuck on last-good is what Stalled is for")
	})

	It("takes the generation back once it fits again", func() {
		Expect(apply(newPolicy(domain, rules(16)))).To(Succeed())

		Eventually(policyCondition(domain, v1.ConditionAccepted)).Should(Equal("True"),
			"a generation back within the budget must compile")
		Eventually(policyCondition(domain, v1.ConditionStalled)).Should(Equal("False"),
			"a generation that compiles again is no longer stuck")

		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ActiveGeneration).To(Equal(p.Status.ObservedGeneration),
			"the generation that fits again is not the active one")
	})
})

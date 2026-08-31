//go:build e2e

package e2e

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The domain budget gate: a policy set whose worst-case decision would
// collect more buckets than the runtime backstop admits is turned away at
// admission, with the engine as the judge. Seats are not re-litigated - the
// policies already running keep running - and a freed seat goes to the
// rejected policy without anyone touching it. Pure status mechanics: the
// domain needs no gateway, so this suite sends no traffic.
var _ = Describe("the domain budget gate", Ordered, Label("budget"), func() {
	const domain = "gateway.e2e-budget"
	names := []string{"e2e-budget-a", "e2e-budget-b", "e2e-budget-c"}

	// One block of 15 unconditional rules with 4 windows each: 60 buckets per
	// decision, safely inside the per-policy cap of 64 - only the domain
	// total of 128 can turn the third policy away.
	heavyLimits := func() []v1alpha1.LimitBlock {
		rules := make([]v1alpha1.Rule, 0, 15)
		for i := 0; i < 15; i++ {
			rules = append(rules, v1alpha1.Rule{
				Name: fmt.Sprintf("r%02d", i),
				Rates: []v1alpha1.Rate{
					{Requests: 100, Period: "10s", Algorithm: v1alpha1.AlgorithmFixedWindow},
					{Requests: 100, Period: "1m", Algorithm: v1alpha1.AlgorithmFixedWindow},
					{Requests: 100, Period: "1h", Algorithm: v1alpha1.AlgorithmFixedWindow},
					{Requests: 100, Period: "1d", Algorithm: v1alpha1.AlgorithmFixedWindow},
				},
			})
		}
		return []v1alpha1.LimitBlock{{Name: "heavy", Rules: rules}}
	}

	AfterAll(func() { deletePolicies(names...) })

	It("seats what fits and rejects what would not", func() {
		Expect(apply(newPolicy(names[0], domain, heavyLimits()))).To(Succeed())
		Expect(apply(newPolicy(names[1], domain, heavyLimits()))).To(Succeed())
		for _, name := range names[:2] {
			Eventually(policyCondition(name, v1alpha1.ConditionReady)).Should(Equal("True"),
				"%s fits the domain and must be ready", name)
		}

		// 60 + 60 + 60 breaches the domain's 128; the third policy is valid
		// on its own merits, so only the domain gate can be the reason.
		Expect(apply(newPolicy(names[2], domain, heavyLimits()))).To(Succeed())
		Eventually(func() string {
			p, err := getPolicy(names[2])
			if err != nil {
				return ""
			}
			c := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionReady)
			if c == nil || c.Status != "False" {
				return ""
			}
			return c.Reason
		}).Should(Equal(v1alpha1.ReasonRejectedByDomainBudget),
			"the third policy was not rejected by the domain gate")

		p, err := getPolicy(names[2])
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ActiveGeneration).To(BeZero(),
			"a policy the gate turned away enforces nothing")

		// The seats are not re-litigated: admitting a rejected newcomer by
		// evicting a running policy would turn every apply into a lottery.
		for _, name := range names[:2] {
			Expect(policyCondition(name, v1alpha1.ConditionReady)()).To(Equal("True"),
				"%s lost its seat to a rejected newcomer", name)
		}
	})

	It("gives a freed seat to the rejected policy", func() {
		// Idempotent on purpose: a flake retry of this spec re-enters after
		// the first attempt already deleted the policy.
		if err := k8s.Delete(ctx, newPolicy(names[0], domain, nil)); err != nil {
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "deleting %s: %v", names[0], err)
		}

		// The deletion event fans out to the domain's peers, so the freed
		// seat reaches the rejected policy's status with no further touch.
		Eventually(policyCondition(names[2], v1alpha1.ConditionReady)).Should(Equal("True"),
			"the rejected policy did not take the freed seat")
	})
})

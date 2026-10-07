//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// The operator writes a preset into every rule that takes it, so a gateway
// sees the resolved rule under the rule's own name. The unit suites pin the
// merge; what only a cluster shows is the counters of the resolved rules
// surviving an edit of the preset, the last-good generation holding while a
// reference does not resolve, and a stored behavior keeping the preset's out
// until the field is removed from the object.
var _ = Describe("rule presets", Ordered, Label("presets"), func() {
	const (
		domain      = "gateway.public"
		ordersPath  = "/e2e-presets/orders"
		catalogPath = "/e2e-presets/catalog"

		// Two per day and FixedWindow: the counts carry across every spec
		// of the suite, and a fixed window resets on its calendar boundary,
		// so the window is the longest the schema admits.
		limit = 2
	)
	var applied bool

	// policy is the policy of the suite: one preset, taken by one rule of
	// each of two blocks with targets of their own. requests is the window
	// of the preset and behavior its behavior; an empty behavior leaves the
	// preset's out.
	policy := func(requests int32, behavior v1.RuleBehavior) *v1.RateLimitPolicy {
		block := func(name, prefix string) v1.LimitBlock {
			return v1.LimitBlock{
				Name: name,
				Target: &v1.Target{Routes: []v1.Route{{
					Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: prefix},
				}}},
				Rules: []v1.Rule{{Name: "budget", Preset: "standard"}},
			}
		}
		p := newPolicy(domain, []v1.LimitBlock{block("orders", ordersPath), block("catalog", catalogPath)})
		p.Spec.Presets = &v1.Presets{Rules: []v1.Rule{{
			Name:     "standard",
			Behavior: behavior,
			Rates: []v1.Rate{{
				Requests: requests, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow,
			}},
		}}}
		return p
	}

	BeforeAll(func() {
		if applied {
			return
		}
		applied = true

		// Warmed before the policy exists, so the warm-up probes spend
		// nothing of the day-long budgets.
		waitGatewayServes("public-gateway", ordersPath)
		waitGatewayServes("public-gateway", catalogPath)
		Expect(apply(policy(limit, ""))).To(Succeed())
		waitApplied(domain)
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
	})

	It("limits every block that takes the preset, each in a bucket of its own", func() {
		for _, path := range []string{ordersPath, catalogPath} {
			codes := gatewayBurst("public-gateway", path, limit+1, nil)
			for i, code := range codes[:limit] {
				Expect(code).NotTo(Equal(429), "request %d of %s within the preset's budget was refused", i+1, path)
			}
			Expect(codes[limit]).To(Equal(429),
				"the request of %s over the preset's budget was admitted; the resolved rule is not enforced", path)
		}
	})

	It("keeps the counters of the resolved rules across an edit of the preset's window", func() {
		// The window grows from two to four. The counter key carries the
		// block, the rule, the algorithm, and the period, none of which the
		// edit touches, so the two requests each bucket already holds stay
		// counted: two more are admitted, and the third is refused. A reset
		// would admit all three.
		Expect(apply(policy(limit+2, ""))).To(Succeed())
		waitApplied(domain)

		for _, path := range []string{ordersPath, catalogPath} {
			codes := gatewayBurst("public-gateway", path, 3, nil)
			Expect(codes[:2]).NotTo(ContainElement(429),
				"the widened window of %s did not admit the two requests it gained: %v", path, codes)
			Expect(codes[2]).To(Equal(429),
				"the third request of %s was admitted; the edit of the preset reset the bucket", path)
		}
	})

	It("reports a preset nothing declares at the rule that names it and keeps the last-good generation", func() {
		before, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())

		broken := policy(limit+2, "")
		broken.Spec.Limits[1].Rules[0].Preset = "standrad"
		Expect(apply(broken)).To(Succeed())

		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(p.Status.ObservedGeneration).To(Equal(p.Generation), "the operator has not observed the edit")
			g.Expect(p.Status.RuleProblems).To(HaveLen(1))
			g.Expect(p.Status.RuleProblems[0].Reason).To(Equal(v1.ProblemUnresolvedPresetReference))
			g.Expect(p.Status.RuleProblems[0].Block).To(Equal("catalog"))
			g.Expect(p.Status.RuleProblems[0].Rule).To(Equal("budget"))
			g.Expect(p.Status.RuleProblems[0].Message).To(ContainSubstring("standrad"))
			g.Expect(p.Status.ActiveGeneration).To(Equal(before.Generation),
				"the generation enforced is not the last good one")
		}).WithTimeout(time.Minute).WithPolling(time.Second).Should(Succeed())
		Expect(policyCondition(domain, v1.ConditionAccepted)()).To(Equal("False"))

		// The last-good generation holds the orders bucket at its four: a
		// domain left unprotected would admit this request.
		Expect(gatewayGet("public-gateway", ordersPath, nil)).To(Equal(429),
			"the orders budget of the last-good generation is not enforced")
	})

	// An object stored before the schema stopped writing defaults carries
	// behavior: Enforce on every rule that left it out, and a written field
	// wins over the preset's. The orders rule stands for such an object; the
	// catalog rule takes the preset as is.
	It("keeps a written behavior over the preset's until the field is removed", func() {
		shadowed := policy(limit+2, v1.RuleBehaviorShadow)
		shadowed.Spec.Limits[0].Rules[0].Behavior = v1.RuleBehaviorEnforce
		Expect(apply(shadowed)).To(Succeed())
		waitApplied(domain)

		Expect(gatewayGet("public-gateway", ordersPath, nil)).To(Equal(429),
			"the written Enforce of the orders rule did not win over the Shadow preset")
		Expect(gatewayGet("public-gateway", catalogPath, nil)).NotTo(Equal(429),
			"the catalog rule took Shadow from the preset and still refused")
		Eventually(func() float64 {
			return counterSum(scrapeAllReplicas(), "ratelimit_decisions_total",
				map[string]string{"domain": domain, "outcome": "shadow_over_limit", "rule": "catalog/budget"})
		}).WithTimeout(30*time.Second).Should(BeNumerically(">", 0),
			"the Shadow rule of catalog recorded no shadow_over_limit outcome")

		By("removing the written behavior with the JSON patch of the runbook")
		patch := client.RawPatch(types.JSONPatchType,
			[]byte(`[{"op": "remove", "path": "/spec/limits/0/rules/0/behavior"}]`))
		Expect(k8s.Patch(ctx, newPolicy(domain, nil), patch)).To(Succeed())
		waitApplied(domain)

		Expect(gatewayGet("public-gateway", ordersPath, nil)).NotTo(Equal(429),
			"the orders rule still refuses after its written behavior was removed; the preset's Shadow did not apply")
		Eventually(func() float64 {
			return counterSum(scrapeAllReplicas(), "ratelimit_decisions_total",
				map[string]string{"domain": domain, "outcome": "shadow_over_limit", "rule": "orders/budget"})
		}).WithTimeout(30*time.Second).Should(BeNumerically(">", 0),
			"the orders rule recorded no shadow_over_limit outcome after taking Shadow from the preset")
	})
})

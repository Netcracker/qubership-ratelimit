//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// A shadow rule is how a tighter limit is tried out over live traffic: it
// counts, it reports what it would have refused, and it never refuses. The
// unit suites prove the verdict math; only a gateway shows that real traffic
// keeps flowing while the dry run records its refusals.
var _ = Describe("shadow rules", Ordered, Label("shadow"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e"

		// The counter identity is block/rule: the policy is the singleton of
		// its domain, so its name adds nothing a bucket key needs.
		rule = "probe/dry-run"
	)
	var applied bool

	BeforeAll(func() {
		if !applied {
			applied = true

			waitGatewayServes("public-gateway", probePath)
			limits := prefixLimits(probePath, "dry-run", nil, 1, 3600)
			limits[0].Rules[0].Behavior = v1.RuleBehaviorShadow
			Expect(apply(newPolicy(domain, limits))).To(Succeed())
			waitApplied(domain)
		}
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
	})

	It("records refusals without refusing", func() {
		Expect(gatewayBurst("public-gateway", probePath, 4, nil)).To(HaveEach(beAdmitted()),
			"a burst over the shadow limit of 1; a shadow rule must never refuse")

		Eventually(func() float64 {
			return counterSum(scrapeAllReplicas(), "ratelimit_decisions_total",
				map[string]string{"domain": domain, "outcome": "shadow_over_limit", "rule": rule})
		}).WithTimeout(30*time.Second).Should(BeNumerically(">", 0),
			"the dry run left no shadow_over_limit outcome for %s", rule)
	})
})

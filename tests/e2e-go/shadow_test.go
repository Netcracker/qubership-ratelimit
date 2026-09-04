//go:build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// A shadow rule is how a tighter limit is tried out over live traffic: it
// counts, it reports what it would have refused, and it never refuses. The
// unit suites prove the verdict math; only a gateway shows that real traffic
// keeps flowing while the dry run records its refusals.
var _ = Describe("shadow rules", Ordered, Label("shadow"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e"
	)
	var policyName string

	BeforeAll(func() {
		if policyName == "" {
			policyName = fmt.Sprintf("e2e-shadow-%d", time.Now().Unix())

			waitGatewayServes("public-gateway", probePath)
			limits := prefixLimits(probePath, "dry-run", nil, 1, 3600)
			limits[0].Rules[0].Behavior = v1alpha1.RuleBehaviorShadow
			before := storeRebuilds()
			Expect(apply(newPolicy(domain, limits))).To(Succeed())
			waitStoreRebuilt(before)
		}
	})
	AfterAll(func() {
		if policyName != "" {
			deletePolicies(domain)
		}
	})

	It("records refusals without refusing", func() {
		codes := gatewayBurst("public-gateway", probePath, 4, nil)
		for i, code := range codes {
			Expect((code >= 200 && code < 300) || code == 404).To(BeTrue(),
				"request %d was not admitted (got %d); a shadow rule must never refuse", i+1, code)
		}

		rule := policyName + "/probe/dry-run"
		Eventually(func() bool {
			families := scrapeAllReplicas()
			return counterSum(families, "ratelimit_decisions_total",
				map[string]string{"domain": domain, "outcome": "shadow_over_limit", "rule": rule}) > 0
		}).WithTimeout(30*time.Second).Should(BeTrue(),
			"the dry run left no shadow_over_limit outcome for %s", rule)
	})
})

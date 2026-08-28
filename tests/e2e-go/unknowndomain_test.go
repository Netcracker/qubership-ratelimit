//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// A domain the filter sends and no policy claims: the filter config and the
// custom resources have drifted apart, and the traffic passes unlimited -
// counted, logged by name, but never refused. The private gateway plays the
// unclaimed domain: only the ratelimit suite ever claims gateway.private,
// and it cleans up after itself, so between containers the domain is free.
var _ = Describe("an unknown domain", Ordered, Label("unknown-domain"), func() {
	const (
		domain    = "gateway.private"
		probePath = "/e2e-ratelimit"
	)

	BeforeAll(func() {
		// Sequential containers make the window; this check makes it a
		// diagnosis instead of a silent false green when that ever changes.
		var policies v1alpha1.RateLimitPolicyList
		Expect(k8s.List(ctx, &policies, client.InNamespace(namespace))).To(Succeed())
		for _, p := range policies.Items {
			Expect(p.Spec.Domain).NotTo(Equal(domain),
				"%s claims %s; this suite needs the domain unclaimed", p.Name, domain)
		}
		waitGatewayServes("private-gateway", probePath)
	})

	It("passes the traffic, counted and named", func() {
		before := scrapeAllReplicas()
		since := time.Now()

		codes := gatewayBurst("private-gateway", probePath, 3, nil)
		for i, code := range codes {
			Expect((code >= 200 && code < 300) || code == 404).To(BeTrue(),
				"request %d was not admitted (got %d); unknown-domain traffic passes unlimited", i+1, code)
		}

		Eventually(func() float64 {
			after := scrapeAllReplicas()
			return counterSum(after, "ratelimit_unknown_domain_checks_total", nil) -
				counterSum(before, "ratelimit_unknown_domain_checks_total", nil)
		}).WithTimeout(30*time.Second).Should(BeNumerically(">=", 3),
			"the unknown-domain counter did not grow with the burst")

		// The metric hides the name on purpose; the log carries it.
		Eventually(operatorLogsSince(since)).Should(SatisfyAll(
			ContainSubstring("unknown rate limit domain"),
			ContainSubstring("domain="+domain),
		), "the operator did not log the unknown domain by name")
	})
})

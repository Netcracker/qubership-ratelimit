//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	dto "github.com/prometheus/client_model/go"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// Identity extraction end to end: a bearer token travels through the gateway
// as a descriptor, the mapping turns its claim into a key, and the key
// becomes the axis of a per-client bucket. No other suite sends a token
// through a claim mapping, so this is the only proof the whole path is wired -
// including the extraction metrics the dead-claim-path detector stands on.
var _ = Describe("identity extraction through the gateway", Ordered, Label("jwt"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e"
		limit     = 2
	)
	var (
		applied bool

		// tokensBefore is the scrape taken before the first token of the
		// per-client spec: the extraction series grow from it.
		tokensBefore map[string]*dto.MetricFamily
	)

	BeforeAll(func() {
		// The fixture half runs once even across flake retries: the budget
		// is an hour long, and a retry that reapplied the policy would
		// re-count from empty buckets.
		if applied {
			return
		}
		applied = true

		// Warm-up probes carry no token, so the tenant rule cannot match
		// them and the per-client budgets stay untouched - the order of
		// warm-up and apply does not matter here.
		waitGatewayServes("public-gateway", probePath)

		limits := prefixLimits(probePath, "per-tenant", []string{"tenant"}, limit, 3600)
		limits[0].Rules[0].Matches = []v1.Predicate{{
			Key: "tenant", Operator: v1.OperatorExists}}

		// The claim mapping travels in the same object as the rules that
		// reference it: one edit, one generation, applied atomically.
		policy := newPolicy(domain, limits)
		policy.Spec.Mappings = []v1.ClaimMapping{{Key: "tenant", Claim: "org_id"}}

		Expect(apply(policy)).To(Succeed())
		waitApplied(domain)
	})
	AfterAll(func() { deletePolicies(domain) })

	It("counts each client in its own bucket", func() {
		tokensBefore = scrapeAllReplicas()

		clientA := map[string]string{"Authorization": "Bearer " + unsignedToken(map[string]string{"org_id": "acme-a"})}
		codes := gatewayBurst("public-gateway", probePath, limit+1, clientA)
		Expect(codes[:limit]).NotTo(ContainElement(429), "client A's requests within its budget of %d", limit)
		Expect(codes[limit]).To(Equal(429),
			"client A's request over the budget was admitted; the per-tenant bucket is not keyed")

		// A different claim value is a different bucket: client B must be
		// admitted while client A stands refused.
		clientB := map[string]string{"Authorization": "Bearer " + unsignedToken(map[string]string{"org_id": "acme-b"})}
		Expect(gatewayGet("public-gateway", probePath, clientB)).NotTo(Equal(429),
			"client B was refused out of client A's bucket")
	})

	It("grows the domain's extraction series with every token sent", func() {
		// The detector's two halves moved, both on this domain: tokens
		// arrived, and the declared key extracted values for them. Both are
		// read with the domain label, which is what keeps one domain's
		// traffic from answering for another domain's declared keys. The
		// per-client spec sent limit+1 tokens of client A and one of client B.
		sent := float64(limit + 2)
		extractions := map[string]string{"domain": domain, "key": "tenant"}
		tokens := map[string]string{"domain": domain}
		Eventually(func(g Gomega) {
			after := scrapeAllReplicas()
			g.Expect(counterSum(after, "ratelimit_extractions_total", extractions)-
				counterSum(tokensBefore, "ratelimit_extractions_total", extractions)).To(BeNumerically(">=", sent),
				`growth of ratelimit_extractions_total{domain=%q,key="tenant"}`, domain)
			g.Expect(counterSum(after, "ratelimit_tokens_seen_total", tokens)-
				counterSum(tokensBefore, "ratelimit_tokens_seen_total", tokens)).To(BeNumerically(">=", sent),
				"growth of ratelimit_tokens_seen_total{domain=%q}", domain)
		}).WithTimeout(30*time.Second).Should(Succeed(),
			"the extraction series of %s did not grow with the tokens", domain)
	})
})

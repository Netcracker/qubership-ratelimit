//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	dto "github.com/prometheus/client_model/go"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Identity extraction end to end: a bearer token travels through the gateway
// as a descriptor, the mapping turns its claim into a key, and the key
// becomes the axis of a per-client bucket. No other suite sends a single
// token, so this is the only proof the whole path is wired - including the
// extraction metrics the dead-claim-path detector stands on.
var _ = Describe("identity extraction through the gateway", Ordered, Label("jwt"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e"
		limit     = 2
	)
	var applied bool

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
		limits[0].Rules[0].Matches = []v1alpha1.Predicate{{
			Key: "tenant", Operator: v1alpha1.OperatorExists}}

		// The claim mapping travels in the same object as the rules that
		// reference it: one edit, one generation, applied atomically.
		policy := newPolicy(domain, limits)
		policy.Spec.Mappings = []v1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}}

		before := storeRebuilds()
		Expect(apply(policy)).To(Succeed())
		waitStoreRebuilt(before)
	})
	AfterAll(func() { deletePolicies(domain) })

	It("counts each client in its own bucket", func() {
		beforeFamilies := scrapeAllReplicas()

		clientA := map[string]string{"Authorization": "Bearer " + unsignedJWT("acme-a")}
		codes := gatewayBurst("public-gateway", probePath, limit+1, clientA)
		for i, code := range codes[:limit] {
			Expect(code).NotTo(Equal(429), "request %d of client A's budget was refused", i+1)
		}
		Expect(codes[limit]).To(Equal(429),
			"client A's request over the budget was admitted; the per-tenant bucket is not keyed")

		// A different claim value is a different bucket: client B must be
		// admitted while client A stands refused.
		clientB := map[string]string{"Authorization": "Bearer " + unsignedJWT("acme-b")}
		Expect(gatewayGet("public-gateway", probePath, clientB)).NotTo(Equal(429),
			"client B was refused out of client A's bucket")

		// The detector's two halves moved: tokens arrived, and the declared
		// key extracted values for them.
		sent := float64(limit + 2)
		Eventually(func() bool {
			after := scrapeAllReplicas()
			return counterSum(after, "ratelimit_extractions_total", map[string]string{"key": "tenant"})-
				counterSum(beforeFamilies, "ratelimit_extractions_total", map[string]string{"key": "tenant"}) >= sent &&
				counterSum(after, "ratelimit_tokens_seen_total", nil)-
					counterSum(beforeFamilies, "ratelimit_tokens_seen_total", nil) >= sent
		}).WithTimeout(30*time.Second).Should(BeTrue(),
			"the extraction series did not grow with the tokens")
	})
})

// unsignedJWT builds an alg-none token with one org_id claim. The engine
// decodes the payload and never verifies - the gateway owns signatures - so
// an empty signature segment is a valid fixture.
func unsignedJWT(orgID string) string {
	seg := func(v map[string]string) string {
		raw, err := json.Marshal(v)
		Expect(err).NotTo(HaveOccurred())
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := seg(map[string]string{"alg": "none", "typ": "JWT"})
	payload := seg(map[string]string{"org_id": orgID})
	return header + "." + payload + "."
}

// counterSum adds up every series of the family that carries the given
// labels - counters arrive per replica, and the union is what a burst
// touched.
func counterSum(families map[string]*dto.MetricFamily, name string, labels map[string]string) float64 {
	family := families[name]
	if family == nil {
		return 0
	}
	total := 0.0
	for _, m := range family.Metric {
		carried := map[string]string{}
		for _, pair := range m.Label {
			carried[pair.GetName()] = pair.GetValue()
		}
		matches := true
		for k, v := range labels {
			if carried[k] != v {
				matches = false
				break
			}
		}
		if matches {
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

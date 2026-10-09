//go:build e2e

package e2e

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// A route that reads the cost of a request from a query parameter is the one
// part of matching that looks at the query string, and the query string
// reaches the service only inside the path entry the gateway sends. The unit
// suites prove the reading and the arithmetic; only a gateway shows that the
// page size of a real request is what the window charges.
var _ = Describe("the cost a route reads from the query string", Ordered, Label("cost"), func() {
	const (
		domain = "gateway.public"
		prefix = "/e2e-cost"
	)

	BeforeAll(func() {
		// Warmed before the policy exists, so the probes charge nothing.
		waitGatewayServes("public-gateway", prefix)
		Expect(apply(newPolicy(domain, costLimits(prefix)))).To(Succeed())
		waitApplied(domain)
	})
	AfterAll(func() { deletePolicies(domain) })

	// One request through the public gateway, with its status and the rate
	// limit headers it was answered with.
	get := func(path string) (int, map[string]string) {
		codes, answered := gatewayBurstWithHeaders("public-gateway", path, 1, nil)
		return codes[0], rateLimitHeaders(answered[0])
	}

	It("charges a page its limit and refuses the page that no longer fits", func() {
		code, headers := get(prefix + "/pages?limit=60")
		Expect(code).To(beAdmitted(), "the first page of 60 items out of 100")
		Expect(headers).To(gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{
			"x-ratelimit-limit":     Equal("100"),
			"x-ratelimit-remaining": Equal("40"),
			"ratelimit-policy":      Equal(`"items/per-path";q=100;w=3600`),
		}), "the headers of the first page of 60 items")

		code, headers = get(prefix + "/pages?limit=60")
		Expect(code).To(Equal(429), "a second page of 60 items with 40 left")
		Expect(headers).To(HaveKeyWithValue("retry-after", Not(BeEmpty())),
			"a refusal that waiting cures carries a retry hint")

		code, _ = get(prefix + "/pages?limit=40")
		Expect(code).To(beAdmitted(), "a page of the 40 items left")
	})

	It("charges the default of 20 for a request without a usable limit", func() {
		code, headers := get(prefix + "/default")
		Expect(code).To(beAdmitted(), "a request without limit")
		Expect(headers).To(HaveKeyWithValue("x-ratelimit-remaining", "80"),
			"the remaining items after a request without limit")

		code, headers = get(prefix + "/default?limit=abc")
		Expect(code).To(beAdmitted(), "a request with limit=abc")
		Expect(headers).To(HaveKeyWithValue("x-ratelimit-remaining", "60"),
			"the remaining items after a request with limit=abc")
	})

	It("refuses a limit above the window without a retry hint and charges nothing for it", func() {
		code, headers := get(prefix + "/huge?limit=101")
		Expect(code).To(Equal(429), "a page of 101 items against a window of 100")
		Expect(headers).To(HaveKeyWithValue("retry-after", BeEmpty()),
			"no waiting cures a cost above the capacity of the window")

		code, _ = get(prefix + "/huge?limit=100")
		Expect(code).To(beAdmitted(), "a page of 100 items after the refused one")
	})

	It("counts requests in a block whose route reads no cost", func() {
		codes, answered := gatewayBurstWithHeaders("public-gateway", prefix+"/calls?limit=1", 11, nil)

		Expect(codes[:10]).To(HaveEach(beAdmitted()), "ten pages of one item under ten calls an hour")
		Expect(codes[10]).To(Equal(429), "the eleventh call of the hour")
		Expect(rateLimitHeaders(answered[10])).To(
			HaveKeyWithValue("ratelimit-policy", `"calls/per-path";q=10;w=3600`),
			"the headers of the eleventh call name the window of calls")
	})
})

// costLimits counts the requests under prefix twice, per path and under GCRA,
// so that no calendar boundary falls inside a spec: the block items reads the
// cost from limit, 20 when a request carries none, and holds 100 items an
// hour; the block calls reads no cost and holds 10 requests an hour.
func costLimits(prefix string) []v1.LimitBlock {
	defaultCost := int32(20)
	route := v1.Route{Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: prefix}}
	costRoute := route
	costRoute.Cost = &v1.RouteCost{Source: v1.CostSourceQueryParameter, Name: "limit", Default: &defaultCost}
	block := func(name string, route v1.Route, requests int32) v1.LimitBlock {
		return v1.LimitBlock{
			Name:   name,
			Target: &v1.Target{Routes: []v1.Route{route}},
			Rules: []v1.Rule{{
				Name:     "per-path",
				Counters: []string{"path"},
				Rates:    []v1.Rate{{Requests: requests, PeriodSeconds: 3600, Algorithm: v1.AlgorithmGCRA}},
			}},
		}
	}
	return []v1.LimitBlock{block("items", costRoute, 100), block("calls", route, 10)}
}

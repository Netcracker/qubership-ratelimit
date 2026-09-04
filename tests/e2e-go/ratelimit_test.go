//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The thing the operator exists for: a gateway calls it on every request and
// honours the verdict. Everything here needs a real gateway, a real Envoy, and
// the operator's own gRPC endpoint at once - which is why none of it can be a
// unit test.
var _ = Describe("rate limiting through the gateways", Ordered, Label("ratelimit"), func() {
	const (
		publicDomain  = "gateway.public"
		privateDomain = "gateway.private"
		// The backend status is irrelevant - what matters is 429 versus
		// not-429 - so the probe path only has to reach a routing verdict.
		probePath = "/e2e-ratelimit"
	)

	BeforeAll(func() {
		before := storeRebuilds()
		Expect(apply(newPolicy(publicDomain, totalLimits(1, 1)))).To(Succeed())
		Expect(apply(newPolicy(privateDomain, totalLimits(1, 1)))).To(Succeed())
		waitStoreRebuilt(before)
		// Both gateways are warmed: a cold gateway answers 503 on its own,
		// and the not-429 assertions below would take that for an admission.
		waitGatewayServes("public-gateway", probePath)
		waitGatewayServes("private-gateway", probePath)
	})
	// deletePolicies takes domains: a policy is named after the domain it
	// serves, so passing anything else deletes nothing and leaks the claim
	// into the suites that need the domain unclaimed.
	AfterAll(func() { deletePolicies(publicDomain, privateDomain) })

	It("is what the gateway is configured to call", func() {
		// A wrong cluster name fails exactly like an unreachable operator, so
		// assert the configuration rather than inferring it from behaviour.
		expected := fmt.Sprintf("outbound|9000||%s.%s.svc.cluster.local", operatorDeployment(), namespace)
		Eventually(func() string {
			return rateLimitClusterOf(gatewayPod("public-gateway").Name)
		}).WithTimeout(time.Minute).WithPolling(5 * time.Second).Should(Equal(expected))
	})

	It("receives the four descriptor entries", func() {
		// The descriptor the gateway sends is the operator's input contract.
		keys := descriptorKeysOf(gatewayPod("public-gateway").Name)
		Expect(keys).To(ContainElements("path", "method", "token", "request_id"),
			"a descriptor entry is missing from the gateway config")
	})

	It("refuses a burst over the declared limit", func() {
		// One per second for the whole domain: a burst must produce a refusal,
		// and the first request must not be one - a 429 there would mean a
		// window carried over from an earlier test.
		nextWindow()
		codes := gatewayBurst("public-gateway", probePath, 4, nil)
		Expect(codes[0]).NotTo(Equal(429),
			"the first request of a burst was refused; the window did not reset between tests")
		Expect(codes).To(ContainElement(429),
			"no request in the burst was refused; the declared limit is not being enforced")
		Expect(codes).NotTo(ContainElements(0, 503),
			"a request did not reach a routing verdict: %v", codes)
	})

	It("admits traffic again once the window reopens", func() {
		nextWindow()
		Expect(gatewayGet("public-gateway", probePath, nil)).NotTo(Equal(429),
			"still refused after the window should have reopened")
	})

	It("limits each gateway on its own", func() {
		// The counting axis carries the domain, so exhausting the public
		// gateway must not refuse the private one. The answer has to be an
		// admission, not merely not-429: a 503 would mean the probe never
		// reached a rate limit verdict at all.
		nextWindow()
		gatewayBurst("public-gateway", probePath, 3, nil)
		code := gatewayGet("private-gateway", probePath, nil)
		Expect((code >= 200 && code < 300) || code == 404).To(BeTrue(),
			"the private gateway did not admit while only the public one was exhausted (got %d)", code)
	})

	It("logs each check without ever logging the token", func() {
		// The per-check line is Debug; the e2e install runs with
		// logLevel=debug precisely so this contract stays observable.
		since := time.Now()
		secret := "e2e-secret-token-should-never-be-logged"
		requestID := fmt.Sprintf("e2e-correlation-%d", time.Now().Unix())
		nextWindow()
		gatewayBurst("public-gateway", probePath, 1, map[string]string{"X-Request-Id": requestID})
		gatewayGet("public-gateway", probePath, map[string]string{"Authorization": "Bearer " + secret})

		Eventually(func() string {
			var checks []string
			for _, line := range strings.Split(operatorLogsSince(since)(), "\n") {
				if strings.Contains(line, "rate limit check") {
					checks = append(checks, line)
				}
			}
			return strings.Join(checks, "\n")
		}).WithTimeout(30*time.Second).Should(SatisfyAll(
			ContainSubstring("domain="+publicDomain),
			ContainSubstring("path="+probePath),
			ContainSubstring("[request_id="+requestID+"]"),
		), "the operator did not log the check with its domain, path and request id")

		// The token is a credential and must never reach a log line, in any form.
		Expect(operatorLogsSince(since)()).NotTo(ContainSubstring(secret),
			"the Authorization value was written to the log")
	})

	// The unknown-domain path is deliberately not tested here: proving it
	// means removing every policy that claims gateway.public, which in a
	// shared namespace would disrupt whatever else uses the gateway.
	// internal/rls covers it.
})

// rateLimitClusterOf digs the ratelimit filter's cluster name out of the
// Envoy config dump - the jq of the bash suite, spelled in Go.
func rateLimitClusterOf(pod string) string {
	dump, err := configDump(pod)
	if err != nil {
		return ""
	}
	for _, cfg := range dump {
		if !strings.Contains(str(cfg, "@type"), "ListenersConfigDump") {
			continue
		}
		for _, dl := range list(cfg, "dynamic_listeners") {
			listener, _ := walk(dl, "active_state", "listener").(map[string]any)
			for _, fc := range list(listener, "filter_chains") {
				for _, f := range list(fc, "filters") {
					if str(f, "name") != "envoy.filters.network.http_connection_manager" {
						continue
					}
					for _, hf := range list(walk(f, "typed_config"), "http_filters") {
						if str(hf, "name") != "envoy.filters.http.ratelimit" {
							continue
						}
						if name := str(walk(hf, "typed_config", "rate_limit_service",
							"grpc_service", "envoy_grpc"), "cluster_name"); name != "" {
							return name
						}
					}
				}
			}
		}
	}
	return ""
}

// descriptorKeysOf collects the descriptor keys of every rate_limits action in
// the gateway's route config.
func descriptorKeysOf(pod string) []string {
	dump, err := configDump(pod)
	Expect(err).NotTo(HaveOccurred())
	seen := map[string]struct{}{}
	for _, cfg := range dump {
		if !strings.Contains(str(cfg, "@type"), "RoutesConfigDump") {
			continue
		}
		for _, rc := range list(cfg, "dynamic_route_configs") {
			for _, vh := range list(walk(rc, "route_config"), "virtual_hosts") {
				for _, rl := range list(vh, "rate_limits") {
					for _, action := range list(rl, "actions") {
						if key := str(walk(action, "request_headers"), "descriptor_key"); key != "" {
							seen[key] = struct{}{}
						}
					}
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	return keys
}

func configDump(pod string) ([]map[string]any, error) {
	out, err := execPod(pod, "istio-proxy", "pilot-agent", "request", "GET", "config_dump")
	if err != nil {
		return nil, err
	}
	var dump struct {
		Configs []map[string]any `json:"configs"`
	}
	if err := json.Unmarshal([]byte(out), &dump); err != nil {
		return nil, err
	}
	return dump.Configs, nil
}

// walk, list and str are the smallest JSON-path kit the config dump needs.
func walk(node any, path ...string) any {
	for _, key := range path {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = m[key]
	}
	return node
}

func list(node any, key string) []any {
	items, _ := walk(node, key).([]any)
	return items
}

func str(node any, key string) string {
	s, _ := walk(node, key).(string)
	return s
}

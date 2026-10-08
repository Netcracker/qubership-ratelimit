//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
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
		p.Spec.Presets = &v1.Presets{Rules: []v1.RulePreset{{
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

// A block preset is a cascade written once and stamped on blocks with
// targets of their own. The unit suites pin the merge and the equality of the
// resolved policy with one written out; what a cluster adds is the enforced
// set the replicas build from each form being one and the same, and the
// cascade behaving on real traffic: as declared, with a rule overridden by
// name, and with a rule inserted and one dropped.
var _ = Describe("block presets", Ordered, Label("presets"), func() {
	const (
		domain      = "gateway.public"
		ordersPath  = "/e2e-presets/cascade/orders"
		catalogPath = "/e2e-presets/cascade/catalog"
		exportsPath = "/e2e-presets/cascade/exports"
		basePath    = "/ratelimit/v1"
		route       = "e2e-presets-management"

		// Per day and FixedWindow, as the rule presets suite: the counts
		// carry across the specs.
		perUser = 2
	)
	var (
		applied bool
		port    int32

		// What the written-out policy compiled to, read before the preset
		// form replaces it.
		writtenRules   int32
		writtenVersion string
	)

	dayWindow := func(requests int32) []v1.Rate {
		return []v1.Rate{{Requests: requests, PeriodSeconds: 86400, Algorithm: v1.AlgorithmFixedWindow}}
	}
	prefix := func(path string) *v1.Target {
		return &v1.Target{Routes: []v1.Route{{Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: path}}}}
	}
	internal := v1.Rule{Name: "internal", Behavior: v1.RuleBehaviorBypass,
		Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorEquals, Value: "prometheus"}}}
	perUserRule := v1.Rule{Name: "per-user", Counters: []string{"sub"}, Rates: dayWindow(perUser)}
	anonymous := v1.Rule{Name: "anonymous", Rates: dayWindow(perUser),
		Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorDoesNotExist}}}
	partner := v1.Rule{Name: "partner", Counters: []string{"sub"}, Rates: dayWindow(1),
		Matches: []v1.Predicate{{Key: "sub", Operator: v1.OperatorInGroup, Value: "partners"}}}
	withPolicy := func(blocks []v1.LimitBlock) *v1.RateLimitPolicy {
		p := newPolicy(domain, blocks)
		p.Spec.Groups = []v1.Group{{Name: "partners", Values: []string{"partner-a"}}}
		return p
	}

	// presetForm is the policy of the suite as the resource specification
	// writes it: one cascade, three blocks taking it.
	presetForm := func() *v1.RateLimitPolicy {
		partnerBefore := partner
		partnerBefore.Before = "per-user"
		p := withPolicy([]v1.LimitBlock{
			{Name: "orders", Preset: "cascade", Target: prefix(ordersPath)},
			{Name: "catalog", Preset: "cascade", Target: prefix(catalogPath),
				Rules: []v1.Rule{{Name: "per-user", Rates: dayWindow(perUser + 2)}}},
			{Name: "exports", Preset: "cascade", Target: prefix(exportsPath),
				Rules: []v1.Rule{partnerBefore, {Name: "anonymous", Dropped: true}}},
		})
		p.Spec.Presets = &v1.Presets{
			Rules: []v1.RulePreset{
				{Name: "internal-bypass", Behavior: internal.Behavior, Matches: internal.Matches},
				{Name: "standard", Counters: perUserRule.Counters, Rates: perUserRule.Rates},
			},
			Blocks: []v1.BlockPreset{{Name: "cascade", Mode: v1.BlockModeFirstMatch, Rules: []v1.Rule{
				{Name: "internal", Preset: "internal-bypass"},
				{Name: "per-user", Preset: "standard"},
				anonymous,
			}}},
		}
		return p
	}

	// writtenOut is the same policy with every block written in full.
	writtenOut := func() *v1.RateLimitPolicy {
		perUserCatalog := perUserRule
		perUserCatalog.Rates = dayWindow(perUser + 2)
		return withPolicy([]v1.LimitBlock{
			{Name: "orders", Mode: v1.BlockModeFirstMatch, Target: prefix(ordersPath),
				Rules: []v1.Rule{internal, perUserRule, anonymous}},
			{Name: "catalog", Mode: v1.BlockModeFirstMatch, Target: prefix(catalogPath),
				Rules: []v1.Rule{internal, perUserCatalog, anonymous}},
			{Name: "exports", Mode: v1.BlockModeFirstMatch, Target: prefix(exportsPath),
				Rules: []v1.Rule{internal, partner, perUserRule}},
		})
	}

	// enforcedSet reads what the replicas enforce for the domain: the rule
	// count of the status, and the ruleSetVersion of the management API
	// where the release renders the management port, the empty string
	// otherwise.
	enforcedSet := func() (int32, string) {
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		if port == 0 {
			return p.Status.Rules, ""
		}
		var version string
		Eventually(func() string {
			body, code := gatewayGetBody("private-gateway", basePath+"/domains",
				map[string]string{"Authorization": "Bearer " + managementToken("e2e@example.com", "viewer")})
			if code != http.StatusOK {
				return ""
			}
			version = listedRuleSetVersion(body, domain)
			return version
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).ShouldNot(BeEmpty(),
			"the private gateway never served a listing with %s through %s", domain, basePath)
		return p.Status.Rules, version
	}

	BeforeAll(func() {
		if applied {
			return
		}
		applied = true

		for _, path := range []string{ordersPath, catalogPath, exportsPath} {
			waitGatewayServes("public-gateway", path)
		}
		port = managementPort()
		if port != 0 {
			Expect(apply(managementRoute(route, basePath, port))).To(Succeed())
		}

		Expect(apply(writtenOut())).To(Succeed())
		waitApplied(domain)
		writtenRules, writtenVersion = enforcedSet()

		Expect(apply(presetForm())).To(Succeed())
		waitApplied(domain)
	})
	AfterAll(func() {
		if port != 0 {
			_ = k8s.Delete(ctx, managementRoute(route, basePath, port))
		}
		if applied {
			deletePolicies(domain)
		}
	})

	It("compiles to the rule set of the same policy written out", func() {
		// The written-out form is the last-good generation, so a refused
		// preset form would leave the same set enforced: the generation
		// has to be the preset form's own before the two are compared.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Status.ActiveGeneration).To(Equal(p.Generation),
			"the preset form is not the enforced generation; the operator refused it: %v", p.Status.RuleProblems)
		Expect(policyCondition(domain, v1.ConditionAccepted)()).To(Equal("True"))

		rules, version := enforcedSet()
		Expect(rules).To(Equal(writtenRules), "the RULES count differs from the written-out policy's")
		if port == 0 {
			Skip("the release runs without management.enabled; the ruleSetVersion cannot be compared")
		}
		Expect(version).To(Equal(writtenVersion),
			"the replicas enforce a rule set other than the written-out policy's; a preset reached the engine")
	})

	It("enforces the cascade as declared", func() {
		for i, code := range gatewayBurst("public-gateway", ordersPath, 3, bearer(subjectJWT("prometheus"))) {
			Expect(code).NotTo(Equal(429), "request %d of the internal caller was refused; the Bypass rule did not apply", i+1)
		}
		codes := gatewayBurst("public-gateway", ordersPath, perUser+1, bearer(subjectJWT("alice")))
		Expect(codes[:perUser]).NotTo(ContainElement(429), "alice's budget on orders was refused early: %v", codes)
		Expect(codes[perUser]).To(Equal(429), "alice's request over the per-user budget of orders was admitted")
		codes = gatewayBurst("public-gateway", ordersPath, perUser+1, nil)
		Expect(codes[:perUser]).NotTo(ContainElement(429), "the anonymous budget on orders was refused early: %v", codes)
		Expect(codes[perUser]).To(Equal(429), "the anonymous request over the budget of orders was admitted")
	})

	It("applies the window overridden by name", func() {
		codes := gatewayBurst("public-gateway", catalogPath, perUser+3, bearer(subjectJWT("alice")))
		Expect(codes[:perUser+2]).NotTo(ContainElement(429),
			"alice's widened budget on catalog was refused early; the override did not apply: %v", codes)
		Expect(codes[perUser+2]).To(Equal(429), "alice's request over the widened budget of catalog was admitted")
	})

	It("applies the rule inserted in front of per-user and leaves the dropped one out", func() {
		codes := gatewayBurst("public-gateway", exportsPath, 2, bearer(subjectJWT("partner-a")))
		Expect(codes[0]).NotTo(Equal(429), "the partner's first request on exports was refused")
		Expect(codes[1]).To(Equal(429),
			"the partner's second request on exports was admitted; the partner rule is not in front of per-user")
		for i, code := range gatewayBurst("public-gateway", exportsPath, perUser+1, nil) {
			Expect(code).NotTo(Equal(429),
				"anonymous request %d on exports was refused; the dropped anonymous rule still applies", i+1)
		}
	})
})

// subjectJWT builds an alg-none token with one sub claim, which the built-in
// sub key reads lowercased. The engine decodes the payload and never
// verifies, so an empty signature segment is a valid fixture.
func subjectJWT(sub string) string {
	seg := func(v map[string]string) string {
		raw, err := json.Marshal(v)
		Expect(err).NotTo(HaveOccurred())
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return seg(map[string]string{"alg": "none", "typ": "JWT"}) + "." + seg(map[string]string{"sub": sub}) + "."
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// listedRuleSetVersion reads the ruleSetVersion of one domain out of a
// listing body, the empty string when the listing does not carry it.
func listedRuleSetVersion(body, domain string) string {
	var listing struct {
		Items []struct {
			Domain         string `json:"domain"`
			RuleSetVersion string `json:"ruleSetVersion"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &listing); err != nil {
		return ""
	}
	for _, item := range listing.Items {
		if item.Domain == domain {
			return item.RuleSetVersion
		}
	}
	return ""
}

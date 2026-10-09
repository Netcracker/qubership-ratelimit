//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

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
	var (
		applied bool

		// The block names carry the run's suffix, for the reason on runSuffix;
		// a retry of one spec inside a run keeps the buckets, since the specs
		// share them on purpose.
		ordersBlock  = "orders-" + runSuffix
		catalogBlock = "catalog-" + runSuffix
	)

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
		p := newPolicy(domain, []v1.LimitBlock{block(ordersBlock, ordersPath), block(catalogBlock, catalogPath)})
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
		// The orders burst spends its bucket before the catalog burst starts,
		// so the catalog burst is admitted only from a bucket of its own.
		bursts := map[string][]int{}
		for _, path := range []string{ordersPath, catalogPath} {
			bursts[path] = gatewayBurst("public-gateway", path, limit+1, nil)
		}
		Expect(bursts).To(gstruct.MatchAllKeys(gstruct.Keys{
			ordersPath:  HaveExactElements(beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests)),
			catalogPath: HaveExactElements(beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests)),
		}), "the codes of a burst of %d requests through public-gateway, by path", limit+1)
	})

	It("keeps the counters of the resolved rules across an edit of the preset's window", func() {
		// The window grows from two to four. The counter key carries the
		// block, the rule, the algorithm, and the period, none of which the
		// edit touches, so the two requests each bucket already holds stay
		// counted: two more are admitted, and the third is refused. A reset
		// would admit all three.
		Expect(apply(policy(limit+2, ""))).To(Succeed())
		waitApplied(domain)

		bursts := map[string][]int{}
		for _, path := range []string{ordersPath, catalogPath} {
			bursts[path] = gatewayBurst("public-gateway", path, 3, nil)
		}
		Expect(bursts).To(gstruct.MatchAllKeys(gstruct.Keys{
			ordersPath:  HaveExactElements(beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests)),
			catalogPath: HaveExactElements(beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests)),
		}), "the codes of a burst of 3 requests through public-gateway once the window is four, by path")
	})

	It("reports a preset nothing declares at the rule that names it and keeps the last-good generation", func() {
		before, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred(), "getPolicy(%s) before the edit", domain)

		broken := policy(limit+2, "")
		broken.Spec.Limits[1].Rules[0].Preset = "standrad"
		Expect(apply(broken)).To(Succeed())

		// The problem names the preset in its message, and the block and the
		// rule of the point of use in its fields.
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(p.Status.ObservedGeneration).To(Equal(p.Generation), "the operator has not observed the edit")
			g.Expect(p.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"RuleProblems": HaveExactElements(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
					"Block":   Equal(catalogBlock),
					"Rule":    Equal("budget"),
					"Reason":  Equal(v1.ProblemUnresolvedPresetReference),
					"Message": ContainSubstring("standrad"),
				})),
				"ActiveGeneration": Equal(before.Generation),
			}))
		}).WithTimeout(time.Minute).WithPolling(time.Second).Should(Succeed(),
			"the status of %s to report the unresolved preset and keep generation %d active",
			domain, before.Generation)
		Expect(policyCondition(domain, v1.ConditionAccepted)()).To(Equal("False"),
			"the Accepted condition of %s", domain)

		// The last-good generation holds the orders bucket at its four: a
		// domain left unprotected would admit this request.
		Expect(gatewayGet("public-gateway", ordersPath, nil)).To(Equal(http.StatusTooManyRequests),
			"the code of a request on %s through public-gateway", ordersPath)
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

		orders := gatewayGet("public-gateway", ordersPath, nil)
		catalog := gatewayGet("public-gateway", catalogPath, nil)
		Expect(map[string]int{ordersPath: orders, catalogPath: catalog}).To(gstruct.MatchAllKeys(gstruct.Keys{
			// The orders rule writes Enforce over the preset's Shadow.
			ordersPath: Equal(http.StatusTooManyRequests),
			// The catalog rule takes Shadow from the preset.
			catalogPath: beAdmitted(),
		}), "the code of a request through public-gateway, by path")
		Eventually(func() float64 {
			return counterSum(scrapeAllReplicas(), "ratelimit_decisions_total",
				map[string]string{"domain": domain, "outcome": "shadow_over_limit", "rule": catalogBlock + "/budget"})
		}).WithTimeout(30*time.Second).Should(BeNumerically(">", 0),
			"the shadow_over_limit decisions of rule %s/budget across the replicas", catalogBlock)

		By("removing the written behavior with the JSON patch of the runbook")
		patch := client.RawPatch(types.JSONPatchType,
			[]byte(`[{"op": "test", "path": "/spec/limits/0/rules/0/name", "value": "budget"},
			        {"op": "remove", "path": "/spec/limits/0/rules/0/behavior"}]`))
		Expect(k8s.Patch(ctx, newPolicy(domain, nil), patch)).To(Succeed())
		waitApplied(domain)

		Expect(gatewayGet("public-gateway", ordersPath, nil)).To(beAdmitted(),
			"the code of a request on %s through public-gateway once its rule writes no behavior", ordersPath)
		Eventually(func() float64 {
			return counterSum(scrapeAllReplicas(), "ratelimit_decisions_total",
				map[string]string{"domain": domain, "outcome": "shadow_over_limit", "rule": ordersBlock + "/budget"})
		}).WithTimeout(30*time.Second).Should(BeNumerically(">", 0),
			"the shadow_over_limit decisions of rule %s/budget across the replicas", ordersBlock)
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
		// form replaces it, and what the preset form compiled to.
		writtenRules   int32
		writtenVersion string
		presetRules    int32
		presetVersion  string

		// The block names carry the run's suffix, for the reason on runSuffix,
		// in both forms of the policy, so the two compile to one rule set.
		ordersBlock  = "orders-" + runSuffix
		catalogBlock = "catalog-" + runSuffix
		exportsBlock = "exports-" + runSuffix
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
			{Name: ordersBlock, Preset: "cascade", Target: prefix(ordersPath)},
			{Name: catalogBlock, Preset: "cascade", Target: prefix(catalogPath),
				Rules: []v1.Rule{{Name: "per-user", Rates: dayWindow(perUser + 2)}}},
			{Name: exportsBlock, Preset: "cascade", Target: prefix(exportsPath),
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
			{Name: ordersBlock, Mode: v1.BlockModeFirstMatch, Target: prefix(ordersPath),
				Rules: []v1.Rule{internal, perUserRule, anonymous}},
			{Name: catalogBlock, Mode: v1.BlockModeFirstMatch, Target: prefix(catalogPath),
				Rules: []v1.Rule{internal, perUserCatalog, anonymous}},
			{Name: exportsBlock, Mode: v1.BlockModeFirstMatch, Target: prefix(exportsPath),
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
				map[string]string{"Authorization": "Bearer " + managementToken()})
			if code != http.StatusOK {
				return ""
			}
			version = listedRuleSetVersion(body, domain)
			return version
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).ShouldNot(BeEmpty(),
			"the ruleSetVersion of %s in the listing private-gateway serves at %s/domains", domain, basePath)
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

	It("enforces as many rules as the same policy written out", func() {
		// The written-out form is the last-good generation, so a refused
		// preset form would leave the same set enforced: the generation
		// has to be the preset form's own before the two are compared.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred(), "getPolicy(%s)", domain)
		Expect(p.Status.ActiveGeneration).To(Equal(p.Generation),
			"the active generation of %s; its rule problems: %v", domain, p.Status.RuleProblems)
		Expect(policyCondition(domain, v1.ConditionAccepted)()).To(Equal("True"),
			"the Accepted condition of %s", domain)

		presetRules, presetVersion = enforcedSet()
		Expect(presetRules).To(Equal(writtenRules), "the RULES count of %s", domain)
	})

	// The ruleSetVersion identifies the rule set the replicas enforce for a
	// domain and changes with any block, rule, route, or window of it, so an
	// equal version is the set of the policy written out.
	It("enforces the rule set of the same policy written out", func() {
		if port == 0 {
			Skip("the release runs without management.enabled; the ruleSetVersion cannot be compared")
		}
		Expect(presetVersion).NotTo(BeEmpty(),
			"the ruleSetVersion the spec \"enforces as many rules as the same policy written out\" reads")
		Expect(presetVersion).To(Equal(writtenVersion), "the ruleSetVersion of %s in the management API", domain)
	})

	It("enforces the cascade as declared", func() {
		bursts := map[string][]int{}
		bursts["prometheus"] = gatewayBurst("public-gateway", ordersPath, 3, bearerFor("prometheus"))
		bursts["alice"] = gatewayBurst("public-gateway", ordersPath, perUser+1, bearerFor("alice"))
		bursts["anonymous"] = gatewayBurst("public-gateway", ordersPath, perUser+1, nil)
		Expect(bursts).To(gstruct.MatchAllKeys(gstruct.Keys{
			// The internal rule bypasses the rest of the cascade.
			"prometheus": HaveEach(beAdmitted()),
			// The per-user rule counts by sub.
			"alice": HaveExactElements(beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests)),
			// The anonymous rule counts the requests without sub.
			"anonymous": HaveExactElements(beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests)),
		}), "the codes of a burst on %s through public-gateway, by caller", ordersPath)
	})

	It("applies the window overridden by name", func() {
		codes := gatewayBurst("public-gateway", catalogPath, perUser+3, bearerFor("alice"))
		Expect(codes).To(HaveExactElements(
			beAdmitted(), beAdmitted(), beAdmitted(), beAdmitted(), Equal(http.StatusTooManyRequests),
		), "the codes of a burst of %d requests on %s for alice", perUser+3, catalogPath)
	})

	It("applies the rule inserted in front of per-user", func() {
		// The partner rule admits one request a day and per-user two, so the
		// second request is refused where the partner rule decides first.
		codes := gatewayBurst("public-gateway", exportsPath, 2, bearerFor("partner-a"))
		Expect(codes).To(HaveExactElements(beAdmitted(), Equal(http.StatusTooManyRequests)),
			"the codes of a burst of 2 requests on %s for partner-a", exportsPath)
	})

	It("leaves the dropped rule out", func() {
		// Without the anonymous rule no rule of the cascade matches a request
		// without sub: per-user has no sub to count by, and the other two
		// match named subjects.
		Expect(gatewayBurst("public-gateway", exportsPath, perUser+1, nil)).To(HaveEach(beAdmitted()),
			"the codes of a burst of %d requests on %s without a token", perUser+1, exportsPath)
	})
})

// bearerFor is the Authorization header of a caller whose token carries sub,
// which the built-in sub key reads lowercased.
func bearerFor(sub string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + unsignedToken(map[string]string{"sub": sub})}
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

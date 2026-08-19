package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

const envtestNamespace = "ratelimit-envtest"

// These specs run against a real API server, which is the only place the CEL
// rules of the CRD actually run. A fake client accepts anything the Go types
// allow, so a rule that never fires would look like a rule that works.

func policyWith(name string, blocks ...ratelimitv1alpha1.LimitBlock) *ratelimitv1alpha1.RateLimitPolicy {
	return &ratelimitv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: envtestNamespace, Name: name},
		Spec: ratelimitv1alpha1.RateLimitPolicySpec{
			Domain: "gateway.public",
			Limits: blocks,
		},
	}
}

func blockWith(name string, rules ...ratelimitv1alpha1.Rule) ratelimitv1alpha1.LimitBlock {
	return ratelimitv1alpha1.LimitBlock{Name: name, Rules: rules}
}

func ruleWith(name string, rates ...ratelimitv1alpha1.Rate) ratelimitv1alpha1.Rule {
	if len(rates) == 0 {
		rates = []ratelimitv1alpha1.Rate{{Requests: 100, Period: "1m"}}
	}
	return ratelimitv1alpha1.Rule{Name: name, Rates: rates}
}

func predicateRule(name string, predicates ...ratelimitv1alpha1.Predicate) ratelimitv1alpha1.Rule {
	rule := ruleWith(name)
	rule.When = predicates
	return rule
}

func int32Ptr(value int32) *int32 { return new(value) }

var _ = Describe("RateLimitPolicy", func() {
	var reconciler *RateLimitPolicyReconciler

	BeforeEach(func() {
		reconciler = &RateLimitPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: envtestNamespace}}
		err := k8sClient.Create(ctx, ns)
		if err != nil {
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
	})

	create := func(policy *ratelimitv1alpha1.RateLimitPolicy) error {
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed())
		})
		return k8sClient.Create(ctx, policy)
	}

	Context("the schema", func() {
		It("requires a domain", func() {
			policy := policyWith("no-domain", blockWith("api", ruleWith("total")))
			policy.Spec.Domain = ""

			Expect(create(policy)).To(MatchError(ContainSubstring("should be at least 1 chars long")))
		})

		It("requires at least one block", func() {
			Expect(create(policyWith("no-limits"))).To(MatchError(ContainSubstring("spec.limits")))
		})

		It("rejects a domain that would break a counter key", func() {
			// A colon separates the segments of a key and braces are Redis Cluster
			// hash tags, so neither may appear in a domain.
			for _, domain := range []string{"Gateway.Public", "gateway:public", "gateway{public}", "gateway public"} {
				policy := policyWith("bad-domain", blockWith("api", ruleWith("total")))
				policy.Spec.Domain = domain

				Expect(create(policy)).To(MatchError(ContainSubstring("spec.domain")), "domain %q", domain)
			}
		})

		It("rejects two blocks of one name", func() {
			// The list is keyed by name, so uniqueness comes out of the schema
			// rather than out of a CEL rule.
			policy := policyWith("dup-blocks",
				blockWith("api", ruleWith("total")),
				blockWith("api", ruleWith("total")),
			)

			Expect(create(policy)).To(MatchError(ContainSubstring("Duplicate value")))
		})

		It("keeps path and method out of when", func() {
			// Paths and methods are selected by the target of the block.
			for _, key := range []string{"path", "method", "token"} {
				policy := policyWith("when-"+key, blockWith("api", predicateRule("r",
					ratelimitv1alpha1.Predicate{
						Key:      key,
						Operator: ratelimitv1alpha1.OperatorExists,
					})))

				Expect(create(policy)).
					To(MatchError(ContainSubstring("selected by target.routes")), "key %q", key)
			}
		})

		It("pairs every operator with the operand it takes", func() {
			cases := map[string]ratelimitv1alpha1.Predicate{
				"Equals with values": {
					Key: "client", Operator: ratelimitv1alpha1.OperatorEquals, Values: []string{"a"},
				},
				"Equals without value": {
					Key: "client", Operator: ratelimitv1alpha1.OperatorEquals,
				},
				"In with value": {
					Key: "client", Operator: ratelimitv1alpha1.OperatorIn, Value: "a",
				},
				"In without values": {
					Key: "client", Operator: ratelimitv1alpha1.OperatorIn,
				},
				"Exists with a value": {
					Key: "client", Operator: ratelimitv1alpha1.OperatorExists, Value: "a",
				},
				"NotExists with values": {
					Key: "client", Operator: ratelimitv1alpha1.OperatorNotExists, Values: []string{"a"},
				},
			}

			for name, predicate := range cases {
				policy := policyWith("operand", blockWith("api", predicateRule("r", predicate)))

				Expect(create(policy)).To(MatchError(ContainSubstring("operator")), "case %q", name)
			}
		})

		It("accepts the operators that do match their operand", func() {
			policy := policyWith("operands-ok", blockWith("api", predicateRule("r",
				ratelimitv1alpha1.Predicate{
					Key: "client", Operator: ratelimitv1alpha1.OperatorEquals, Value: "a",
				},
				ratelimitv1alpha1.Predicate{
					Key: "client", Operator: ratelimitv1alpha1.OperatorIn, Values: []string{"a", "b"},
				},
				ratelimitv1alpha1.Predicate{
					Key: "roles", Operator: ratelimitv1alpha1.OperatorContains, Value: "admin",
				},
				ratelimitv1alpha1.Predicate{
					Key: "tenant", Operator: ratelimitv1alpha1.OperatorNotExists,
				},
			)))

			Expect(create(policy)).To(Succeed())
		})

		It("keeps burst to GCRA windows", func() {
			policy := policyWith("burst-fixed", blockWith("api", ruleWith("total",
				ratelimitv1alpha1.Rate{
					Requests:  100,
					Period:    "1m",
					Burst:     int32Ptr(10),
					Algorithm: ratelimitv1alpha1.AlgorithmFixedWindow,
				})))

			Expect(create(policy)).To(MatchError(ContainSubstring("burst is a GCRA parameter")))
		})

		It("holds a period between one second and one day", func() {
			for _, period := range []string{"2d", "25h", "1441m"} {
				policy := policyWith("period", blockWith("api",
					ruleWith("total", ratelimitv1alpha1.Rate{Requests: 1, Period: period})))

				Expect(create(policy)).To(MatchError(ContainSubstring("period ranges")), "period %q", period)
			}
		})

		It("accepts one day written as a day", func() {
			// time.ParseDuration has no d suffix, so the range rule spells this case
			// out; a policy expressing a daily quota as 24h would work too.
			policy := policyWith("period-day", blockWith("api", ruleWith("quota",
				ratelimitv1alpha1.Rate{
					Requests:  20000,
					Period:    "1d",
					Algorithm: ratelimitv1alpha1.AlgorithmFixedWindow,
				})))

			Expect(create(policy)).To(Succeed())
		})

		It("rejects two windows of one period in a rule", func() {
			policy := policyWith("dup-period", blockWith("api", ruleWith("total",
				ratelimitv1alpha1.Rate{Requests: 10, Period: "1m"},
				ratelimitv1alpha1.Rate{Requests: 20, Period: "1m"},
			)))

			Expect(create(policy)).To(MatchError(ContainSubstring("periods of a rule are unique")))
		})

		It("gives a Bypass rule no rates and every other rule at least one", func() {
			withRates := policyWith("bypass-rates", blockWith("api", ratelimitv1alpha1.Rule{
				Name:     "internal",
				Behavior: ratelimitv1alpha1.RuleBehaviorBypass,
				Rates:    []ratelimitv1alpha1.Rate{{Requests: 1, Period: "1m"}},
			}))
			Expect(create(withRates)).To(MatchError(ContainSubstring("Bypass carries no rates")))

			withoutRates := policyWith("enforce-no-rates", blockWith("api", ratelimitv1alpha1.Rule{
				Name: "total",
			}))
			Expect(create(withoutRates)).To(MatchError(ContainSubstring("carries at least one")))
		})

		It("accepts a Bypass rule without rates", func() {
			policy := policyWith("bypass-ok", blockWith("api",
				ratelimitv1alpha1.Rule{
					Name:     "internal",
					Behavior: ratelimitv1alpha1.RuleBehaviorBypass,
					When: []ratelimitv1alpha1.Predicate{{
						Key:      "client",
						Operator: ratelimitv1alpha1.OperatorEquals,
						Value:    "prometheus",
					}},
				},
				ruleWith("everyone"),
			))

			Expect(create(policy)).To(Succeed())
		})

		It("keeps replaces out of a FirstMatch block", func() {
			// In a FirstMatch block the order of the rules already decides.
			block := blockWith("cascade",
				ruleWith("broad"),
				ratelimitv1alpha1.Rule{
					Name:     "narrow",
					Replaces: []string{"broad"},
					Rates:    []ratelimitv1alpha1.Rate{{Requests: 10, Period: "1m"}},
				},
			)
			block.Mode = ratelimitv1alpha1.BlockModeFirstMatch
			policy := policyWith("replaces-firstmatch", block)

			Expect(create(policy)).To(MatchError(ContainSubstring("replaces needs mode All")))
		})

		It("rejects a malformed template", func() {
			cases := map[string]string{
				"unnamed placeholder":  "/api/{}/orders",
				"placeholder in part":  "/api/v{version}x/orders",
				"unclosed placeholder": "/api/{id/orders",
				"nested braces":        "/api/{a{b}}/orders",
				"upper-case name":      "/api/{OrderId}/orders",
			}

			for name, value := range cases {
				policy := policyWith("template", ratelimitv1alpha1.LimitBlock{
					Name: "api",
					Target: &ratelimitv1alpha1.Target{Routes: []ratelimitv1alpha1.Route{{
						Path: ratelimitv1alpha1.PathMatch{
							Type:  ratelimitv1alpha1.PathMatchTemplate,
							Value: value,
						},
					}}},
					Rules: []ratelimitv1alpha1.Rule{ruleWith("total")},
				})

				Expect(create(policy)).To(MatchError(ContainSubstring("Template")), "case %q", name)
			}
		})

		It("keeps a template placeholder off a built-in key name", func() {
			// A capture named path would shadow the path axis inside its block.
			policy := policyWith("template-builtin", ratelimitv1alpha1.LimitBlock{
				Name: "api",
				Target: &ratelimitv1alpha1.Target{Routes: []ratelimitv1alpha1.Route{{
					Path: ratelimitv1alpha1.PathMatch{
						Type:  ratelimitv1alpha1.PathMatchTemplate,
						Value: "/api/{path}/orders",
					},
				}}},
				Rules: []ratelimitv1alpha1.Rule{ruleWith("total")},
			})

			Expect(create(policy)).To(MatchError(ContainSubstring("built-in key")))
		})

		It("accepts a well-formed template", func() {
			policy := policyWith("template-ok", ratelimitv1alpha1.LimitBlock{
				Name: "api",
				Target: &ratelimitv1alpha1.Target{Routes: []ratelimitv1alpha1.Route{{
					Path: ratelimitv1alpha1.PathMatch{
						Type:  ratelimitv1alpha1.PathMatchTemplate,
						Value: "/api/v1/orders/{order_id}/items",
					},
					Methods: []ratelimitv1alpha1.HTTPMethod{"GET", "POST"},
				}}},
				Rules: []ratelimitv1alpha1.Rule{ruleWith("total")},
			})

			Expect(create(policy)).To(Succeed())
		})

		It("rejects a method outside the HTTP set", func() {
			policy := policyWith("bad-method", ratelimitv1alpha1.LimitBlock{
				Name: "api",
				Target: &ratelimitv1alpha1.Target{Routes: []ratelimitv1alpha1.Route{{
					Path:    ratelimitv1alpha1.PathMatch{Type: ratelimitv1alpha1.PathMatchPrefix, Value: "/api/"},
					Methods: []ratelimitv1alpha1.HTTPMethod{"FETCH"},
				}}},
				Rules: []ratelimitv1alpha1.Rule{ruleWith("total")},
			})

			Expect(create(policy)).To(MatchError(ContainSubstring("Unsupported value")))
		})

		It("applies the defaults of the schema", func() {
			policy := policyWith("defaults", blockWith("api", ruleWith("total")))
			Expect(create(policy)).To(Succeed())

			stored := &ratelimitv1alpha1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), stored)).To(Succeed())

			Expect(stored.Spec.Limits[0].Mode).To(Equal(ratelimitv1alpha1.BlockModeAll))
			Expect(stored.Spec.Limits[0].Rules[0].Behavior).To(Equal(ratelimitv1alpha1.RuleBehaviorEnforce))
			Expect(stored.Spec.Limits[0].Rules[0].Rates[0].Algorithm).To(Equal(ratelimitv1alpha1.AlgorithmGCRA))
		})
	})

	Context("reconciliation", func() {
		It("accepts a policy and records the generation it saw", func() {
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "public-gateway"}
			Expect(create(policyWith(name.Name, blockWith("api", ruleWith("total"))))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			reconciled := &ratelimitv1alpha1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status.ObservedGeneration).To(Equal(reconciled.Generation))

			accepted := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
			Expect(accepted).NotTo(BeNil())
			Expect(accepted.Status).To(Equal(metav1.ConditionTrue))
			Expect(accepted.Reason).To(Equal(ratelimitv1alpha1.ReasonRulesCompiled))
			Expect(accepted.ObservedGeneration).To(Equal(reconciled.Generation))

			ready := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionTrue))

			By("keeping the spec out of the status subresource")
			Expect(reconciled.Spec.Domain).To(Equal("gateway.public"))
		})

		It("writes the rule problems the API server accepts", func() {
			// The status carries a list, and the API server validates it like any
			// other field: a problem the operator cannot write is a problem nobody
			// sees.
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "dead-rule"}
			Expect(create(policyWith(name.Name, blockWith("api", predicateRule("per-plan",
				ratelimitv1alpha1.Predicate{
					Key:      "plan",
					Operator: ratelimitv1alpha1.OperatorExists,
				}))))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			reconciled := &ratelimitv1alpha1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status.RuleProblems).To(HaveLen(1))
			Expect(reconciled.Status.RuleProblems[0].Reason).
				To(Equal(ratelimitv1alpha1.ProblemUnresolvedKeyReference))
			Expect(reconciled.Status.Problems).To(Equal(int32(1)))
		})

		It("records the pair of generations the API server accepts", func() {
			// activeGeneration and ruleProblems are new status fields, and a field the
			// API server rejects is a diagnostic nobody ever sees.
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "stuck"}
			Expect(create(policyWith(name.Name, blockWith("api", predicateRule("per-tenant",
				ratelimitv1alpha1.Predicate{
					Key:      "tenant",
					Operator: ratelimitv1alpha1.OperatorExists,
				}))))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			reconciled := &ratelimitv1alpha1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status.ObservedGeneration).To(Equal(reconciled.Generation))
			Expect(reconciled.Status.ActiveGeneration).To(BeZero(),
				"a generation with a blocking problem enforces nothing")

			ready := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			Expect(ready.Reason).To(Equal(ratelimitv1alpha1.ReasonMappingRequired))
		})

		It("ignores a policy that is already gone", func() {
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Namespace: envtestNamespace, Name: "never-existed"},
			})

			Expect(err).NotTo(HaveOccurred())
		})
	})
})

var _ = Describe("RateLimitMapping", func() {
	var reconciler *RateLimitMappingReconciler

	BeforeEach(func() {
		reconciler = &RateLimitMappingReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: envtestNamespace}}
		err := k8sClient.Create(ctx, ns)
		if err != nil {
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
	})

	mapping := func(name, domain string, entries ...ratelimitv1alpha1.ClaimMapping) *ratelimitv1alpha1.RateLimitMapping {
		return &ratelimitv1alpha1.RateLimitMapping{
			ObjectMeta: metav1.ObjectMeta{Namespace: envtestNamespace, Name: name},
			Spec: ratelimitv1alpha1.RateLimitMappingSpec{
				Domain:   domain,
				Mappings: entries,
			},
		}
	}

	create := func(object *ratelimitv1alpha1.RateLimitMapping) error {
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed())
		})
		return k8sClient.Create(ctx, object)
	}

	It("is a singleton by construction", func() {
		// The name equals the domain and object names are unique in a namespace, so
		// a second mapping of one domain is not representable. There is no "which
		// one wins" to arbitrate.
		Expect(create(mapping("gateway.public", "gateway.public"))).To(Succeed())

		second := mapping("gateway.public", "gateway.public")
		Expect(k8sClient.Create(ctx, second)).To(MatchError(ContainSubstring("already exists")))
	})

	It("rejects a name that is not the domain", func() {
		Expect(create(mapping("something-else", "gateway.public"))).
			To(MatchError(ContainSubstring("has to equal spec.domain")))
	})

	It("takes exactly one of claim and claimPath", func() {
		both := mapping("gateway.both", "gateway.both", ratelimitv1alpha1.ClaimMapping{
			Key:       "tenant",
			Claim:     "org_id",
			ClaimPath: []string{"org_id"},
		})
		Expect(create(both)).To(MatchError(ContainSubstring("exactly one of claim and claimPath")))

		neither := mapping("gateway.neither", "gateway.neither", ratelimitv1alpha1.ClaimMapping{
			Key: "tenant",
		})
		Expect(create(neither)).To(MatchError(ContainSubstring("exactly one of claim and claimPath")))
	})

	It("keeps a mapping off a key the engine produces", func() {
		for _, key := range []string{"path", "method", "token"} {
			object := mapping("gateway.reserved", "gateway.reserved", ratelimitv1alpha1.ClaimMapping{
				Key:   key,
				Claim: "whatever",
			})

			Expect(create(object)).To(MatchError(ContainSubstring("cannot be redefined")), "key %q", key)
		}
	})

	It("accepts an override of the built-in client key", func() {
		// client is the one built-in key a mapping may redefine, because it is a
		// default rather than an engine input.
		object := mapping("gateway.client", "gateway.client",
			ratelimitv1alpha1.ClaimMapping{Key: "client", Claim: "azp"})

		Expect(create(object)).To(Succeed())
	})

	It("publishes the effective keys", func() {
		name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.keys"}
		Expect(create(mapping(name.Name, name.Name,
			ratelimitv1alpha1.ClaimMapping{
				Key:       "roles",
				Claim:     "realm_access.roles",
				Type:      ratelimitv1alpha1.ClaimTypeStringArray,
				Normalize: ratelimitv1alpha1.NormalizeLowercase,
			},
			ratelimitv1alpha1.ClaimMapping{
				Key:       "tenant",
				ClaimPath: []string{"https://acme.com/tenant"},
				Fallbacks: []string{"sub"},
			},
		))).To(Succeed())

		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		reconciled := &ratelimitv1alpha1.RateLimitMapping{}
		Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
		Expect(reconciled.Status.EffectiveKeys).
			To(Equal([]string{"client", "method", "path", "roles", "tenant"}))
		Expect(reconciled.Status.ObservedGeneration).To(Equal(reconciled.Generation))
	})

	It("records the veto list the API server accepts", func() {
		// rejectedBy is how the author of a rejected mapping finds who blocked it,
		// and the API server has to accept every field of it.
		name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.vetoed"}
		Expect(create(mapping(name.Name, name.Name,
			ratelimitv1alpha1.ClaimMapping{Key: "tenant", Claim: "org_id"}))).To(Succeed())

		stored := &ratelimitv1alpha1.RateLimitMapping{}
		Expect(k8sClient.Get(ctx, name, stored)).To(Succeed())
		stored.Status.ObservedGeneration = 5
		stored.Status.ActiveGeneration = 3
		stored.Status.EffectiveKeys = []string{"client", "method", "path", "tenant"}
		stored.Status.RejectedBy = []ratelimitv1alpha1.MappingRejection{{
			Policy:     "quote-api",
			Generation: 3,
			Block:      "quote-api",
			Rule:       "per-tenant",
			Reason:     ratelimitv1alpha1.ProblemUnresolvedKeyReference,
		}}
		Expect(k8sClient.Status().Update(ctx, stored)).To(Succeed())

		reloaded := &ratelimitv1alpha1.RateLimitMapping{}
		Expect(k8sClient.Get(ctx, name, reloaded)).To(Succeed())
		Expect(reloaded.Status.ActiveGeneration).To(Equal(int64(3)))
		Expect(reloaded.Status.RejectedBy).To(HaveLen(1))
		Expect(reloaded.Status.RejectedBy[0].Rule).To(Equal("per-tenant"))
	})

	It("ignores a mapping that is already gone", func() {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: envtestNamespace, Name: "never-existed"},
		})

		Expect(err).NotTo(HaveOccurred())
	})
})

package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

const envtestNamespace = "ratelimit-envtest"

// These specs run against a real API server, which is the only place the schema
// actually runs. A fake client accepts anything the Go types allow, so a
// constraint that never fires would look like one that works.
//
// The schema holds the shape of values and nothing else: patterns, enums,
// ranges, uniqueness through list types, and the one CEL rule that makes a
// policy the singleton of its domain. Everything that relates fields to each
// other is the compiler's, answered through the status — the cost estimator
// charges every CEL rule the product of the list bounds on the way to it, so
// keeping those checks here would mean bounding every list for the estimator's
// sake and maintaining a second copy of the compiler.

// policyWith builds a policy for a domain. The name is the domain: the CEL rule
// admits nothing else.
func policyWith(domain string, blocks ...ratelimitv1alpha1.LimitBlock) *ratelimitv1alpha1.RateLimitPolicy {
	return &ratelimitv1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: envtestNamespace, Name: domain},
		Spec: ratelimitv1alpha1.RateLimitPolicySpec{
			Domain: domain,
			Limits: blocks,
		},
	}
}

func blockWith(name string, rules ...ratelimitv1alpha1.Rule) ratelimitv1alpha1.LimitBlock {
	return ratelimitv1alpha1.LimitBlock{Name: name, Rules: rules}
}

func ruleWith(name string, rates ...ratelimitv1alpha1.Rate) ratelimitv1alpha1.Rule {
	if len(rates) == 0 {
		rates = []ratelimitv1alpha1.Rate{{Requests: 100, PeriodSeconds: 60}}
	}
	return ratelimitv1alpha1.Rule{Name: name, Rates: rates}
}

func predicateRule(name string, predicates ...ratelimitv1alpha1.Predicate) ratelimitv1alpha1.Rule {
	rule := ruleWith(name)
	rule.Matches = predicates
	return rule
}

var _ = Describe("RateLimitPolicy", func() {
	var reconciler *RateLimitPolicyReconciler

	BeforeEach(func() {
		reconciler = &RateLimitPolicyReconciler{
			Client:    k8sClient,
			Scheme:    k8sClient.Scheme(),
			Namespace: envtestNamespace,
		}

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

	Context("the singleton rule", func() {
		It("requires the name to be the domain", func() {
			// Object names are unique within a namespace, so this one rule is what
			// makes a second policy for a domain unrepresentable. There is no
			// "which of the two wins" question left to answer.
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Name = "something-else"

			Expect(create(policy)).To(MatchError(ContainSubstring("metadata.name has to equal spec.domain")))
		})

		It("refuses a second policy for a domain", func() {
			Expect(create(policyWith("gateway.public", blockWith("api", ruleWith("total"))))).To(Succeed())

			twin := policyWith("gateway.public", blockWith("other", ruleWith("total")))
			Expect(create(twin)).To(MatchError(ContainSubstring("already exists")))
		})
	})

	Context("the schema", func() {
		It("requires a domain", func() {
			// The name has to equal the domain, and a name cannot be empty, so an
			// empty domain has nowhere left to hide.
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Domain = ""

			Expect(create(policy)).To(HaveOccurred())
		})

		It("requires at least one block", func() {
			Expect(create(policyWith("gateway.public"))).To(HaveOccurred())
		})

		It("rejects a domain that would break a counter key", func() {
			// A colon separates key segments, braces are Redis Cluster hash tags,
			// and a slash separates the namespace from the domain inside the tag.
			// The object is never created, so it is not registered for cleanup:
			// deleting a name the API server refused fails on the name itself.
			for _, domain := range []string{"gateway:public", "gateway{public}", "Gateway.Public", "a/b"} {
				policy := policyWith(domain, blockWith("api", ruleWith("total")))

				Expect(k8sClient.Create(ctx, policy)).To(HaveOccurred(), "domain %q", domain)
			}
		})

		It("rejects two blocks of one name", func() {
			policy := policyWith("gateway.public",
				blockWith("api", ruleWith("total")),
				blockWith("api", ruleWith("total")),
			)

			Expect(create(policy)).To(MatchError(ContainSubstring("Duplicate value")))
		})

		It("rejects two rules of one name in a block", func() {
			policy := policyWith("gateway.public",
				blockWith("api", ruleWith("total"), ruleWith("total")))

			Expect(create(policy)).To(MatchError(ContainSubstring("Duplicate value")))
		})

		It("rejects two windows of one period in a rule", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total",
				ratelimitv1alpha1.Rate{Requests: 10, PeriodSeconds: 60},
				ratelimitv1alpha1.Rate{Requests: 20, PeriodSeconds: 60},
			)))

			Expect(create(policy)).To(MatchError(ContainSubstring("Duplicate value")))
		})

		It("holds a period between one second and one day", func() {
			for _, seconds := range []int32{0, 86401} {
				policy := policyWith("gateway.public", blockWith("api", ruleWith("total",
					ratelimitv1alpha1.Rate{Requests: 10, PeriodSeconds: seconds})))

				Expect(create(policy)).To(HaveOccurred(), "periodSeconds %d", seconds)
			}
		})

		It("accepts a day, the longest window a rate limit has", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total",
				ratelimitv1alpha1.Rate{Requests: 10, PeriodSeconds: 86400})))

			Expect(create(policy)).To(Succeed())
		})

		It("rejects a method outside the HTTP set", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Limits[0].Target = &ratelimitv1alpha1.Target{
				Routes: []ratelimitv1alpha1.Route{{
					Path:    ratelimitv1alpha1.PathMatch{Type: ratelimitv1alpha1.PathMatchPrefix, Value: "/api/"},
					Methods: []ratelimitv1alpha1.HTTPMethod{"FETCH"},
				}},
			}

			Expect(create(policy)).To(MatchError(ContainSubstring("Unsupported value")))
		})

		It("rejects a duplicated method on a route", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Limits[0].Target = &ratelimitv1alpha1.Target{
				Routes: []ratelimitv1alpha1.Route{{
					Path:    ratelimitv1alpha1.PathMatch{Type: ratelimitv1alpha1.PathMatchPrefix, Value: "/api/"},
					Methods: []ratelimitv1alpha1.HTTPMethod{"GET", "GET"},
				}},
			}

			Expect(create(policy)).To(MatchError(ContainSubstring("Duplicate value")))
		})

		It("requires a path to start with a slash", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Limits[0].Target = &ratelimitv1alpha1.Target{
				Routes: []ratelimitv1alpha1.Route{{
					Path: ratelimitv1alpha1.PathMatch{Type: ratelimitv1alpha1.PathMatchPrefix, Value: "api/"},
				}},
			}

			Expect(create(policy)).To(MatchError(ContainSubstring("should match")))
		})

		It("admits a camelCase descriptor key", func() {
			// One pattern covers every place a key is named, and it admits the
			// camelCase the reference examples use.
			policy := policyWith("gateway.public", blockWith("api",
				predicateRule("per-tenant", ratelimitv1alpha1.Predicate{
					Key: "tenantId", Operator: ratelimitv1alpha1.OperatorExists,
				})))
			policy.Spec.Mappings = []ratelimitv1alpha1.ClaimMapping{
				{Key: "tenantId", Claim: "org_id"},
			}
			policy.Spec.Limits[0].Rules[0].Counters = []string{"tenantId"}
			policy.Spec.Limits[0].Target = &ratelimitv1alpha1.Target{
				Routes: []ratelimitv1alpha1.Route{{
					Path: ratelimitv1alpha1.PathMatch{
						Type: ratelimitv1alpha1.PathMatchTemplate, Value: "/api/orders/{orderId}",
					},
				}},
			}

			Expect(create(policy)).To(Succeed())
		})

		It("carries a policy no list bound would fit", func() {
			// The lists carry no maxItems: what binds a generation is the bucket
			// budget and the object size, and both are the compiler's business.
			policy := policyWith("gateway.public")
			for i := range 40 {
				policy.Spec.Limits = append(policy.Spec.Limits,
					blockWith(blockName(i), ruleWith("total")))
			}

			Expect(create(policy)).To(Succeed())
		})

		It("applies the defaults of the schema", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			Expect(create(policy)).To(Succeed())

			stored := &ratelimitv1alpha1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), stored)).To(Succeed())

			Expect(stored.Spec.Limits[0].Mode).To(Equal(ratelimitv1alpha1.BlockModeAll))
			Expect(stored.Spec.Limits[0].Rules[0].Behavior).To(Equal(ratelimitv1alpha1.RuleBehaviorEnforce))
			Expect(stored.Spec.Limits[0].Rules[0].Rates[0].Algorithm).To(Equal(ratelimitv1alpha1.AlgorithmGCRA))
		})

		It("accepts the mappings and groups of the one object", func() {
			policy := policyWith("gateway.public", blockWith("api",
				predicateRule("partners", ratelimitv1alpha1.Predicate{
					Key: "client", Operator: ratelimitv1alpha1.OperatorInGroup, Value: "partners",
				})))
			policy.Spec.Mappings = []ratelimitv1alpha1.ClaimMapping{{
				Key:           "roles",
				Claim:         "realm_access.roles",
				Type:          ratelimitv1alpha1.ClaimTypeStringArray,
				Normalization: ratelimitv1alpha1.NormalizeLowercase,
				Fallbacks:     []string{"sub"},
			}}
			policy.Spec.Groups = []ratelimitv1alpha1.ClientGroup{
				{Name: "partners", Clients: []string{"p1", "p2"}},
			}

			Expect(create(policy)).To(Succeed())
		})

		It("rejects two mappings of one key", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Mappings = []ratelimitv1alpha1.ClaimMapping{
				{Key: "roles", Claim: "a"},
				{Key: "roles", Claim: "b"},
			}

			Expect(create(policy)).To(MatchError(ContainSubstring("Duplicate value")))
		})
	})

	Context("reconciliation", func() {
		It("records the status the API server accepts", func() {
			// Every one of these fields is validated like any other: a status the
			// operator cannot write is a diagnostic nobody ever sees.
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.public"}
			Expect(create(policyWith(name.Name, blockWith("api", ruleWith("total"))))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			reconciled := &ratelimitv1alpha1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status.ObservedGeneration).To(Equal(reconciled.Generation))
			Expect(reconciled.Status.ActiveGeneration).To(Equal(reconciled.Generation))
			Expect(reconciled.Status.Rules).To(Equal(int32(1)))
			Expect(reconciled.Status.EffectiveKeys).To(ContainElement("client"))

			accepted := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
			Expect(accepted).NotTo(BeNil())
			Expect(accepted.Status).To(Equal(metav1.ConditionTrue))
			Expect(accepted.Reason).To(Equal(ratelimitv1alpha1.ReasonRulesCompiled))
			Expect(accepted.ObservedGeneration).To(Equal(reconciled.Generation))

			// Without a probe the fleet is unobserved, which is Unknown rather
			// than a claim of unanimity nobody checked.
			ready := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Reason).To(Equal(ratelimitv1alpha1.ReasonProbeFailed))

			stalled := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionStalled)
			Expect(stalled).NotTo(BeNil())
			Expect(stalled.Status).To(Equal(metav1.ConditionFalse))

			By("keeping the spec out of the status subresource")
			Expect(reconciled.Spec.Domain).To(Equal("gateway.public"))
		})

		It("writes the rule problems the API server accepts", func() {
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.private"}
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
			Expect(reconciled.Status.ActiveGeneration).To(BeZero(),
				"a generation with a blocking problem enforces nothing")

			accepted := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
			Expect(accepted.Status).To(Equal(metav1.ConditionFalse))
			Expect(accepted.Reason).To(Equal(ratelimitv1alpha1.ReasonCompilationFailed))

			stalled := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionStalled)
			Expect(stalled.Status).To(Equal(metav1.ConditionTrue))
			Expect(stalled.Reason).To(Equal(ratelimitv1alpha1.ReasonNotCompiled))
		})

		It("ignores a policy that is already gone", func() {
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.absent"},
			})

			Expect(err).NotTo(HaveOccurred())
		})
	})
})

// blockName numbers the blocks of the no-bounds spec.
func blockName(i int) string {
	const digits = "0123456789"
	return "b" + string(digits[i/10]) + string(digits[i%10])
}

var _ = Describe("SetupWithManager", func() {
	// The builder chain runs at registration, and registration needs a real
	// manager. The manager is never started: what these lines can get wrong
	// fails right here.
	It("registers the controller with a manager", func() {
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:  clientgoscheme.Scheme,
			Metrics: metricsserver.Options{BindAddress: "0"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect((&RateLimitPolicyReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).
			SetupWithManager(mgr)).To(Succeed())
	})
})

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
	gtypes "github.com/onsi/gomega/types"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ratelimitv1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/operator/internal/policy"
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
//
// A refusal by the schema is matched by the cause the API server reports, its
// type and the field it names, rather than by the wording of its message: a
// domain such as "gateway:public" is also an invalid object name, and only
// the field tells the pattern on spec.domain apart from the validation of
// metadata.name. The CEL rule is matched by the message it declares, and an
// empty domain, which two rules refuse, only as invalid.

// policyWith builds a policy for a domain. The name is the domain: the CEL rule
// admits nothing else.
func policyWith(domain string, blocks ...ratelimitv1.LimitBlock) *ratelimitv1.RateLimitPolicy {
	return &ratelimitv1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: envtestNamespace, Name: domain},
		Spec: ratelimitv1.RateLimitPolicySpec{
			Domain: domain,
			Limits: blocks,
		},
	}
}

func blockWith(name string, rules ...ratelimitv1.Rule) ratelimitv1.LimitBlock {
	return ratelimitv1.LimitBlock{Name: name, Rules: rules}
}

func ruleWith(name string, rates ...ratelimitv1.Rate) ratelimitv1.Rule {
	if len(rates) == 0 {
		rates = []ratelimitv1.Rate{{Requests: 100, PeriodSeconds: 60}}
	}
	return ratelimitv1.Rule{Name: name, Rates: rates}
}

func predicateRule(name string, predicates ...ratelimitv1.Predicate) ratelimitv1.Rule {
	rule := ruleWith(name)
	rule.Matches = predicates
	return rule
}

// rejectedAt matches an error of the API server that refuses an object for a
// cause of causeType at field.
func rejectedAt(causeType metav1.CauseType, field string) gtypes.GomegaMatcher {
	return WithTransform(statusCauses, ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Type":  Equal(causeType),
		"Field": Equal(field),
	})))
}

// statusCauses returns the causes an error of the API server carries, and
// none for any other error.
func statusCauses(err error) []metav1.StatusCause {
	var status apierrors.APIStatus
	if !errors.As(err, &status) || status.Status().Details == nil {
		return nil
	}
	return status.Status().Details.Causes
}

var _ = Describe("RateLimitPolicy", func() {
	var reconciler *RateLimitPolicyReconciler
	var recorder *events.FakeRecorder

	BeforeEach(func() {
		// A stub fleet, so the healthy path reaches Ready: True against a real
		// API server. Without a probe every generation stops at ProbeFailed,
		// and the condition this suite exists to check would never be asserted.
		recorder = events.NewFakeRecorder(16)
		reconciler = &RateLimitPolicyReconciler{
			Client:    k8sClient,
			Scheme:    k8sClient.Scheme(),
			Namespace: envtestNamespace,
			Probe:     unanimous(3),
			Events:    recorder,
		}

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: envtestNamespace}}
		err := k8sClient.Create(ctx, ns)
		if err != nil {
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
	})

	create := func(policy *ratelimitv1.RateLimitPolicy) error {
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed())
		})
		return k8sClient.Create(ctx, policy)
	}

	Context("the singleton rule", func() {
		It("requires the name to be the domain", func() {
			// Object names are unique within a namespace, so this one rule is what
			// makes a second policy for a domain unrepresentable. There is no
			// "which of the two wins" question left to answer. The message is the
			// one the CEL rule declares for the author.
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Name = "something-else"

			Expect(create(policy)).To(MatchError(ContainSubstring("metadata.name has to equal spec.domain")))
		})

		It("refuses a second policy for a domain", func() {
			Expect(create(policyWith("gateway.public", blockWith("api", ruleWith("total"))))).To(Succeed())

			twin := policyWith("gateway.public", blockWith("other", ruleWith("total")))
			Expect(create(twin)).To(MatchError(apierrors.IsAlreadyExists, "apierrors.IsAlreadyExists"))
		})
	})

	Context("the schema", func() {
		It("requires a domain", func() {
			// The name has to equal the domain, and a name cannot be empty, so an
			// empty domain is refused whichever of the two rules reports it.
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Domain = ""

			Expect(create(policy)).To(MatchError(apierrors.IsInvalid, "apierrors.IsInvalid"))
		})

		It("requires at least one block", func() {
			Expect(create(policyWith("gateway.public"))).
				To(rejectedAt(metav1.CauseTypeFieldValueRequired, "spec.limits"))
		})

		// A colon separates key segments, braces are Redis Cluster hash tags,
		// and a slash separates the namespace from the domain inside the tag.
		// The object is never created, so it is not registered for cleanup:
		// deleting a name the API server refused fails on the name itself.
		DescribeTable("rejects a domain that would break a counter key",
			func(domain string) {
				Expect(k8sClient.Create(ctx, policyWith(domain, blockWith("api", ruleWith("total"))))).
					To(rejectedAt(metav1.CauseTypeFieldValueInvalid, "spec.domain"))
			},
			Entry("a colon", "gateway:public"),
			Entry("braces", "gateway{public}"),
			Entry("an uppercase letter", "Gateway.Public"),
			Entry("a slash", "a/b"),
		)

		It("rejects two blocks of one name", func() {
			policy := policyWith("gateway.public",
				blockWith("api", ruleWith("total")),
				blockWith("api", ruleWith("total")),
			)

			Expect(create(policy)).To(rejectedAt(metav1.CauseTypeFieldValueDuplicate, "spec.limits[1]"))
		})

		It("rejects two rules of one name in a block", func() {
			policy := policyWith("gateway.public",
				blockWith("api", ruleWith("total"), ruleWith("total")))

			Expect(create(policy)).To(rejectedAt(metav1.CauseTypeFieldValueDuplicate, "spec.limits[0].rules[1]"))
		})

		It("rejects two windows of one period in a rule", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total",
				ratelimitv1.Rate{Requests: 10, PeriodSeconds: 60},
				ratelimitv1.Rate{Requests: 20, PeriodSeconds: 60},
			)))

			Expect(create(policy)).
				To(rejectedAt(metav1.CauseTypeFieldValueDuplicate, "spec.limits[0].rules[0].rates[1]"))
		})

		DescribeTable("rejects a period outside one second to one day",
			func(seconds int32) {
				policy := policyWith("gateway.public", blockWith("api", ruleWith("total",
					ratelimitv1.Rate{Requests: 10, PeriodSeconds: seconds})))

				Expect(create(policy)).
					To(rejectedAt(metav1.CauseTypeFieldValueInvalid, "spec.limits[0].rules[0].rates[0].periodSeconds"))
			},
			Entry("zero seconds", int32(0)),
			Entry("a day and a second", int32(86401)),
		)

		DescribeTable("accepts a period at the bounds of a window",
			func(seconds int32) {
				policy := policyWith("gateway.public", blockWith("api", ruleWith("total",
					ratelimitv1.Rate{Requests: 10, PeriodSeconds: seconds})))

				Expect(create(policy)).To(Succeed())
			},
			Entry("one second, the shortest window", int32(1)),
			Entry("a day, the longest window a rate limit has", int32(86400)),
		)

		It("rejects a method outside the HTTP set", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Limits[0].Target = &ratelimitv1.Target{
				Routes: []ratelimitv1.Route{{
					Path:    ratelimitv1.PathMatch{Type: ratelimitv1.PathMatchPrefix, Value: "/api/"},
					Methods: []ratelimitv1.HTTPMethod{"FETCH"},
				}},
			}

			Expect(create(policy)).
				To(rejectedAt(metav1.CauseTypeFieldValueNotSupported, "spec.limits[0].target.routes[0].methods[0]"))
		})

		It("rejects a duplicated method on a route", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Limits[0].Target = &ratelimitv1.Target{
				Routes: []ratelimitv1.Route{{
					Path:    ratelimitv1.PathMatch{Type: ratelimitv1.PathMatchPrefix, Value: "/api/"},
					Methods: []ratelimitv1.HTTPMethod{"GET", "GET"},
				}},
			}

			Expect(create(policy)).
				To(rejectedAt(metav1.CauseTypeFieldValueDuplicate, "spec.limits[0].target.routes[0].methods[1]"))
		})

		It("requires a path to start with a slash", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Limits[0].Target = &ratelimitv1.Target{
				Routes: []ratelimitv1.Route{{
					Path: ratelimitv1.PathMatch{Type: ratelimitv1.PathMatchPrefix, Value: "api/"},
				}},
			}

			Expect(create(policy)).
				To(rejectedAt(metav1.CauseTypeFieldValueInvalid, "spec.limits[0].target.routes[0].path.value"))
		})

		It("admits a camelCase descriptor key", func() {
			// One pattern covers every place a key is named, and it admits the
			// camelCase the reference examples use.
			policy := policyWith("gateway.public", blockWith("api",
				predicateRule("per-tenant", ratelimitv1.Predicate{
					Key: "tenantId", Operator: ratelimitv1.OperatorExists,
				})))
			policy.Spec.Mappings = []ratelimitv1.ClaimMapping{
				{Key: "tenantId", Claim: "org_id"},
			}
			policy.Spec.Limits[0].Rules[0].Counters = []string{"tenantId"}
			policy.Spec.Limits[0].Target = &ratelimitv1.Target{
				Routes: []ratelimitv1.Route{{
					Path: ratelimitv1.PathMatch{
						Type: ratelimitv1.PathMatchTemplate, Value: "/api/orders/{orderId}",
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
					blockWith(fmt.Sprintf("b%02d", i), ruleWith("total")))
			}

			Expect(create(policy)).To(Succeed())
		})

		It("applies the defaults of the schema", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			Expect(create(policy)).To(Succeed())

			stored := &ratelimitv1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), stored)).To(Succeed())

			type defaults struct {
				Mode      ratelimitv1.BlockMode
				Behavior  ratelimitv1.RuleBehavior
				Algorithm ratelimitv1.Algorithm
			}
			block := stored.Spec.Limits[0]
			Expect(defaults{block.Mode, block.Rules[0].Behavior, block.Rules[0].Rates[0].Algorithm}).
				To(Equal(defaults{ratelimitv1.BlockModeAll, ratelimitv1.RuleBehaviorEnforce, ratelimitv1.AlgorithmGCRA}))
		})

		It("accepts the mappings and groups of the one object", func() {
			policy := policyWith("gateway.public", blockWith("api",
				predicateRule("partners", ratelimitv1.Predicate{
					Key: "sub", Operator: ratelimitv1.OperatorInGroup, Value: "partners",
				})))
			policy.Spec.Mappings = []ratelimitv1.ClaimMapping{{
				Key:           "roles",
				Claim:         "realm_access.roles",
				Type:          ratelimitv1.ClaimTypeStringArray,
				Normalization: ratelimitv1.NormalizeLowercase,
				Fallbacks:     []string{"sub"},
			}}
			policy.Spec.Groups = []ratelimitv1.Group{
				{Name: "partners", Values: []string{"p1", "p2"}},
			}

			Expect(create(policy)).To(Succeed())
		})

		It("rejects two mappings of one key", func() {
			policy := policyWith("gateway.public", blockWith("api", ruleWith("total")))
			policy.Spec.Mappings = []ratelimitv1.ClaimMapping{
				{Key: "roles", Claim: "a"},
				{Key: "roles", Claim: "b"},
			}

			Expect(create(policy)).To(rejectedAt(metav1.CauseTypeFieldValueDuplicate, "spec.mappings[1]"))
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

			reconciled := &ratelimitv1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"ObservedGeneration": Equal(reconciled.Generation),
				"ActiveGeneration":   Equal(reconciled.Generation),
				"Rules":              Equal(int32(1)),
				"EffectiveKeys":      ContainElement("sub"),
				"Conditions": SatisfyAll(
					WithTransform(verdicts, gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{
						ratelimitv1.ConditionAccepted: Equal(verdict{metav1.ConditionTrue, ratelimitv1.ReasonRulesCompiled}),
						ratelimitv1.ConditionReady:    Equal(verdict{metav1.ConditionTrue, ratelimitv1.ReasonAllReplicas}),
						ratelimitv1.ConditionStalled:  Equal(verdict{metav1.ConditionFalse, ratelimitv1.ReasonProgressing}),
					})),
					HaveEach(HaveField("ObservedGeneration", reconciled.Generation)),
				),
				// The fraction the printer columns show, written by the API
				// server rather than by a fake. The REPLICAS column reads
				// Summary, because a printer column is a JSONPath expression
				// and JSONPath cannot join two numbers into a fraction.
				"Replicas": gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
					"Total":         Equal(int32(3)),
					"Applied":       Equal(int32(3)),
					"Summary":       Equal("3/3"),
					"LastCheckTime": Not(BeNil()),
				}),
			}))

			By("keeping the spec out of the status subresource")
			Expect(reconciled.Spec.Domain).To(Equal("gateway.public"))
		})

		// A generation the author cannot see refused anywhere else. The condition
		// says the same thing, but nobody watches conditions on an object they
		// have already applied. A reconcile runs on its interval whether or not
		// anything moved, so the Warning is raised once per generation rather
		// than once per reconcile. The recorder writes to its channel before
		// Reconcile returns, so the events are read without a wait.
		It("raises one Warning per generation that does not compile", func() {
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.events"}
			broken := policyWith(name.Name, blockWith("api", predicateRule("per-plan",
				ratelimitv1.Predicate{Key: "plan", Operator: ratelimitv1.OperatorExists})))
			Expect(create(broken)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			Expect(recorded(recorder)).To(ConsistOf(SatisfyAll(
				HavePrefix("Warning "+ratelimitv1.ReasonNotCompiled+" generation 1 "),
				ContainSubstring(ratelimitv1.ProblemUnresolvedKeyReference),
			)), "the events of the first reconcile of generation 1")

			By("staying quiet while the same generation keeps failing")
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			Expect(recorded(recorder)).To(BeEmpty(), "the events of the second reconcile of generation 1")

			By("raising it again for the next generation")
			Expect(k8sClient.Get(ctx, name, broken)).To(Succeed())
			broken.Spec.Limits[0].Rules[0].Matches[0].Key = "tier"
			Expect(k8sClient.Update(ctx, broken)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			Expect(recorded(recorder)).To(ConsistOf(HavePrefix("Warning "+ratelimitv1.ReasonNotCompiled+" generation 2 ")),
				"the events of the first reconcile of generation 2")
		})

		It("stays quiet on a generation that compiles", func() {
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.quiet"}
			Expect(create(policyWith(name.Name, blockWith("api", ruleWith("total"))))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			Expect(recorded(recorder)).To(BeEmpty(), "the events of a reconcile of a generation that compiles")
		})

		It("forgets the series of a deleted policy", func() {
			// The reconcile of a policy that is gone is the only place the
			// leader learns to stop reporting it. Without this an alert on a
			// stalled domain fires forever on an object nobody can fix.
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.retired"}
			Expect(create(policyWith(name.Name, blockWith("api", ruleWith("total"))))).To(Succeed())
			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			Expect(scrapedDomains()).To(ContainElement(name.Name),
				"the domains of ratelimit_policy_replicas while the policy exists")

			Expect(k8sClient.Delete(ctx, policyWith(name.Name))).To(Succeed())
			_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())
			Expect(scrapedDomains()).NotTo(ContainElement(name.Name),
				"the domains of ratelimit_policy_replicas once the policy is deleted")
		})

		It("writes the rule problems the API server accepts", func() {
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.private"}
			Expect(create(policyWith(name.Name, blockWith("api", predicateRule("per-plan",
				ratelimitv1.Predicate{
					Key:      "plan",
					Operator: ratelimitv1.OperatorExists,
				}))))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			reconciled := &ratelimitv1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"RuleProblems": HaveExactElements(HaveField("Reason", ratelimitv1.ProblemUnresolvedKeyReference)),
				"Problems":     Equal(int32(1)),
				// A generation with a blocking problem enforces nothing.
				"ActiveGeneration": BeZero(),
				"Conditions": WithTransform(verdicts, gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{
					ratelimitv1.ConditionAccepted: Equal(verdict{metav1.ConditionFalse, ratelimitv1.ReasonCompilationFailed}),
					ratelimitv1.ConditionStalled:  Equal(verdict{metav1.ConditionTrue, ratelimitv1.ReasonNotCompiled}),
				})),
			}))
		})

		// A structural mistake in a long Template route quotes the whole
		// template in its message, past the 1024 characters the CRD allows a
		// rule problem. Written as compiled, the status write is refused, on
		// every retry, and the author sees no condition and no problem at all.
		It("writes a rule problem whose message the CRD would refuse whole", func() {
			name := types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.long"}
			template := "/" + strings.Repeat("segment/", 130) + "/{id}"
			Expect(len(template)).To(BeNumerically(">", ratelimitv1.MaxRuleProblemMessage), "the length of the template")
			block := blockWith("api", ruleWith("total"))
			block.Target = &ratelimitv1.Target{Routes: []ratelimitv1.Route{{
				Path: ratelimitv1.PathMatch{Type: ratelimitv1.PathMatchTemplate, Value: template},
			}}}
			Expect(create(policyWith(name.Name, block))).To(Succeed())

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
			Expect(err).NotTo(HaveOccurred())

			reconciled := &ratelimitv1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
			Expect(reconciled.Status).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"Conditions": WithTransform(verdicts, HaveKeyWithValue(ratelimitv1.ConditionAccepted,
					verdict{metav1.ConditionFalse, ratelimitv1.ReasonCompilationFailed})),
				// The message quoting the template, cut to the bound.
				"RuleProblems": ContainElement(HaveField("Message",
					WithTransform(utf8.RuneCountInString, Equal(ratelimitv1.MaxRuleProblemMessage)))),
			}))
		})

		It("does not requeue a policy that is already gone", func() {
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Namespace: envtestNamespace, Name: "gateway.absent"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
		})
	})
})

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

// The reads of this kind all have to ask for the unstructured form, because
// that is the only informer the process runs. Against a plain client - which
// is what the rest of this file uses - a typed read works just as well, so the
// mistake is invisible: it surfaces only against a cache configured the way
// the real manager configures it, as a component that starts cleanly and never
// reconciles anything. So this manager is built from the same functions the
// binary calls, and started, which is what makes ReaderFailOnMissingInformer
// mean something here.
var _ = Describe("the manager's cache", Ordered, func() {
	const cached = "cache.probe"
	var managerUnderTest ctrl.Manager

	BeforeAll(func() {
		// The spec of SetupWithManager registers a controller of this name on
		// its own manager, and the name registry is global to the process.
		skipNameValidation := true
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:     clientgoscheme.Scheme,
			Metrics:    metricsserver.Options{BindAddress: "0"},
			Client:     ClientOptions(),
			Cache:      CacheOptions(envtestNamespace),
			Controller: config.Controller{SkipNameValidation: &skipNameValidation},
		})
		Expect(err).NotTo(HaveOccurred())

		// Registered, not just built. ByObject only configures an informer;
		// what creates one is a caller asking for it, which in the binary is
		// this registration and the configuration writer. A manager with no
		// controller on it would fail these reads for a reason the binary
		// does not have.
		Expect((&RateLimitPolicyReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Service: "ratelimit",
		}).SetupWithManager(mgr)).To(Succeed())

		started, stop := context.WithCancel(context.Background())
		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(started)).To(Succeed())
		}()
		DeferCleanup(stop)
		Expect(mgr.GetCache().WaitForCacheSync(started)).To(BeTrue())

		// What the configuration writer does on every replica, and the step
		// that actually creates the informer: ByObject only configures one.
		_, err = mgr.GetCache().GetInformer(started, policy.Object())
		Expect(err).NotTo(HaveOccurred())

		// A policy has to exist for these reads to distinguish anything: a
		// failed list and an empty namespace both come back with nothing.
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: envtestNamespace}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(context.Background(), ns))).To(Succeed())
		probe := policyWith(cached, blockWith("b", ruleWith("r")))
		Expect(k8sClient.Create(context.Background(), probe)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(context.Background(), probe))).To(Succeed())
		})
		// The wait reads the manager's cache, which the specs read, and not the
		// API server: a policy the API server already returns can still be on
		// its way to the informer, and a spec that lists the cache then finds
		// nothing.
		Eventually(func(g Gomega) {
			list := policy.ObjectList()
			g.Expect(mgr.GetCache().List(started, list, client.InNamespace(envtestNamespace))).To(Succeed())
			names := make([]string, 0, len(list.Items))
			for i := range list.Items {
				names = append(names, list.Items[i].GetName())
			}
			g.Expect(names).To(ContainElement(cached), "the policies in the manager's cache")
		}).Should(Succeed(), "waiting for the manager's cache to hold policy %s", cached)

		managerUnderTest = mgr
	})

	It("serves the policies the compiler loads", func() {
		// policy.Load is the read every rebuild and every reconcile goes
		// through.
		input, err := policy.Load(context.Background(), managerUnderTest.GetCache(), envtestNamespace)

		Expect(err).NotTo(HaveOccurred(), "policy.Load through the manager's cache")
		Expect(input.Policies).To(ContainElement(HaveField("ObjectMeta.Name", cached)),
			"the policies policy.Load read through the manager's cache")
	})

	It("serves the list an EndpointSlice change fans out from", func() {
		reconciler := &RateLimitPolicyReconciler{
			Client:  managerUnderTest.GetClient(),
			Scheme:  managerUnderTest.GetScheme(),
			Service: "ratelimit",
		}
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: envtestNamespace,
				Name:      "ratelimit-abcde",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "ratelimit"},
			},
		}

		// A read failure is logged and swallowed here, so the assertion is on
		// the requests: the fan-out going quiet is exactly how the bug this
		// pins presented.
		Expect(reconciler.policiesBehind(context.Background(), slice)).
			To(ContainElement(reconcile.Request{NamespacedName: types.NamespacedName{
				Namespace: envtestNamespace, Name: cached,
			}}), "the requests of the EndpointSlice fan-out")
	})
})

// recorded takes the events the recorder holds, oldest first, and leaves it
// empty.
func recorded(recorder *events.FakeRecorder) []string {
	var taken []string
	for {
		select {
		case event := <-recorder.Events:
			taken = append(taken, event)
		default:
			return taken
		}
	}
}

// scrapedDomains names the domains the leader's own series currently carry.
func scrapedDomains() []string {
	families, err := ctrlmetrics.Registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	var domains []string
	for _, family := range families {
		if family.GetName() != "ratelimit_policy_replicas" {
			continue
		}
		for _, m := range family.GetMetric() {
			for _, label := range m.GetLabel() {
				if label.GetName() == "domain" {
					domains = append(domains, label.GetValue())
				}
			}
		}
	}
	return domains
}

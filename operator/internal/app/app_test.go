package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/operator/internal/config"
	operatorpolicy "github.com/netcracker/qubership-ratelimit/operator/internal/policy"
)

const testNamespace = "ratelimit-app-envtest"

// conditionsOf reads the status conditions of the policy, or none while the
// policy cannot be read.
func conditionsOf(key client.ObjectKey) func() []metav1.Condition {
	return func() []metav1.Condition {
		var got v1.RateLimitPolicy
		if err := k8sClient.Get(ctx, key, &got); err != nil {
			return nil
		}
		return got.Status.Conditions
	}
}

// readyWithReason matches a Ready condition that carries the reason.
func readyWithReason(reason string) OmegaMatcher {
	return ContainElement(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
		"Type":   Equal(v1.ConditionReady),
		"Reason": Equal(reason),
	}))
}

// createPolicy creates a policy of one rule in its own domain and deletes it
// when the spec ends.
func createPolicy(domain string, matches ...v1.Predicate) *v1.RateLimitPolicy {
	object := &v1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: domain},
		Spec: v1.RateLimitPolicySpec{Domain: domain, Limits: []v1.LimitBlock{{
			Name: "a", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: 1, PeriodSeconds: 60}},
				Matches: matches}}}}},
	}
	Expect(k8sClient.Create(ctx, object)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed()) })
	return object
}

// Build against a real API server. What it proves is that the operator's
// parts fit together as wired: both controllers register, the store is the
// status reconciler's reader, and a started manager writes the namespace's
// ConfigMap and a policy's status without anything else running.
//
// One Build per process: controller names are registered globally, so every
// spec here reads the one manager the container builds and starts, with no
// POD_NAME and the election on: the run outside a pod that a local start is.
// The lock is controller-runtime's own then, and it needs the namespace it
// cannot read from a pod that is not there. The specs keep their order,
// because the spec that looks for the ConfigMap at start has to run before
// any other spec creates a policy.
var _ = Describe("the operator, built without a Deployment to adopt", Ordered, ContinueOnFailure, func() {
	var (
		warnings  []string
		probeAddr string
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, ns))).To(Succeed())

		// The health probes on a port of their own: the readyz answer is part
		// of what is built.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		probeAddr = listener.Addr().String()
		Expect(listener.Close()).To(Succeed())

		GinkgoT().Setenv("POD_NAME", "")
		mgr, err := Build(cfg, scheme.Scheme, testNamespace, Options{
			ProbeAddr: probeAddr, MetricsAddr: "0", Deployment: "ratelimit-operator", Version: "0.0.0-test",
			LeaderElection: true,
			Log:            logf.Log,
			Warn: func(format string, args ...any) {
				warnings = append(warnings, fmt.Sprintf(format, args...))
			},
		})
		Expect(err).NotTo(HaveOccurred())

		runCtx, stop := context.WithCancel(ctx)
		DeferCleanup(stop)
		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(runCtx)).To(Succeed())
		}()
		Expect(mgr.GetCache().WaitForCacheSync(runCtx)).To(BeTrue())
	})

	It("writes the ConfigMap at start, before any policy exists", func() {
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: contract.ConfigMapName},
				&corev1.ConfigMap{})
		}).WithTimeout(20*time.Second).Should(Succeed(), "the writer to write the empty manifest at start")
	})

	It("warns that the Deployment to adopt is missing", func() {
		Expect(warnings).To(ContainElement(ContainSubstring("written without an owner")))
	})

	It("warns that the lease is signed with the hostname", func() {
		Expect(warnings).To(ContainElement(ContainSubstring("POD_NAME")))
	})

	It("writes the payload of a policy into the ConfigMap", func() {
		createPolicy("gateway.app")

		Eventually(func() map[string][]byte {
			var object corev1.ConfigMap
			if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: contract.ConfigMapName},
				&object); err != nil {
				return nil
			}
			return object.BinaryData
		}).WithTimeout(20*time.Second).Should(HaveKey("gateway.app.json.gz"),
			"the writer to put the payload of gateway.app into the ConfigMap")
	})

	// No Service exists here, so the status reconciler finds no replica.
	It("reports NoReplicas on a policy while no Service exists", func() {
		object := createPolicy("gateway.status")

		Eventually(conditionsOf(client.ObjectKeyFromObject(object))).WithTimeout(20*time.Second).
			Should(readyWithReason(v1.ReasonNoReplicas), "the Ready condition of gateway.status to carry NoReplicas")
	})

	// The writer as built reports a lost last-good generation as an event: a
	// saved generation this build does not compile, under a latest one that
	// does not compile either, ends in a Warning on the policy.
	It("reports a lost last-good generation as a Warning event", func() {
		lost := createPolicy("gateway.lost", v1.Predicate{Key: "ghost", Operator: v1.OperatorExists})
		// The save goes in once the manager's cache holds the policy: a writer
		// that reconciles the saved object before it sees the policy drops the
		// generation of a domain it does not know, with no outcome to report.
		Eventually(conditionsOf(client.ObjectKeyFromObject(lost))).WithTimeout(20*time.Second).
			Should(readyWithReason(v1.ReasonNotCompiled), "the Ready condition of gateway.lost to carry NotCompiled")
		store := config.New(k8sClient, testNamespace, nil, "0.0.0-test", logf.Log)
		saved := map[string]operatorpolicy.Bundle{"gateway.lost": {
			UID: string(lost.UID), GoodGeneration: 1, GoodSpec: lost.Spec,
		}}
		lostEvents := func() []string {
			var list eventsv1.EventList
			if err := k8sClient.List(ctx, &list, client.InNamespace(testNamespace)); err != nil {
				return nil
			}
			var notes []string
			for _, e := range list.Items {
				if e.Reason == config.ReasonLastGoodLost && e.Regarding.Name == lost.Name {
					notes = append(notes, e.Type+": "+e.Note)
				}
			}
			return notes
		}

		// A pass of the writer that read the ConfigMap before this save
		// writes it back without the saved generation and reports nothing,
		// so the save repeats until a pass reads it.
		Eventually(func(g Gomega) {
			g.Expect(store.Save(ctx, saved, operatorpolicy.ConfigMapLimit)).To(Succeed())
			g.Eventually(lostEvents).WithTimeout(5*time.Second).Should(ContainElement(
				ContainSubstring("Warning: last-good generation 1 does not compile with this operator build")),
				"a LastGoodLost event on gateway.lost")
		}).WithTimeout(30*time.Second).Should(Succeed(), "the writer to report the saved generation it dropped")
	})

	It("answers the readiness probe", func() {
		Eventually(func() int {
			resp, err := http.Get("http://" + probeAddr + "/readyz")
			if err != nil {
				return 0
			}
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode
		}).WithTimeout(10*time.Second).Should(Equal(http.StatusOK), "GET /readyz to answer 200")
	})

	// The lease is held, and the scrape says so: ratelimit_leader is what
	// tells a query which pod's status series to read.
	It("marks its scrape as the lease holder's", func() {
		Eventually(func() float64 {
			families, err := ctrlmetrics.Registry.Gather()
			if err != nil {
				return -1
			}
			for _, family := range families {
				if family.GetName() == "ratelimit_leader" && len(family.GetMetric()) == 1 {
					return family.GetMetric()[0].GetGauge().GetValue()
				}
			}
			return -1
		}).WithTimeout(20*time.Second).Should(Equal(1.0), "ratelimit_leader to be 1, or -1 while it is not exported")
	})
})

var _ = Describe("the operator, not built", func() {
	It("fails on a config no manager can be made from", func() {
		bad := *cfg
		bad.Host = "://not-a-url"
		_, err := Build(&bad, scheme.Scheme, testNamespace, Options{MetricsAddr: "0", ProbeAddr: "0", Log: logf.Log})
		Expect(err).To(MatchError(ContainSubstring("create manager")))
	})
})

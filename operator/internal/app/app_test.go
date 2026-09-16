package app

import (
	"context"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

const testNamespace = "ratelimit-app-envtest"

// Build against a real API server. What it proves is that the operator's
// parts fit together as wired: both controllers register, the store is the
// status reconciler's reader, and a started manager writes the namespace's
// ConfigMap and a policy's status without anything else running.
var _ = Describe("the operator, built", Ordered, func() {
	var warnings []string

	BeforeAll(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, ns))).To(Succeed())
	})

	// One Build per process: controller names are registered globally, so
	// the construction and the run are one spec.
	It("builds without a Deployment to adopt, and runs both controllers", func() {
		// The health probes on a port of their own: the readyz answer is part
		// of what is built.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		probeAddr := listener.Addr().String()
		Expect(listener.Close()).To(Succeed())

		mgr, err := Build(cfg, scheme.Scheme, testNamespace, Options{
			ProbeAddr: probeAddr, MetricsAddr: "0", Deployment: "ratelimit-operator", Version: "0.0.0-test",
			Log:  logf.Log,
			Warn: func(format string, args ...any) { warnings = append(warnings, format) },
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(mgr).NotTo(BeNil())
		Expect(warnings).To(ContainElement("%v"), "the missing Deployment is a warning, not a refusal to build")

		runCtx, cancel := context.WithCancel(ctx)
		DeferCleanup(cancel)
		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(runCtx)).To(Succeed())
		}()
		Expect(mgr.GetCache().WaitForCacheSync(runCtx)).To(BeTrue())

		// The kick at start: a ConfigMap before any policy.
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: contract.ConfigMapName},
				&corev1.ConfigMap{})
		}).WithTimeout(20*time.Second).Should(Succeed(), "the writer did not write the empty manifest at start")

		policy := &v1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "gateway.app"},
			Spec: v1alpha1.RateLimitPolicySpec{Domain: "gateway.app", Limits: []v1alpha1.LimitBlock{{
				Name: "a", Rules: []v1alpha1.Rule{{Name: "total", Rates: []v1alpha1.Rate{{Requests: 1, PeriodSeconds: 60}}}}}}},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed()) })

		// Both controllers: the writer puts the payload in the object, the
		// status reconciler reports NoReplicas, since no Service exists here.
		Eventually(func() []string {
			var object corev1.ConfigMap
			if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: contract.ConfigMapName}, &object); err != nil {
				return nil
			}
			keys := make([]string, 0, len(object.BinaryData))
			for k := range object.BinaryData {
				keys = append(keys, k)
			}
			return keys
		}).WithTimeout(20 * time.Second).Should(ContainElement("gateway.app.json.gz"))
		Eventually(func() string {
			var got v1alpha1.RateLimitPolicy
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), &got); err != nil {
				return ""
			}
			for _, c := range got.Status.Conditions {
				if c.Type == v1alpha1.ConditionReady {
					return c.Reason
				}
			}
			return ""
		}).WithTimeout(20 * time.Second).Should(Equal(v1alpha1.ReasonNoReplicas))

		// And the probes answer.
		Eventually(func() int {
			resp, err := http.Get("http://" + probeAddr + "/readyz")
			if err != nil {
				return 0
			}
			defer func() { _ = resp.Body.Close() }()
			return resp.StatusCode
		}).WithTimeout(10 * time.Second).Should(Equal(http.StatusOK))
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

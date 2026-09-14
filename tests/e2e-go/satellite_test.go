//go:build e2e

package e2e

import (
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The composite model, end to end. A composite is one baseline namespace plus
// satellites, each with its own gateway; the component runs in the baseline
// alone, a satellite gets the gateway filters pointed at it, and rules are
// written per composite. What that has to mean in traffic is one budget: a
// request through the baseline's gateway and one through a satellite's are
// charged against the same bucket.
//
// A render check proves the satellite's filters carry the baseline's address.
// Only a gateway in another namespace proves the address works, and only two
// gateways spending one budget prove the model. The satellite namespace, its
// gateways, and the satellite release are set up by the workflow, where the
// rest of the suite's infrastructure lives; the suite finds them through
// E2E_SATELLITE_NAMESPACE and skips without it.
var _ = Describe("a composite: a baseline and a satellite", Ordered, Label("satellite"), func() {
	const (
		// The domain both public gateways send. Rules are per composite, so
		// this is the same domain on purpose, not a coincidence to avoid.
		domain = "gateway.public"

		// The prefix the policy targets and the route serves.
		probePrefix = "/e2e-satellite"

		// Two requests an hour, so the third request of the hour is refused
		// whichever gateway it enters by, and the window never reopens during
		// the run.
		limit = 2
	)
	var (
		applied bool

		// probePath is one path under probePrefix per run. The counter is keyed
		// by path and the window is an hour, and deleting the policy does not
		// clear a counter in Redis: a second run inside the hour on the same
		// store would be refused on its first request. A fresh path is a fresh
		// bucket. The route serves it because PathPrefix matches the segment,
		// and the rule counts it because Prefix matches the string.
		probePath = probePrefix + "/" + strconv.FormatInt(time.Now().Unix(), 10)
	)

	BeforeAll(func() {
		if satellite == "" {
			Skip("E2E_SATELLITE_NAMESPACE is unset; the stand has no satellite namespace")
		}
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
	})

	It("renders the gateway filters in the satellite and nothing else", func() {
		filters := &unstructured.UnstructuredList{}
		filters.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "networking.istio.io", Version: "v1alpha3", Kind: "EnvoyFilterList"})
		Expect(k8s.List(ctx, filters, client.InNamespace(satellite),
			client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"})).To(Succeed())
		Expect(filters.Items).To(HaveLen(2), "one filter per enabled gateway")

		// No component: a satellite that rendered a Deployment would run a
		// second limiter counting in its own store, and the baseline's
		// gateways would be none the wiser.
		owned := client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"}
		var deployments appsv1.DeploymentList
		Expect(k8s.List(ctx, &deployments, client.InNamespace(satellite), owned)).To(Succeed())
		Expect(deployments.Items).To(BeEmpty(), "a satellite rendered a Deployment")
		var services corev1.ServiceList
		Expect(k8s.List(ctx, &services, client.InNamespace(satellite), owned)).To(Succeed())
		Expect(services.Items).To(BeEmpty(), "a satellite rendered a Service")
		var accounts corev1.ServiceAccountList
		Expect(k8s.List(ctx, &accounts, client.InNamespace(satellite), owned)).To(Succeed())
		Expect(accounts.Items).To(BeEmpty(), "a satellite rendered a ServiceAccount")
		var roles rbacv1.RoleList
		Expect(k8s.List(ctx, &roles, client.InNamespace(satellite), owned)).To(Succeed())
		Expect(roles.Items).To(BeEmpty(), "a satellite rendered a Role")
	})

	It("configures the satellite gateway to call the baseline's RLS", func() {
		// Read from Envoy's own config dump rather than from the EnvoyFilter
		// object: the object is what the chart wrote, the dump is what the
		// gateway is actually going to call, and a filter Istio rejected
		// leaves the first in place and the second empty.
		expected := "outbound|9000||ratelimit." + namespace + ".svc.cluster.local"
		Eventually(func() string {
			return rateLimitClusterOfIn(satellite, gatewayPodIn(satellite, "public-gateway").Name)
		}).WithTimeout(time.Minute).WithPolling(5*time.Second).Should(Equal(expected),
			"the satellite gateway is not configured with the baseline's Service")
	})

	It("charges both gateways against one budget", func() {
		// Warmed before the policy exists, so the warm-up probes do not spend
		// the budget the requests below are about to measure.
		waitGatewayServes("public-gateway", probePath)
		waitGatewayServesIn(satellite, "public-gateway", probePath)

		before := storeRebuilds()
		Expect(apply(newPolicy(domain,
			prefixLimits(probePrefix, "per-path", []string{"path"}, limit, 3600)))).To(Succeed())
		applied = true
		waitStoreRebuilt(before)

		// One request through each gateway spends the two the hour allows.
		// The order is the point: the satellite's request has to land in the
		// bucket the baseline's request opened.
		Expect(gatewayGet("public-gateway", probePath, nil)).To(BeNumerically("<", 300),
			"the baseline gateway refused the first request of the hour")
		Expect(gatewayBurstIn(satellite, "public-gateway", probePath, 1, nil)[0]).To(BeNumerically("<", 300),
			"the satellite gateway refused the second request of the hour")

		// The third is refused whichever gateway it enters by. Through the
		// satellite first: a 429 here can only have come from the baseline's
		// RLS, over the address the satellite's filter carries, out of a
		// bucket the baseline's own request helped fill.
		Expect(gatewayBurstIn(satellite, "public-gateway", probePath, 1, nil)[0]).To(Equal(429),
			"the satellite gateway admitted a third request; the two gateways are not sharing a budget")
		Expect(gatewayGet("public-gateway", probePath, nil)).To(Equal(429),
			"the baseline gateway admitted a third request; the two gateways are not sharing a budget")
	})

	It("ignores a policy placed in the satellite", func() {
		// The negative control. A satellite runs no controller and its
		// namespace is outside the baseline's cache, so an object created
		// there is never compiled: nothing writes its status, and no gateway
		// enforces it. A tighter limit on a path of its own is the way to see
		// that - if anything read the object, the third request would be
		// refused.
		//
		// The path shares no prefix with probePath. The engine's Prefix is a
		// string prefix, not the segment prefix of a Gateway API route, so a
		// path under the positive spec's rule would be counted by that rule
		// and refused for the wrong reason.
		const strayPath = "/e2e-stray"
		stray := newPolicy(domain, prefixLimits(strayPath, "stray", []string{"path"}, 1, 3600))
		stray.Namespace = satellite
		Expect(apply(stray)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8s.Delete(ctx, stray))).To(Succeed())
		})

		waitGatewayServesIn(satellite, "public-gateway", strayPath)
		codes := gatewayBurstIn(satellite, "public-gateway", strayPath, 3, nil)
		Expect(codes).NotTo(ContainElement(429),
			"a policy in the satellite affected traffic; something compiled it: %v", codes)

		// And nothing has claimed it. A status would mean a controller saw the
		// object; a 30 s window covers several probe intervals of the
		// baseline's leader, which is the only controller there is.
		Consistently(func() []metav1.Condition {
			var got v1alpha1.RateLimitPolicy
			if err := k8s.Get(ctx, client.ObjectKeyFromObject(stray), &got); err != nil {
				return nil
			}
			return got.Status.Conditions
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(BeEmpty(),
			"a policy in the satellite received a status; a controller is watching that namespace")
	})
})

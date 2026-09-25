//go:build e2e

package e2e

import (
	"fmt"
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

	"github.com/netcracker/qubership-ratelimit/api/contract"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
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

		// Two requests an hour. GCRA rather than a fixed window: a 3600 s fixed
		// window resets at the top of the hour, so a run whose third request
		// crossed hh:00 would have it admitted. GCRA with the default burst
		// admits two at once and then refuses for half an hour, with no
		// calendar boundary for the run to cross.
		limit = 2
	)
	var (
		applied bool

		// probePath is one path under probePrefix per attempt, set in the
		// spec that spends it. The counter is keyed by path and the window
		// is long, and deleting the policy does not clear a counter in Redis:
		// a second run inside the window on the same store, or a
		// --flake-attempts retry of the spec, would be refused on its first
		// request. A fresh path is a fresh bucket. The route serves it because
		// PathPrefix matches the segment, and the rule counts it because
		// Prefix matches the string.
		probePath string
	)

	// hourlyGCRA is prefixLimits with GCRA in place of the fixed window, for
	// the reason on limit above.
	hourlyGCRA := func(prefix, rule string, requests int32) []v1.LimitBlock {
		blocks := prefixLimits(prefix, rule, []string{"path"}, requests, 3600)
		blocks[0].Rules[0].Rates[0].Algorithm = v1.AlgorithmGCRA
		return blocks
	}

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
		// The operator chart renders the filters, and only them; the service
		// chart renders nothing. The objects are listed by each chart's
		// label, since that is what each chart puts on what it renders.
		filters := &unstructured.UnstructuredList{}
		filters.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "networking.istio.io", Version: "v1alpha3", Kind: "EnvoyFilterList"})
		Expect(k8s.List(ctx, filters, client.InNamespace(satellite),
			client.MatchingLabels{"app.kubernetes.io/name": operatorChart})).To(Succeed())
		Expect(filters.Items).To(HaveLen(2), "one filter per enabled gateway")

		// No component: a satellite that rendered a Deployment would run a
		// second limiter counting in its own store, and the baseline's
		// gateways would be none the wiser; a satellite that rendered an
		// operator would write a status nobody reads. Neither chart leaves
		// an account or a Role behind either.
		for _, chart := range []string{operatorChart, serviceChart} {
			owned := client.MatchingLabels{"app.kubernetes.io/name": chart}
			var deployments appsv1.DeploymentList
			Expect(k8s.List(ctx, &deployments, client.InNamespace(satellite), owned)).To(Succeed())
			Expect(deployments.Items).To(BeEmpty(), "a satellite rendered a Deployment of %s", chart)
			var services corev1.ServiceList
			Expect(k8s.List(ctx, &services, client.InNamespace(satellite), owned)).To(Succeed())
			Expect(services.Items).To(BeEmpty(), "a satellite rendered a Service of %s", chart)
			var accounts corev1.ServiceAccountList
			Expect(k8s.List(ctx, &accounts, client.InNamespace(satellite), owned)).To(Succeed())
			Expect(accounts.Items).To(BeEmpty(), "a satellite rendered a ServiceAccount of %s", chart)
			var roles rbacv1.RoleList
			Expect(k8s.List(ctx, &roles, client.InNamespace(satellite), owned)).To(Succeed())
			Expect(roles.Items).To(BeEmpty(), "a satellite rendered a Role of %s", chart)
		}
		var maps corev1.ConfigMapList
		Expect(k8s.List(ctx, &maps, client.InNamespace(satellite))).To(Succeed())
		for _, cm := range maps.Items {
			Expect(cm.Name).NotTo(Equal(contract.ConfigMapName), "a satellite holds a configuration ConfigMap")
		}
	})

	It("configures the satellite gateway to call the baseline's RLS", func() {
		// Read from Envoy's own config dump rather than from the EnvoyFilter
		// object: the object is what the chart wrote, the dump is what the
		// gateway is actually going to call, and a filter Istio rejected
		// leaves the first in place and the second empty.
		expected := fmt.Sprintf("outbound|%d||%s.%s.svc.cluster.local", contract.GRPCPort, contract.ServiceName, namespace)
		Eventually(func() string {
			return rateLimitClusterOfIn(satellite, gatewayPodIn(satellite, "public-gateway").Name)
		}).WithTimeout(time.Minute).WithPolling(5*time.Second).Should(Equal(expected),
			"the satellite gateway is not configured with the baseline's Service")
	})

	It("charges both gateways against one budget", func() {
		// Set here rather than when the tree is built, so that a retry of this
		// spec gets a bucket of its own.
		probePath = probePrefix + "/" + strconv.FormatInt(time.Now().UnixNano(), 10)

		// Warmed before the policy exists, so the warm-up probes do not spend
		// the budget the requests below are about to measure.
		waitGatewayServes("public-gateway", probePath)
		waitGatewayServesIn(satellite, "public-gateway", probePath)

		Expect(apply(newPolicy(domain, hourlyGCRA(probePrefix, "per-path", limit)))).To(Succeed())
		applied = true
		waitApplied(domain)

		// One request through each gateway spends the two the window allows.
		// The order is the point: the satellite's request has to land in the
		// bucket the baseline's request opened.
		Expect(gatewayGet("public-gateway", probePath, nil)).To(BeNumerically("<", 300),
			"the first request of the window did not pass through the baseline gateway")
		Expect(gatewayGetIn(satellite, "public-gateway", probePath, nil)).To(BeNumerically("<", 300),
			"the second request of the window did not pass through the satellite gateway")

		// The third is refused whichever gateway it enters by. Through the
		// satellite first: a 429 here can only have come from the baseline's
		// RLS, over the address the satellite's filter carries, out of a
		// bucket the baseline's own request helped fill.
		Expect(gatewayGetIn(satellite, "public-gateway", probePath, nil)).To(Equal(429),
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
		// The path lies outside probePrefix: a path under it would be counted
		// by the positive spec's rule and refused for the wrong reason.
		const strayPath = "/e2e-stray"
		stray := newPolicy(domain, hourlyGCRA(strayPath, "stray", 1))
		stray.Namespace = satellite
		Expect(apply(stray)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8s.Delete(ctx, stray))).To(Succeed())
		})

		waitGatewayServesIn(satellite, "public-gateway", strayPath)
		// The claim is that the traffic passed, so that is what is asserted:
		// not-429 would hold for three 503s or three transport errors too.
		codes := gatewayBurstIn(satellite, "public-gateway", strayPath, 3, nil)
		Expect(codes).To(HaveEach(BeNumerically("<", 300)),
			"a policy in the satellite affected traffic, or the path did not pass; something compiled it: %v", codes)

		// And nothing has claimed it. A status would mean a controller saw the
		// object; a 30 s window covers several probe intervals of the
		// baseline's operator, which is the only controller there is.
		// The error is returned, not swallowed: BeEmpty accepts nil, so a
		// Get that failed would otherwise read as "no status".
		Consistently(func() ([]metav1.Condition, error) {
			var got v1.RateLimitPolicy
			if err := k8s.Get(ctx, client.ObjectKeyFromObject(stray), &got); err != nil {
				return nil, err
			}
			return got.Status.Conditions, nil
		}).WithTimeout(30*time.Second).WithPolling(5*time.Second).Should(BeEmpty(),
			"a policy in the satellite received a status; a controller is watching that namespace")
	})
})

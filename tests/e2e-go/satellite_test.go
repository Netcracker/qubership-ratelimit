//go:build e2e

package e2e

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A composite is one baseline namespace plus satellites, each with its own
// gateway, and the component runs in the baseline alone. The chart's satellite
// mode renders the gateway filters and nothing else, pointing them at the
// baseline's Service by its fixed name. A render check proves the address is
// written; only a gateway in another namespace proves that the address works:
// that a satellite's Envoy reaches the baseline's RLS across the namespace
// boundary, and that one policy in the baseline governs both gateways.
//
// The satellite namespace, its gateways, and the satellite release are set up
// by the workflow, which is where the other infrastructure of the suite
// already lives. The suite finds them through E2E_SATELLITE_NAMESPACE and
// skips without it, so a local run against a plain stand still passes.
var _ = Describe("a satellite namespace of a composite", Ordered, Label("satellite"), func() {
	const (
		// The domain the public gateways of both namespaces send. It is the
		// same domain on purpose: rules are written per composite, and the
		// counter the satellite's traffic lands in is the baseline's.
		domain    = "gateway.public"
		probePath = "/e2e-satellite"
		limit     = 2
	)
	var (
		satellite string
		applied   bool
	)

	BeforeAll(func() {
		satellite = os.Getenv("E2E_SATELLITE_NAMESPACE")
		if satellite == "" {
			Skip("E2E_SATELLITE_NAMESPACE is unset; the stand has no satellite namespace")
		}
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
	})

	It("renders the gateway filters and nothing else", func() {
		filters := &unstructured.UnstructuredList{}
		filters.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "networking.istio.io", Version: "v1alpha3", Kind: "EnvoyFilterList"})
		Expect(k8s.List(ctx, filters, client.InNamespace(satellite),
			client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"})).To(Succeed())
		Expect(filters.Items).To(HaveLen(2), "one filter per enabled gateway")

		// The filters have to carry the baseline's Service, by its fixed name
		// and the baseline's namespace: a satellite has nothing else to go on.
		authority := "ratelimit." + namespace + ".svc.cluster.local"
		for _, filter := range filters.Items {
			Expect(filter.Object).To(WithTransform(func(o map[string]any) string {
				u := unstructured.Unstructured{Object: o}
				raw, _ := u.MarshalJSON()
				return string(raw)
			}, ContainSubstring(authority)),
				"filter %s does not point at the baseline's Service", filter.GetName())
		}

		// And no component: a satellite that rendered a Deployment would run
		// a second limiter counting in its own store, with the baseline's
		// gateways none the wiser.
		ratelimitOwned := client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"}
		var deployments appsv1.DeploymentList
		Expect(k8s.List(ctx, &deployments, client.InNamespace(satellite), ratelimitOwned)).To(Succeed())
		Expect(deployments.Items).To(BeEmpty(), "a satellite rendered a Deployment")
		var services corev1.ServiceList
		Expect(k8s.List(ctx, &services, client.InNamespace(satellite), ratelimitOwned)).To(Succeed())
		Expect(services.Items).To(BeEmpty(), "a satellite rendered a Service")
		var accounts corev1.ServiceAccountList
		Expect(k8s.List(ctx, &accounts, client.InNamespace(satellite), ratelimitOwned)).To(Succeed())
		Expect(accounts.Items).To(BeEmpty(), "a satellite rendered a ServiceAccount")
		var roles rbacv1.RoleList
		Expect(k8s.List(ctx, &roles, client.InNamespace(satellite), ratelimitOwned)).To(Succeed())
		Expect(roles.Items).To(BeEmpty(), "a satellite rendered a Role")
	})

	It("has its traffic limited by a policy of the baseline", func() {
		// Warmed before the policy exists, so the warm-up probes do not spend
		// the budget the burst below is about to measure.
		waitGatewayServesIn(satellite, "public-gateway", probePath)

		before := storeRebuilds()
		Expect(apply(newPolicy(domain,
			prefixLimits(probePath, "per-path", []string{"path"}, limit, 3600)))).To(Succeed())
		applied = true
		waitStoreRebuilt(before)

		// The policy lives in the baseline; the requests go through the
		// satellite's own gateway. A 429 here can only have come from the
		// baseline's RLS, reached over the address the satellite's filter
		// carries.
		codes := gatewayBurstIn(satellite, "public-gateway", probePath, limit+2, nil)
		Expect(codes).To(ContainElement(429),
			"the satellite gateway was never refused; its checks are not reaching the baseline: %v", codes)
		Expect(codes[:limit]).NotTo(ContainElement(429),
			"the budget was spent before the burst: %v", codes)
	})

	It("counts the satellite's traffic in the baseline's counter", func() {
		// The same path through the baseline's own gateway is refused at once:
		// the satellite already spent the budget. One domain, one counter, two
		// gateways in two namespaces - which is what a composite means.
		Eventually(func() int {
			return gatewayGet("public-gateway", probePath, nil)
		}).WithTimeout(30*time.Second).WithPolling(2*time.Second).Should(Equal(429),
			"the baseline's gateway admitted a path the satellite had exhausted")
	})
})

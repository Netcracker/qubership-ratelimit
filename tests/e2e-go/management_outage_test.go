//go:build e2e

package e2e

import (
	"net/http"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The management API through a private gateway that fails closed, with the
// counter store down. The gateway checks the API's requests like any others,
// and the policy of its domain here covers every path. The service exempts
// the API's own paths in that domain, so the endpoints that read no counters
// return 200 and the one that reads them returns the service's own RLS-0503.
// Every call to the API used to return the gateway's 503 for as long as the
// store was down, which is the outage an operator diagnoses through it.
//
// CI installs both gateways failing open, where a failed check passes and the
// defect cannot show. The suite switches the private gateway to fail-closed
// for its own duration and puts back what it found.
var _ = Describe("the management API during a store outage", Ordered, Label("management-outage"), func() {
	const (
		domain      = "gateway.private"
		gateway     = "private-gateway"
		route       = "e2e-management-outage"
		basePath    = "/ratelimit/v1"
		controlPath = "/e2e/management-outage"
	)
	var (
		store  counterStore
		viewer map[string]string
	)

	// checks reads ratelimit_checks_total of the domain for one verdict,
	// summed over the replicas.
	checks := func(verdict string) float64 {
		return counterSum(scrapeAllReplicas(), "ratelimit_checks_total",
			map[string]string{"domain": domain, "verdict": verdict})
	}

	BeforeAll(func() {
		port := managementPort()
		if port == 0 {
			Skip("the release runs without management.enabled; the chart renders no management port")
		}
		var ok bool
		if store, ok = releaseCounterStore(); !ok {
			Skip("the namespace carries no " + redisSecretName + " Secret to reach the store through")
		}
		var dep appsv1.Deployment
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: store.namespace, Name: store.service}, &dep); err != nil {
			Skip("the store at " + store.addr + " is not a Deployment this suite can scale")
		}
		viewer = map[string]string{"Authorization": "Bearer " + managementToken("e2e@example.com", "viewer")}

		// Every change below registers its own undo before it is made, so a
		// step that fails halfway is still undone, and one undo that fails
		// does not keep the others from running. They run in reverse order
		// once the container ends, and a retry of the container starts from
		// the state it found the first time.
		release := helmRelease(operatorDeployment())
		failClosed := "gateways.private.failClosed=" + strconv.FormatBool(gatewayFailsClosed(gateway))
		DeferCleanup(func() { helmSet(operatorChart, release, failClosed) })
		helmSet(operatorChart, release, "gateways.private.failClosed=true")

		// One block without a target: every path of the gateway is under a
		// rule that reads the store, the API's own paths included. The limit
		// is far above what the suite sends, so it refuses nothing here.
		DeferCleanup(func() { deletePolicies(domain) })
		Expect(apply(newPolicy(domain, totalLimits(1000, 60)))).To(Succeed())
		waitApplied(domain)

		DeferCleanup(func() { _ = k8s.Delete(ctx, managementRoute(route, basePath, port)) })
		Expect(apply(managementRoute(route, basePath, port))).To(Succeed())

		// Both paths are served while the store is up: the control path by the
		// echo backend, the API with a listing that carries the domain. A 503
		// after this point is the outage, not a route that never arrived.
		waitGatewayServes(gateway, controlPath)
		Eventually(func() []string {
			body, code := gatewayGetBody(gateway, basePath+"/domains", viewer)
			if code != http.StatusOK {
				return nil
			}
			domains, _ := listedDomains(body)
			return domains
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(ContainElement(domain),
			"the private gateway never served a listing with %s through %s", domain, basePath)

		// Registered last, so the store comes back first: a suite that leaves
		// Redis at zero would fail every container after it.
		DeferCleanup(func() { store.scale(1) })
	})

	It("refuses the gateway's other traffic once the store is down", func() {
		unavailable := checks("unavailable")
		store.scale(0)

		// The control: the gateway fails closed and the store is down, so a
		// path the policy covers is refused. Without it the two specs on the
		// API's own paths would pass against a gateway that fails open.
		Eventually(func() int {
			return gatewayGet(gateway, controlPath, nil)
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Equal(http.StatusServiceUnavailable),
			"GET %s through %s, failing closed, with the store down", controlPath, gateway)
		Expect(checks("unavailable")-unavailable).To(BeNumerically(">", 0),
			`ratelimit_checks_total{verdict="unavailable"} of %s did not grow: the 503 is not a failed check`, domain)
	})

	It("serves the endpoints that read no counters", func() {
		exempt := checks("exempt")

		// Eventually, not once: the gateway gives a check 50 ms, and one that
		// is slow on a loaded runner is a 503 under fail-closed as well.
		for _, path := range []string{"/status", "/domains", "/domains/" + domain + "/rules", "/openapi.yaml"} {
			Eventually(func() int {
				_, code := gatewayGetBody(gateway, basePath+path, viewer)
				return code
			}).WithTimeout(30*time.Second).WithPolling(2*time.Second).Should(Equal(http.StatusOK),
				"GET %s through %s with the store down", basePath+path, gateway)
		}
		Expect(checks("exempt")-exempt).To(BeNumerically(">", 0),
			`ratelimit_checks_total{verdict="exempt"} of %s did not grow: the requests passed some other way`, domain)
	})

	It("returns the service's own RLS-0503 for the counter listing", func() {
		// The gateway's 503 has no such body: the code in it shows that the
		// request reached the service, and that the service named the store.
		counters := basePath + "/domains/" + domain + "/counters"
		Eventually(func(g Gomega) {
			body, code := gatewayGetBody(gateway, counters, viewer)
			g.Expect(code).To(Equal(http.StatusServiceUnavailable), "body: %s", body)
			g.Expect(body).To(ContainSubstring("RLS-0503"))
		}).WithTimeout(30*time.Second).WithPolling(2*time.Second).Should(Succeed(),
			"GET %s through %s with the store down", counters, gateway)
	})
})

// gatewayFailsClosed reads failure_mode_deny from the rate limit filter the
// operator chart rendered for the gateway.
func gatewayFailsClosed(gateway string) bool {
	filters := &unstructured.UnstructuredList{}
	filters.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "networking.istio.io", Version: "v1alpha3", Kind: "EnvoyFilterList"})
	Expect(k8s.List(ctx, filters, client.InNamespace(namespace),
		client.MatchingLabels{"app.kubernetes.io/name": operatorChart})).To(Succeed())
	for _, filter := range filters.Items {
		refs := list(walk(filter.Object, "spec"), "targetRefs")
		if len(refs) != 1 || str(refs[0], "name") != gateway {
			continue
		}
		for _, patch := range list(walk(filter.Object, "spec"), "configPatches") {
			if str(patch, "applyTo") == "HTTP_FILTER" {
				deny, _ := walk(patch, "patch", "value", "typed_config", "failure_mode_deny").(bool)
				return deny
			}
		}
		Fail("the filter of " + gateway + " carries no HTTP_FILTER patch")
	}
	Fail("no rate limit filter targets the gateway " + gateway)
	return false
}

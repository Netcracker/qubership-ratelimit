//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The failure mode under a dead counter store. The chart installs the filter
// with failClosed=false, so a store outage must widen into admitted traffic,
// not refusals - and the exposure must be visible: unavailable verdicts and
// store errors, not a quiet pass. When the store returns, the limits bite
// again without anyone touching the service.
var _ = Describe("fail-open with the store down", Ordered, Label("failopen"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-redis"
	)
	var (
		applied bool
		store   counterStore
	)

	scaleRedis := func(replicas int32) { store.scale(replicas) }

	BeforeAll(func() {
		var ok bool
		if store, ok = releaseCounterStore(); !ok {
			Skip("the namespace carries no " + redisSecretName + " Secret to reach the store through")
		}
		var dep appsv1.Deployment
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: store.namespace, Name: store.service}, &dep); err != nil {
			addr := store.addr
			store = counterStore{}
			Skip("the store at " + addr + " is not a Deployment this suite can scale")
		}

		if !applied {
			applied = true
			waitGatewayServes("public-gateway", probePath)
			// Far above the burst: every probe is an admission, and every
			// admission is a store roundtrip - which is all this suite needs.
			Expect(apply(newPolicy(domain,
				prefixLimits(probePath, "total", nil, 1000, 60)))).To(Succeed())
			waitApplied(domain)
		}
	})
	AfterAll(func() {
		// The store comes back whatever happened above; a suite that leaves
		// Redis at zero would fail everything after it. It comes back first:
		// the cleanup wait below can fail, and nothing after a failed step in
		// this closure runs.
		if store.service != "" {
			scaleRedis(1)
		}
		if applied {
			deletePolicies(domain)
		}
	})

	It("admits traffic while the store is down, visibly", func() {
		before := scrapeAllReplicas()
		scaleRedis(0)

		// The gateway must keep admitting - fail-open - while the service
		// reports what is happening: unavailable verdicts and store errors.
		unavailable := map[string]string{"domain": domain, "verdict": "unavailable"}
		storeErrors := map[string]string{"domain": domain}
		Eventually(func(g Gomega) {
			g.Expect(gatewayBurst("public-gateway", probePath, 2, nil)).To(HaveEach(beAdmitted()),
				"a burst through public-gateway with the store down")
			after := scrapeAllReplicas()
			g.Expect(counterSum(after, "ratelimit_checks_total", unavailable)-
				counterSum(before, "ratelimit_checks_total", unavailable)).To(BeNumerically(">", 0),
				`growth of ratelimit_checks_total{domain=%q,verdict="unavailable"}`, domain)
			g.Expect(counterSum(after, "ratelimit_store_errors_total", storeErrors)-
				counterSum(before, "ratelimit_store_errors_total", storeErrors)).To(BeNumerically(">", 0),
				"growth of ratelimit_store_errors_total{domain=%q}", domain)
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
			"the outage did not surface as admitted traffic with unavailable verdicts and store errors")
	})

	It("counts against the store again once it returns", func() {
		mid := scrapeAllReplicas()
		scaleRedis(1)

		ok := map[string]string{"domain": domain, "verdict": "ok"}
		Eventually(func(g Gomega) {
			g.Expect(gatewayGet("public-gateway", probePath, nil)).To(beAdmitted(),
				"GET %s through public-gateway after the store returned", probePath)
			after := scrapeAllReplicas()
			g.Expect(counterSum(after, "ratelimit_checks_total", ok)-
				counterSum(mid, "ratelimit_checks_total", ok)).To(BeNumerically(">", 0),
				`growth of ratelimit_checks_total{domain=%q,verdict="ok"}`, domain)
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
			"no ok verdict after the store returned; the service did not reconnect")
	})
})

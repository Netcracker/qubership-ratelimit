//go:build e2e

package e2e

import (
	"strings"
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
// again without anyone touching the operator.
var _ = Describe("fail-open with the store down", Ordered, Label("failopen"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-redis"
	)
	var (
		applied         bool
		redisDeployment string
	)

	scaleRedis := func(replicas int32) {
		var dep appsv1.Deployment
		Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: redisDeployment}, &dep)).
			To(Succeed())
		dep.Spec.Replicas = &replicas
		Expect(k8s.Update(ctx, &dep)).To(Succeed())
		Eventually(func() int32 {
			var d appsv1.Deployment
			if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: redisDeployment}, &d); err != nil {
				return -1
			}
			return d.Status.ReadyReplicas
		}).WithTimeout(2*time.Minute).WithPolling(2*time.Second).Should(Equal(replicas),
			"the store deployment never reached %d ready replicas", replicas)
	}

	BeforeAll(func() {
		addresses := redisAddresses()
		if addresses == "" {
			Skip("the release carries no redis.addresses, so it counts in process")
		}
		redisDeployment = strings.SplitN(strings.SplitN(addresses, ",", 2)[0], ":", 2)[0]
		var dep appsv1.Deployment
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: redisDeployment}, &dep); err != nil {
			Skip("the store at " + addresses + " is not a Deployment in this namespace")
		}

		if !applied {
			applied = true
			waitGatewayServes("public-gateway", probePath)
			// Far above the burst: every probe is an admission, and every
			// admission is a store roundtrip - which is all this suite needs.
			before := storeRebuilds()
			Expect(apply(newPolicy(domain,
				prefixLimits(probePath, "total", nil, 1000, 60)))).To(Succeed())
			waitStoreRebuilt(before)
		}
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
		// The store comes back whatever happened above; a suite that leaves
		// Redis at zero would fail everything after it.
		if redisDeployment != "" {
			scaleRedis(1)
		}
	})

	It("admits traffic while the store is down, visibly", func() {
		before := scrapeAllReplicas()
		scaleRedis(0)

		// The gateway must keep admitting - fail-open - while the operator
		// reports what is happening: unavailable verdicts and store errors.
		Eventually(func() bool {
			codes := gatewayBurst("public-gateway", probePath, 2, nil)
			for _, code := range codes {
				if (code < 200 || code > 299) && code != 404 {
					return false
				}
			}
			after := scrapeAllReplicas()
			return counterSum(after, "ratelimit_checks_total",
				map[string]string{"domain": domain, "verdict": "unavailable"})-
				counterSum(before, "ratelimit_checks_total",
					map[string]string{"domain": domain, "verdict": "unavailable"}) > 0 &&
				counterSum(after, "ratelimit_store_errors_total", map[string]string{"domain": domain})-
					counterSum(before, "ratelimit_store_errors_total", map[string]string{"domain": domain}) > 0
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(BeTrue(),
			"the outage did not surface as admitted traffic with unavailable verdicts and store errors")
	})

	It("enforces again once the store returns", func() {
		mid := scrapeAllReplicas()
		scaleRedis(1)

		Eventually(func() bool {
			code := gatewayGet("public-gateway", probePath, nil)
			if (code < 200 || code > 299) && code != 404 {
				return false
			}
			after := scrapeAllReplicas()
			return counterSum(after, "ratelimit_checks_total",
				map[string]string{"domain": domain, "verdict": "ok"})-
				counterSum(mid, "ratelimit_checks_total",
					map[string]string{"domain": domain, "verdict": "ok"}) > 0
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(BeTrue(),
			"no ok verdict after the store returned; the operator did not reconnect")
	})
})

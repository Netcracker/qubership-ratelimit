//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Everything here is a property the in-process store cannot have, which is
// the only reason this suite exists: that the operator really selected Redis
// rather than falling back to memory, that the counters live in Redis under
// the documented key shape, and - the one that matters - that a budget
// already spent survives the process that spent it.
//
// The release decides whether this runs. An install without redis.addresses
// is a perfectly good install, so this suite skips rather than fails on one.
var _ = Describe("the shared counter store", Ordered, Label("redis"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-redis"
		limit     = 2
	)
	// The counter key carries the policy name, and a counter outlives the
	// object that declared it - that is the property this suite exists to
	// prove. So each run takes a name of its own; reusing one would inherit
	// the previous run's spent budget and fail on its first request.
	var policyName, addresses string

	BeforeAll(func() {
		addresses = redisAddresses()
		if addresses == "" {
			Skip("the release carries no redis.addresses, so it counts in process")
		}
		// The fixture half runs once even across flake retries: the budget is
		// an hour long, so a retry that minted a fresh policy would leave the
		// gateway un-warmable behind the first attempt's spent budget.
		if policyName == "" {
			policyName = fmt.Sprintf("e2e-redis-%d", time.Now().Unix())

			// The gateway is warmed before the policy exists, not after:
			// every warm-up probe would otherwise come out of the budget
			// this suite is about to count. An hour-long window, so a
			// restart straddling a boundary cannot hand the budget back
			// and blame Redis for it.
			waitGatewayServes("public-gateway", probePath)
			since := time.Now()
			Expect(apply(newPolicy(policyName, domain,
				prefixLimits(probePath, "total", nil, limit, "1h")))).To(Succeed())
			waitStoreRebuilt(since)
		}
	})
	AfterAll(func() {
		if policyName != "" {
			deletePolicies(policyName)
		}
	})

	It("selected Redis rather than falling back", func() {
		// A wrong address, an unreachable host or a typo in the values would
		// leave the operator counting in memory, and every limit would still
		// look enforced on one replica. The startup line tells the two apart.
		var backend string
		for _, pod := range operatorPods() {
			for _, line := range strings.Split(podLogs(pod.Name, nil), "\n") {
				if strings.Contains(line, "counter store selected backend=") {
					backend = line
				}
			}
			if backend != "" {
				break
			}
		}
		Expect(backend).To(ContainSubstring("redis"),
			"the operator did not select the Redis store (startup said: %q)", backend)
	})

	It("enforces a declared limit through the shared store", func() {
		// The budget is spent deliberately, one request at a time, so the
		// count in Redis is a number this test chose rather than whatever a
		// burst happened to land.
		for i := 1; i <= limit; i++ {
			Expect(gatewayGet("public-gateway", probePath, nil)).NotTo(Equal(429),
				"request %d of the budget was refused; another policy is limiting this path", i)
		}
		Expect(gatewayGet("public-gateway", probePath, nil)).To(Equal(429),
			"the request after the budget was admitted; the limit is not being enforced")
	})

	It("keeps the counter under the documented key", func() {
		// The key carries the policy, block and rule so two policies naming
		// one block cannot share a bucket, and the domain sits in a hash tag
		// so every bucket of one decision lands on a single Cluster slot.
		out, err := redisCli(addresses, "--scan", "--pattern", "rl:*"+policyName+"*")
		if err != nil {
			Skip("no redis-cli reachable through " + addresses)
		}
		var key string
		for _, line := range strings.Split(out, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				key = line
				break
			}
		}
		Expect(key).NotTo(BeEmpty(), "no counter key for %s in Redis", policyName)
		Expect(key).To(ContainSubstring("{"+domain+"}"),
			"the key carries no hash tag for the domain")
		Expect(key).To(ContainSubstring(policyName+"/probe/total"),
			"the key does not carry the policy, block and rule")
	})

	It("keeps a spent budget across an operator restart", func() {
		// This is the whole point of the shared store: an in-process counter
		// is lost with its pod, so the budget would come back.
		since := time.Now()
		rolloutRestart(operatorDeployment())

		// Only the store has to be back, and it is waited for through the
		// rebuild it logs. Probing the gateway here would be worse than
		// useless: the budget is spent, so every probe answers 429 and a
		// warm-up that insists on 2xx would never finish.
		waitStoreRebuilt(since)
		Expect(gatewayGet("public-gateway", probePath, nil)).To(Equal(429),
			"the budget came back after a restart; the counters did not outlive the process")
	})
})

// redisAddresses reads what the release pointed the operator at; empty means
// the install counts in process and this suite has nothing to prove.
func redisAddresses() string {
	var dep appsv1.Deployment
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: operatorDeployment()}, &dep); err != nil {
		return ""
	}
	for _, env := range dep.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "REDIS_ADDRESSES" {
			return env.Value
		}
	}
	return ""
}

// redisCli runs one redis-cli command against the store the operator was
// pointed at. The pod is resolved through the Service the operator dials, so
// the suite works against any Redis the release names rather than one it
// hardcodes.
func redisCli(addresses string, args ...string) (string, error) {
	host := strings.SplitN(addresses, ",", 2)[0]
	host = strings.SplitN(host, ":", 2)[0]
	var svc corev1.Service
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: host}, &svc); err != nil {
		return "", err
	}
	if len(svc.Spec.Selector) == 0 {
		return "", fmt.Errorf("the Service %s carries no selector", host)
	}
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(namespace),
		client.MatchingLabels(svc.Spec.Selector)); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pod behind the Service %s", host)
	}
	return execPod(pods.Items[0].Name, "", append([]string{"redis-cli"}, args...)...)
}

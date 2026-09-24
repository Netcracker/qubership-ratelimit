//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Everything here is a property the in-process store cannot have, which is
// the only reason this suite exists: that the service really selected Redis
// rather than falling back to memory, that the counters live in Redis under
// the documented key shape, and - the one that matters - that a budget
// already spent survives the process that spent it.
//
// The release decides whether this runs: without the counter store's Secret
// in the namespace there is no store this suite can reach, and it skips.
var _ = Describe("the shared counter store", Ordered, Label("redis"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-redis"
		limit     = 2
	)
	// A counter outlives the object that declared it - that is the property
	// this suite exists to prove.
	var (
		applied bool
		store   counterStore
	)

	BeforeAll(func() {
		var ok bool
		if store, ok = releaseCounterStore(); !ok {
			Skip("the namespace carries no " + redisSecretName + " Secret to reach the store through")
		}
		// The fixture half runs once even across flake retries: the budget is
		// an hour long, so a retry that minted a fresh policy would leave the
		// gateway un-warmable behind the first attempt's spent budget.
		if !applied {
			applied = true

			// The gateway is warmed before the policy exists, not after:
			// every warm-up probe would otherwise come out of the budget
			// this suite is about to count. An hour-long window, so a
			// restart straddling a boundary cannot hand the budget back
			// and blame Redis for it.
			waitGatewayServes("public-gateway", probePath)
			Expect(apply(newPolicy(domain,
				prefixLimits(probePath, "total", nil, limit, 3600)))).To(Succeed())
			waitApplied(domain)
		}
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
	})

	It("selected Redis rather than falling back", func() {
		// A wrong address, an unreachable host or a typo in the values would
		// leave the service counting in memory, and every limit would still
		// look enforced on one replica. The startup line tells the two apart.
		var backend string
		for _, pod := range servicePods() {
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
			"the service did not select the Redis store (startup said: %q)", backend)
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
		// Namespace and domain sit together in one hash tag, so every bucket
		// of a decision lands on a single Cluster slot and two installations
		// sharing a store cannot collide. Scanning by that tag proves the
		// grouping; the exact key below proves the rest of the layout.
		tag := "{" + namespace + "/" + domain + "}"
		out, err := store.cli("--scan", "--pattern", "rl:*"+tag+"*")
		if err != nil {
			Skip("no redis-cli reachable through " + store.addr)
		}
		var keys []string
		for _, line := range strings.Split(out, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				keys = append(keys, line)
			}
		}
		Expect(keys).NotTo(BeEmpty(), "no counter key under %s in Redis", tag)

		// The whole documented shape: schema version, the tag, the block and
		// rule - which name a bucket space on their own now that a domain has
		// exactly one policy - then the algorithm and the window. This rule
		// declares no axes, so the key ends there, every segment terminated.
		//
		// Asserted as an exact member rather than as a substring of whichever
		// key came back first: the suites share gateway.public, so a scan of
		// the domain returns their counters too, in whatever order Redis
		// hands them over.
		want := "rl:v1:" + tag + ":probe/total:fixedwindow:3600:"
		Expect(keys).To(ContainElement(want),
			"no counter at the documented key; the domain holds %v", keys)
	})

	It("keeps a spent budget across a service restart", func() {
		// This is the whole point of the shared store: an in-process counter
		// is lost with its pod, so the budget would come back.
		rolloutRestart(serviceDeployment())

		// Only the store has to be back, and it is waited for through the
		// rebuild it logs. Probing the gateway here would be worse than
		// useless: the budget is spent, so every probe answers 429 and a
		// warm-up that insists on 2xx would never finish. The replacement
		// pod starts a fresh log, so its first rebuild line is the signal.
		waitApplied(domain)
		Expect(gatewayGet("public-gateway", probePath, nil)).To(Equal(429),
			"the budget came back after a restart; the counters did not outlive the process")
	})
})

// counterStore is the Redis the release counts in, as the service reads it:
// the connection properties of the Secret its DatabaseSecretClaim
// materializes, or that the e2e workflow writes in the same format where the
// cluster has no DBaaS. The host is <service>.<namespace> for a DBaaS
// database, which lives in the Redis adapter's namespace; a bare name is a
// Service of the release's own namespace.
type counterStore struct {
	addr      string
	service   string
	namespace string
	password  string
}

// redisSecretName is the Secret the service chart mounts: <fullname>-redis,
// and the suites install the chart without a fullnameOverride.
const redisSecretName = "ratelimit-service-redis"

// releaseCounterStore reads where the release counts. false means the release
// carries no connection this suite can reach.
func releaseCounterStore() (counterStore, bool) {
	var secret corev1.Secret
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: redisSecretName}, &secret); err != nil {
		return counterStore{}, false
	}
	var properties struct {
		Host     string          `json:"host"`
		Port     json.RawMessage `json:"port"`
		Password string          `json:"password"`
	}
	if err := json.Unmarshal(secret.Data["connectionProperties.json"], &properties); err != nil || properties.Host == "" {
		return counterStore{}, false
	}
	port := strings.Trim(string(properties.Port), `"`)
	store := counterStore{
		addr:      properties.Host + ":" + port,
		service:   properties.Host,
		namespace: namespace,
		password:  properties.Password,
	}
	if name, rest, ok := strings.Cut(properties.Host, "."); ok {
		store.service = name
		store.namespace, _, _ = strings.Cut(rest, ".")
	}
	return store, true
}

// cli runs one redis-cli command against the store, through a pod behind the
// Service the service dials, so the suite works against any Redis the release
// names rather than one it hardcodes.
func (s counterStore) cli(args ...string) (string, error) {
	var svc corev1.Service
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: s.namespace, Name: s.service}, &svc); err != nil {
		return "", err
	}
	if len(svc.Spec.Selector) == 0 {
		return "", fmt.Errorf("the Service %s/%s carries no selector", s.namespace, s.service)
	}
	var pods corev1.PodList
	if err := k8s.List(ctx, &pods, client.InNamespace(s.namespace),
		client.MatchingLabels(svc.Spec.Selector)); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pod behind the Service %s/%s", s.namespace, s.service)
	}
	command := []string{"redis-cli"}
	if s.password != "" {
		command = append(command, "--no-auth-warning", "-a", s.password)
	}
	return execPodIn(s.namespace, pods.Items[0].Name, "", append(command, args...)...)
}

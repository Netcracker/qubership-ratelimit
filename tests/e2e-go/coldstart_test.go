//go:build e2e

package e2e

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Cold start from the last-good state: the policy suite proves a running pod
// falls back to the persisted generation, this one proves a pod born after
// the bad edit does - the restart path where the only source of the good
// spec is the state ConfigMap, because the live object already carries the
// broken generation.
var _ = Describe("cold start from the last-good state", Ordered, Label("coldstart"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e"
	)

	BeforeAll(func() {
		// The breaking edit below leans on the tenant key being unresolved,
		// so the policy declares no mapping of its own.
		before := storeRebuilds()
		Expect(apply(newPolicy(domain, prefixLimits(probePath, "total", nil, 1, 1)))).
			To(Succeed())
		waitStoreRebuilt(before)
		waitGatewayServes("public-gateway", probePath)
	})
	AfterAll(func() { deletePolicies(domain) })

	It("survives a restart with only the ConfigMap to stand on", func() {
		// The good generation has to reach its ConfigMap before the edit
		// breaks the object - otherwise there is nothing to cold-start from.
		Eventually(func() error {
			return k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "ratelimit-state-" + domain},
				&corev1.ConfigMap{})
		}).Should(Succeed(), "the last-good state was never written")
		Eventually(generations(domain)).Should(WithTransform(
			func(g [2]int64) bool { return g[1] > 0 && g[0] == g[1] }, BeTrue()),
			"the policy never reached an active generation to fall back to")

		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		good := p.Status.ActiveGeneration
		p.Spec.Limits[0].Rules[0].Matches = []v1alpha1.Predicate{{
			Key: "tenant", Operator: v1alpha1.OperatorExists}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(policyCondition(domain, v1alpha1.ConditionReady)).Should(Equal("False"),
			"the breaking edit was not rejected")
		Eventually(generations(domain)).Should(WithTransform(
			func(g [2]int64) bool { return g[0] > good && g[1] == good }, BeTrue()),
			"the last-good generation did not keep running after the edit")

		// The pod that reconciled the edit dies here; its replacement has
		// never seen the good generation except through the ConfigMap.
		rolloutRestart(operatorDeployment())
		waitStoreRebuilt(0)

		rebuilt := ""
		for _, pod := range operatorPods() {
			for _, line := range strings.Split(podLogs(pod.Name, nil), "\n") {
				if strings.Contains(line, "rate limit store rebuilt") {
					rebuilt = line
				}
			}
		}
		Expect(rebuilt).To(ContainSubstring("policiesOnLastGood=1"),
			"the fresh pod does not report a policy running on its last-good state")

		// And the proof that counts: the good spec is enforced, not merely
		// reported - one per second on the probe path, from a pod that
		// learned it from the ConfigMap.
		nextWindow()
		codes := gatewayBurst("public-gateway", probePath, 4, nil)
		Expect(codes[0]).NotTo(Equal(429), "the first request of the burst was refused")
		Expect(codes).To(ContainElement(429),
			"the last-good limit is not enforced after the restart")
	})
})

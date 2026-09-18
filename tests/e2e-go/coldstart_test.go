//go:build e2e

package e2e

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Cold start of the service: what a replica born with nothing but its volume
// does. Without a ConfigMap it stays NotReady and out of the Endpoints, with
// no timeout, because a replica that started serving without a configuration
// would turn a missing operator into traffic without enforcement. With an
// explicitly empty manifest it is Ready and passes every request as an
// unknown domain. And after a broken edit, the ConfigMap holds the last-good
// generation, so a replica born after the edit enforces the good spec it
// never saw on the live object.
//
// The container turns the operator off and on: the ConfigMap is the
// operator's, and it recreates the object within a second, so the only way
// to see a replica without one is to have no operator write it.
var _ = Describe("cold start of the service", Ordered, Label("coldstart"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e"
	)
	var operatorOff bool

	AfterAll(func() {
		if operatorOff {
			scaleDeployment(operatorDeployment(), 1)
		}
		deletePolicies(domain)
	})

	It("stays NotReady and out of the Endpoints without a configuration", func() {
		// No operator, no ConfigMap: the volume is mounted optional and
		// empty, and a replica restarted into it has nothing to apply.
		scaleDeployment(operatorDeployment(), 0)
		operatorOff = true
		cm, err := configMap()
		Expect(err).NotTo(HaveOccurred())
		Expect(k8s.Delete(ctx, cm)).To(Succeed())
		Eventually(func() error { _, err := configMap(); return err }).WithTimeout(30*time.Second).
			ShouldNot(Succeed(), "the ConfigMap is still there with the operator off")

		// The running replicas keep their snapshot and stay Ready through
		// the deletion, by design; what has to fail is a fresh one. The
		// rollout below cannot complete: the replacement never turns Ready,
		// so the wait is on the replacement's state, not on the rollout.
		rolloutRestartNoWait(serviceDeployment())
		Eventually(func(g Gomega) {
			var fresh int
			for _, pod := range servicePods() {
				if !strings.Contains(podLogs(pod.Name, nil), "the replica stays NotReady") {
					continue
				}
				fresh++
				g.Expect(podReady(pod)).To(BeFalse(), "a replica without a configuration turned Ready")
			}
			g.Expect(fresh).To(BeNumerically(">", 0), "no replica has started into the empty volume yet")
		}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())

		// Held, not just observed once: no timeout turns the wait into a
		// serving replica.
		Consistently(func(g Gomega) {
			for _, pod := range servicePods() {
				if strings.Contains(podLogs(pod.Name, nil), "the replica stays NotReady") {
					g.Expect(podReady(pod)).To(BeFalse())
				}
			}
		}).WithTimeout(20 * time.Second).WithPolling(2 * time.Second).Should(Succeed())
		Expect(readyServiceEndpoints()).To(BeNumerically("<=", 1),
			"a replica without a configuration is in the Endpoints")
	})

	It("turns Ready on an explicitly empty manifest, and passes every request", func() {
		// The operator back, and no policy in the namespace: it writes a
		// manifest with zero domains, and that is a configuration.
		scaleDeployment(operatorDeployment(), 1)
		operatorOff = false
		Eventually(func() int {
			m, err := configManifest()
			if err != nil {
				return -1
			}
			return len(m.Domains)
		}).WithTimeout(time.Minute).Should(Equal(0), "the operator did not write the empty manifest")

		Eventually(func(g Gomega) {
			pods := servicePods()
			g.Expect(pods).NotTo(BeEmpty())
			for _, pod := range pods {
				g.Expect(podReady(pod)).To(BeTrue(), "replica %s is not Ready on the empty manifest", pod.Name)
			}
		}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
		waitRolloutSettled(serviceDeployment())

		// Every request passes: the domain the gateway sends is unknown to
		// an empty configuration, and unknown domains are admitted.
		since := time.Now()
		time.Sleep(time.Second)
		waitGatewayServes("public-gateway", probePath)
		Expect(burstClean(probePath)).To(BeTrue(), "requests were refused under an empty configuration")
		Eventually(serviceLogsSince(since)).WithTimeout(30*time.Second).
			Should(ContainSubstring("unknown rate limit domain"),
				"the empty configuration did not answer the checks as an unknown domain")
	})

	It("survives a restart with only the ConfigMap to stand on", func() {
		// The breaking edit below leans on the tenant key being unresolved,
		// so the policy declares no mapping of its own.
		Expect(apply(newPolicy(domain, prefixLimits(probePath, "total", nil, 1, 1)))).To(Succeed())
		waitApplied(domain)

		// The good generation has to reach the ConfigMap before the edit
		// breaks the object; otherwise there is nothing to cold-start from.
		Eventually(generations(domain)).Should(WithTransform(
			func(g [2]int64) bool { return g[1] > 0 && g[0] == g[1] }, BeTrue()),
			"the policy never reached an active generation to fall back to")
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		good := p.Status.ActiveGeneration
		Eventually(manifestGeneration(domain)).Should(Equal(good),
			"the good generation never reached %s", contract.ConfigMapName)

		p.Spec.Limits[0].Rules[0].Matches = []v1alpha1.Predicate{{
			Key: "tenant", Operator: v1alpha1.OperatorExists}}
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(policyCondition(domain, v1alpha1.ConditionReady)).Should(Equal("False"),
			"the breaking edit was not rejected")
		Eventually(generations(domain)).Should(WithTransform(
			func(g [2]int64) bool { return g[0] > good && g[1] == good }, BeTrue()),
			"the last-good generation did not keep running after the edit")
		Consistently(manifestGeneration(domain)).WithTimeout(10*time.Second).Should(Equal(good),
			"the broken generation reached the ConfigMap")

		// The pods that applied the good generation die here; their
		// replacements have never seen it except through the ConfigMap.
		rolloutRestart(serviceDeployment())
		waitApplied(domain)
		for _, pod := range servicePods() {
			report := appliedReport(pod)
			Expect(report.Domains[domain].Generation).To(Equal(good),
				"replica %s does not report the last-good generation from the ConfigMap", pod.Name)
		}

		// And the proof that counts: the good spec is enforced, not merely
		// reported. One per second on the probe path, from a pod that
		// learned it from the ConfigMap.
		nextWindow()
		codes := gatewayBurst("public-gateway", probePath, 4, nil)
		Expect(codes[0]).NotTo(Equal(429), "the first request of the burst was refused")
		Expect(codes).To(ContainElement(429),
			"the last-good limit is not enforced after the restart")
	})
})

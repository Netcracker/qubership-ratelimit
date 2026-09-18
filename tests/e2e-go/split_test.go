//go:build e2e

package e2e

import (
	"encoding/json"
	"math/rand/v2"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The seams of the split: what each half does when the other is missing or
// speaks a format it does not read, and what the one object between them
// survives. Each container turns one half off or damages the object, and
// puts things back on the way out.
var _ = Describe("the seams of the split", Ordered, Label("split"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-split"
	)

	Describe("an operator without a service", Ordered, func() {
		var fleet *fleetScale

		BeforeAll(func() {
			Expect(apply(newPolicy(domain, totalLimits(1000, 60)))).To(Succeed())
			waitApplied(domain)
			Eventually(readyReason(domain)).Should(Equal(v1alpha1.ReasonAllReplicas))
		})
		AfterAll(func() {
			if fleet != nil {
				fleet.restore()
			}
			deletePolicies(domain)
		})

		It("reports NoReplicas, and Ready again once the service is back", func() {
			// The service release at zero replicas: the Service has no ready
			// endpoint, and nothing enforces the policy. The operator says
			// so rather than reporting a fleet of none as whole.
			fleet = scaleFleet(0)
			Eventually(readyReason(domain)).WithTimeout(2*time.Minute).WithPolling(2*time.Second).
				Should(Equal(v1alpha1.ReasonNoReplicas), "the operator did not report the missing service")
			Expect(policyCondition(domain, v1alpha1.ConditionStalled)()).To(Equal("False"),
				"a fleet of none is not stuck; it is absent")
			p, err := getPolicy(domain)
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Status.Replicas.Summary).To(Equal("0/0"))

			// Back, the replicas read the ConfigMap the operator kept writing
			// and take the generation up without a policy event.
			fleet.restore()
			fleet = nil
			Eventually(readyReason(domain)).WithTimeout(propagationTimeout).WithPolling(2*time.Second).
				Should(Equal(v1alpha1.ReasonAllReplicas), "the fleet did not come back: %s", describeReplicas(domain))
		})
	})

	Describe("a manifest the service does not read", Ordered, func() {
		var operatorOff bool

		BeforeAll(func() {
			Expect(apply(newPolicy(domain, prefixLimits(probePath, "total", nil, 1, 1)))).To(Succeed())
			waitApplied(domain)
			Eventually(readyReason(domain)).Should(Equal(v1alpha1.ReasonAllReplicas))
		})
		AfterAll(func() {
			if operatorOff {
				scaleDeployment(operatorDeployment(), 1)
			}
			deletePolicies(domain)
		})

		It("leaves the snapshot in place and reports the refusal", func() {
			// The operator rewrites any change to the object within a second,
			// so a manifest of a format this service does not read has to be
			// written while no operator runs. What a real skew would be is a
			// newer operator; the format version alone is what the service
			// judges, and this is the same refusal.
			scaleDeployment(operatorDeployment(), 0)
			operatorOff = true
			cm, err := configMap()
			Expect(err).NotTo(HaveOccurred())
			var raw map[string]any
			Expect(json.Unmarshal([]byte(cm.Data[contract.ManifestKey]), &raw)).To(Succeed())
			raw["formatVersion"] = manifest.FormatVersion + 100
			tampered, err := json.Marshal(raw)
			Expect(err).NotTo(HaveOccurred())
			cm.Data[contract.ManifestKey] = string(tampered)
			Expect(k8s.Update(ctx, cm)).To(Succeed())

			// Every replica refuses it, says why, and keeps what it applied.
			Eventually(func(g Gomega) {
				for _, pod := range servicePods() {
					report := appliedReport(pod)
					g.Expect(report.Refusal).NotTo(BeNil(), "replica %s reports no refusal", pod.Name)
					g.Expect(report.Refusal.FormatVersion).To(Equal(manifest.FormatVersion + 100))
					g.Expect(report.Refusal.Reason).To(ContainSubstring("unsupported format version"))
					g.Expect(report.Domains).To(HaveKey(domain), "replica %s dropped its snapshot", pod.Name)
					g.Expect(podReady(pod)).To(BeTrue(), "replica %s left Ready over a refusal", pod.Name)
				}
			}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())

			// And enforces it: one per second on the probe path, as before.
			nextWindow()
			codes := gatewayBurst("public-gateway", probePath, 4, nil)
			Expect(codes[0]).NotTo(Equal(429), "the first request of the burst was refused")
			Expect(codes).To(ContainElement(429), "the snapshot is not enforced while the manifest is refused")
		})

		It("is turned into ReplicaFormatUnsupported by the operator, then written over", func() {
			// A replica that refuses a manifest and still enforces the latest
			// generation is whole by the judge, and rightly: the refusal
			// names a cause only for a replica that is behind. So the policy
			// moves a generation while the operator is off, and the operator
			// back compiles it, writes the object in its own format, and
			// probes replicas that report the old generation with the
			// refusal: ReplicaFormatUnsupported, at once and without a
			// deadline. Then the kubelet projects the rewrite, the replicas
			// apply the new generation, the refusals clear, and Ready comes
			// back. The first window is the kubelet's sync, so the poll is
			// fast.
			p, err := getPolicy(domain)
			Expect(err).NotTo(HaveOccurred())
			p.Spec.Limits[0].Rules[0].Rates[0].Requests++
			Expect(k8s.Update(ctx, p)).To(Succeed())

			scaleDeployment(operatorDeployment(), 1)
			operatorOff = false
			Eventually(readyReason(domain)).WithTimeout(time.Minute).WithPolling(200*time.Millisecond).
				Should(Equal(v1alpha1.ReasonReplicaFormatUnsupported),
					"the operator never reported the refusing replicas")
			Expect(policyCondition(domain, v1alpha1.ConditionStalled)()).To(Equal("True"),
				"a replica that will never take the generation up is stuck, not in progress")
			Eventually(func() int {
				m, err := configManifest()
				if err != nil {
					return -1
				}
				return m.FormatVersion
			}).WithTimeout(time.Minute).Should(Equal(manifest.FormatVersion), "the operator did not rewrite the manifest")
			Eventually(readyReason(domain)).WithTimeout(propagationTimeout).WithPolling(time.Second).
				Should(Equal(v1alpha1.ReasonAllReplicas), "Ready did not come back after the rewrite")
			for _, pod := range servicePods() {
				Expect(appliedReport(pod).Refusal).To(BeNil(), "replica %s still reports a refusal", pod.Name)
			}
		})
	})

	Describe("a generation the ConfigMap cannot hold", Ordered, func() {
		const (
			bigA = "gateway.big-a"
			bigB = "gateway.big-b"
		)

		AfterAll(func() { deletePolicies(bigA, bigB) })

		It("reports ConfigMapTooLarge and keeps the last-good generation", func() {
			// Two domains of client lists that each fit their own object but
			// not, compressed together, the 1 MiB of a ConfigMap: a list of
			// random alphanumeric names compresses about 1.3 times, so two
			// of 860 KiB each land past the limit while each policy stays
			// under the API server's own cap of 1.5 MiB.
			Expect(apply(newPolicy(bigA, totalLimits(100, 60)))).To(Succeed())
			Expect(apply(withClients(newPolicy(bigB, totalLimits(100, 60)), bigClients))).To(Succeed())
			waitApplied(bigA, bigB)
			Eventually(readyReason(bigA)).Should(Equal(v1alpha1.ReasonAllReplicas))
			Eventually(readyReason(bigB)).Should(Equal(v1alpha1.ReasonAllReplicas))
			Expect(manifestGeneration(bigA)()).To(Equal(int64(1)))

			// The second generation of A does not fit beside B. A's first
			// generation stays in the object and enforced; B is untouched.
			p, err := getPolicy(bigA)
			Expect(err).NotTo(HaveOccurred())
			withClients(p, bigClients)
			Expect(k8s.Update(ctx, p)).To(Succeed())

			Eventually(readyReason(bigA)).WithTimeout(propagationTimeout).WithPolling(2*time.Second).
				Should(Equal(v1alpha1.ReasonConfigMapTooLarge), "the operator did not refuse the generation for its size")
			Expect(policyCondition(bigA, v1alpha1.ConditionStalled)()).To(Equal("True"),
				"a generation that does not fit is stuck, not in progress")
			Expect(policyCondition(bigA, v1alpha1.ConditionAccepted)()).To(Equal("True"),
				"the generation compiles; it is the size that refuses it")
			Expect(generations(bigA)()).To(Equal([2]int64{2, 1}), "last-good is not the active generation")
			Expect(manifestGeneration(bigA)()).To(Equal(int64(1)), "the generation that does not fit reached the object")
			Expect(readyReason(bigB)()).To(Equal(v1alpha1.ReasonAllReplicas), "the other domain was touched")

			// The object stays within the limit, as read from the API.
			cm, err := configMap()
			Expect(err).NotTo(HaveOccurred())
			total := len(cm.Data[contract.ManifestKey])
			for _, payload := range cm.BinaryData {
				total += len(payload)
			}
			Expect(total).To(BeNumerically("<=", 1<<20), "the ConfigMap is over the limit")
		})
	})

	Describe("a deleted ConfigMap", Ordered, func() {
		BeforeAll(func() {
			Expect(apply(newPolicy(domain, prefixLimits(probePath, "total", nil, 1, 1)))).To(Succeed())
			waitApplied(domain)
			Eventually(readyReason(domain)).Should(Equal(v1alpha1.ReasonAllReplicas))
			waitGatewayServes("public-gateway", probePath)
		})
		AfterAll(func() { deletePolicies(domain) })

		It("is recreated by the operator while the service keeps serving", func() {
			cm, err := configMap()
			Expect(err).NotTo(HaveOccurred())
			Expect(k8s.Delete(ctx, cm)).To(Succeed())

			// Recreated under a new UID, with the namespace's state inside.
			Eventually(func() string {
				fresh, err := configMap()
				if err != nil || fresh.UID == cm.UID {
					return ""
				}
				return string(fresh.UID)
			}).WithTimeout(30*time.Second).WithPolling(time.Second).ShouldNot(BeEmpty(),
				"the operator did not recreate %s", contract.ConfigMapName)
			Expect(manifestGeneration(domain)()).To(Equal(generations(domain)()[1]),
				"the recreated object carries a generation other than the active one")

			// Through it all the replicas stayed Ready on their snapshot and
			// kept enforcing: one per second on the probe path.
			for _, pod := range servicePods() {
				Expect(podReady(pod)).To(BeTrue(), "replica %s left Ready over the deletion", pod.Name)
			}
			nextWindow()
			codes := gatewayBurst("public-gateway", probePath, 4, nil)
			Expect(codes[0]).NotTo(Equal(429), "the first request of the burst was refused")
			Expect(codes).To(ContainElement(429), "the limit is not enforced after the deletion")
			Consistently(readyReason(domain)).WithTimeout(15*time.Second).WithPolling(time.Second).
				Should(Equal(v1alpha1.ReasonAllReplicas), "Ready flickered over a deletion that changed no rule")
		})
	})
})

// bigClients is the size of the client list that puts two policies past the
// ConfigMap limit together and each under the API server's cap alone.
const bigClients = 26000

// withClients gives the policy a group of n random client names and a rule
// that references it, so the payload compresses poorly: the spec on the
// size limit needs bytes gzip cannot fold.
func withClients(p *v1alpha1.RateLimitPolicy, n int) *v1alpha1.RateLimitPolicy {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	clients := make([]string, 0, n)
	name := make([]byte, 32)
	for i := 0; i < n; i++ {
		for j := range name {
			name[j] = alphabet[rand.IntN(len(alphabet))]
		}
		clients = append(clients, string(name))
	}
	p.Spec.Groups = []v1alpha1.ClientGroup{{Name: "tenants", Clients: clients}}
	p.Spec.Limits = append(p.Spec.Limits, v1alpha1.LimitBlock{
		Name: "tenants",
		Rules: []v1alpha1.Rule{{
			Name:    "listed",
			Matches: []v1alpha1.Predicate{{Key: "client", Operator: v1alpha1.OperatorInGroup, Value: "tenants"}},
			Rates:   []v1alpha1.Rate{{Requests: 100, PeriodSeconds: 60}},
		}},
	})
	return p
}

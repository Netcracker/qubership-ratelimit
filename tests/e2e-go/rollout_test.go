//go:build e2e

package e2e

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// Ready is a statement about every replica, which makes a rollout the case it
// is easiest to get wrong: the pods change while the rules do not. An operator
// counting a draining pod sees applied fall below total and reports the domain
// as not ready, and a person watching that condition, or Argo CD waiting on
// it, is told a change is in flight when nothing about the policy moved.
//
// Nothing else in the suite covers it. The unit tests pin the arithmetic on a
// fabricated EndpointSlice; only a real rollout produces a pod that is Ready
// and Terminating at the same time. The second half is the opposite case: a
// change to the policy, which does go through the kubelet's projection, and
// has to read as one on its way to every replica.
var _ = Describe("a same-version rollout", Ordered, Label("rollout"), func() {
	const domain = "gateway.rollout"
	var (
		applied bool
		fleet   *fleetScale
	)

	BeforeAll(func() {
		// At one replica the rollout is one pod leaving and one arriving, and
		// the fraction reads 1/1 at both ends; with two, one replica serves
		// through the replacement of the other, and the fraction has a
		// draining pod to get wrong. The operator writes the status
		// throughout, and the assertion on lastCheckTime below is the proof
		// that it did.
		fleet = scaleFleet(2)

		Expect(apply(newPolicy(domain, totalLimits(10, 60)))).To(Succeed())
		applied = true

		// The whole fraction is the precondition: the spec below asserts that
		// Ready never leaves True, which says nothing unless it was True to
		// begin with.
		Eventually(policyCondition(domain, "Ready")).
			WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Equal("True"),
			"the domain was not ready before the rollout, so a flicker would be unreadable")
	})
	AfterAll(func() {
		// The fleet is restored first: the cleanup wait can fail, and nothing
		// after a failed step in this closure runs.
		if fleet != nil {
			fleet.restore()
		}
		if applied {
			deletePolicies(domain)
		}
	})

	It("keeps Ready true while every pod is replaced", func() {
		before, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		checkedBefore := before.Status.Replicas.LastCheckTime
		Expect(checkedBefore).NotTo(BeNil(), "the operator has not probed the fleet yet")

		// Sampled rather than checked at the ends, because the failure this
		// pins is transient by nature: the fraction is wrong only while a pod
		// drains, and both ends of the rollout look correct.
		var (
			mu    sync.Mutex
			seen  []string
			stop  = make(chan struct{})
			ended = make(chan struct{})
		)
		go func() {
			defer GinkgoRecover()
			defer close(ended)
			for {
				select {
				case <-stop:
					return
				case <-time.After(250 * time.Millisecond):
				}
				policy, err := getPolicy(domain)
				if err != nil {
					// A read that fails says nothing about the condition, and
					// the API server is briefly unreachable in some of these
					// clusters. Silence is the honest sample.
					continue
				}
				for _, condition := range policy.Status.Conditions {
					if condition.Type == v1.ConditionReady &&
						condition.Status != metav1.ConditionTrue {
						mu.Lock()
						seen = append(seen, string(condition.Status)+"/"+condition.Reason)
						mu.Unlock()
					}
				}
			}
		}()

		rolloutRestart(serviceDeployment())

		close(stop)
		<-ended

		mu.Lock()
		defer mu.Unlock()
		Expect(seen).To(BeEmpty(),
			"Ready left True during a rollout that changed no rule: %v", seen)

		// The samples above are evidence only if somebody was writing the
		// status while they were taken. A moving lastCheckTime is that
		// somebody: the operator probing the fleet during the rollout.
		after, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(after.Status.Replicas.LastCheckTime).NotTo(BeNil())
		Expect(after.Status.Replicas.LastCheckTime.Time).To(BeTemporally(">", checkedBefore.Time),
			"lastCheckTime did not move: the operator wrote no status while the samples were taken, "+
				"so a frozen True would have passed")
	})

	It("reads a policy change as a rollout on its way to the replicas", func() {
		// A new generation reaches the replicas through the ConfigMap and the
		// kubelet's projection of it, one pod at a time. Ready leaves True
		// while that happens and comes back once every replica applied it.
		// What is asserted is the sequence, never its duration: the window
		// is the kubelet's sync period, seconds here and a minute in
		// production, and a spec that timed it would pin the cluster's
		// configuration rather than the operator's behavior. The reasons on
		// the way are Reconciling, no replica has it yet, and Propagating,
		// some have; which of the two a sample catches depends on the
		// kubelet's timing across the nodes.
		Expect(policyCondition(domain, "Ready")()).To(Equal("True"), "the domain was not ready before the change")
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Limits[0].Rules[0].Rates[0].Requests++
		Expect(k8s.Update(ctx, p)).To(Succeed())

		var seen []string
		Eventually(func() []string {
			reason := readyReason(domain)()
			if reason == v1.ReasonReconciling || reason == v1.ReasonPropagating {
				seen = append(seen, reason)
			}
			return seen
		}).WithTimeout(time.Minute).WithPolling(200*time.Millisecond).ShouldNot(BeEmpty(),
			"the change reached every replica without Ready ever reading as in flight")
		Eventually(readyReason(domain)).WithTimeout(2*time.Minute).WithPolling(time.Second).
			Should(Equal(v1.ReasonAllReplicas), "Ready did not come back once the change propagated")
		Expect(policyCondition(domain, "Stalled")()).To(Equal("False"),
			"a rollout that completed was reported as stalled")
	})

	It("counts the whole fleet once the rollout settles", func() {
		Eventually(func(g Gomega) {
			policy, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(policy.Status.Replicas.Total).To(BeNumerically(">", 0),
				"no replica is in the fraction after the rollout")
			g.Expect(policy.Status.Replicas.Applied).To(Equal(policy.Status.Replicas.Total),
				"a replica is still reported behind after the rollout finished")

			// The REPLICAS printer column reads this field, so a status that
			// carries the numbers and not the fraction shows an empty column.
			g.Expect(policy.Status.Replicas.Summary).NotTo(BeEmpty())
		}).WithTimeout(2 * time.Minute).WithPolling(3 * time.Second).Should(Succeed())
	})
})

//go:build e2e

package e2e

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Ready is a statement about every replica, which makes a rollout the case it
// is easiest to get wrong: the pods change while the rules do not. A leader
// counting a draining pod sees applied fall below total and reports the domain
// as not ready, and an operator watching that condition, or Argo CD waiting on
// it, is told a change is in flight when nothing about the policy moved.
//
// Nothing else in the suite covers it. The unit tests pin the arithmetic on a
// fabricated EndpointSlice; only a real rollout produces a pod that is Ready
// and Terminating at the same time.
var _ = Describe("a same-version rollout", Ordered, Label("rollout"), func() {
	const domain = "gateway.rollout"
	var (
		applied bool
		fleet   *fleetScale
	)

	BeforeAll(func() {
		// At one replica this spec cannot see what it exists to catch. The
		// rollout then replaces the pod holding the lease, and between the
		// old leader's exit and the new one's first reconcile nobody writes
		// the status: the samples read a frozen True, and the new leader's
		// first write is already whole. With two, a surviving leader writes
		// the status through the replacement of the other, and the assertion
		// on lastCheckTime below is the proof that one did.
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
		if applied {
			deletePolicies(domain)
		}
		if fleet != nil {
			fleet.restore()
		}
	})

	It("keeps Ready true while every pod is replaced", func() {
		before, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		checkedBefore := before.Status.Replicas.LastCheckTime
		Expect(checkedBefore).NotTo(BeNil(), "no leader has probed the fleet yet")

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
					if condition.Type == v1alpha1.ConditionReady &&
						condition.Status != metav1.ConditionTrue {
						mu.Lock()
						seen = append(seen, string(condition.Status)+"/"+condition.Reason)
						mu.Unlock()
					}
				}
			}
		}()

		rolloutRestart(operatorDeployment())

		close(stop)
		<-ended

		mu.Lock()
		defer mu.Unlock()
		Expect(seen).To(BeEmpty(),
			"Ready left True during a rollout that changed no rule: %v", seen)

		// The samples above are evidence only if somebody was writing the
		// status while they were taken. A moving lastCheckTime is that
		// somebody: a leader that probed the fleet during the rollout.
		after, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(after.Status.Replicas.LastCheckTime).NotTo(BeNil())
		Expect(after.Status.Replicas.LastCheckTime.Time).To(BeTemporally(">", checkedBefore.Time),
			"lastCheckTime did not move: no leader wrote the status while the samples were taken, "+
				"so a frozen True would have passed")
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

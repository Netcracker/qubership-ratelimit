//go:build e2e

package e2e

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// The operator writes the status and the configuration, and nothing else:
// every service replica answers checks from the configuration it mounted,
// whether or not an operator is running. Deleting the operator pod must
// therefore not interrupt rate limiting, and the replacement must pick the
// lease and the status writes up where the old one left them.
//
// The apply on every replica cannot be seen with one, so unlike most of the
// suite this container scales the service release, and restores the original
// replica count on the way out.
var _ = Describe("the operator", Ordered, Label("operator", "leader"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-leader"
	)
	var (
		fleet    *fleetScale
		operator string
	)

	BeforeAll(func() {
		scaleFleet(&fleet, 2)

		// What this suite measures is whether every replica answers, not
		// whether a limit bites, so its policy declares a limit far above any
		// burst it sends: a refusal below is a fault, not the limit at work.
		Expect(apply(newPolicy(domain, totalLimits(1000, 60)))).To(Succeed())
		waitApplied(domain)
	})
	AfterAll(func() {
		// The fleet is restored first: the cleanup wait can fail, and nothing
		// after a failed step in this closure runs.
		if fleet != nil {
			fleet.restore()
		}
		deletePolicies(domain)
	})

	It("applies the configuration on every service replica", func() {
		// The burst assertions below measure the service, so the gateway
		// must be past its own startup first.
		waitGatewayServes("public-gateway", probePath)

		// Every replica must log its own apply: each reads the ConfigMap
		// from its own volume, and a replica without this line is one
		// serving from an empty store. Traffic cannot prove this: the
		// gateway multiplexes checks over one gRPC connection, so one
		// replica may legitimately serve them all.
		Eventually(func(g Gomega) {
			pods := servicePods()
			g.Expect(len(pods)).To(BeNumerically(">=", 2), "the running service replicas")
			for _, pod := range pods {
				g.Expect(podLogs(pod.Name, nil)).To(ContainSubstring(appliedLine), "the log of replica %s", pod.Name)
			}
		}).WithTimeout(time.Minute).WithPolling(2*time.Second).Should(Succeed(),
			"a replica never applied the configuration")
	})

	// The identity on the lease is the operator's pod name, not a hostname
	// with a random suffix: the status names replicas by pod name, so a reader
	// comparing them against the lease holder has to see the same identifier.
	It("signs the lease with the operator's pod name", func() {
		// The holder has to be a pod that exists, and the two conditions
		// have to be polled together: a lease keeps naming a dead pod until
		// its duration runs out, so right after another suite restarted the
		// operator the first non-empty holder can be the pod that restart
		// killed.
		Eventually(func(g Gomega) {
			holder := leaseHolderPod()
			g.Expect(holder).NotTo(BeEmpty(), "the lease names no holder")
			var pod corev1.Pod
			g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: holder}, &pod)).To(Succeed(),
				"the lease names pod %s", holder)
			operator = holder
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
			"no live operator pod holds the lease")
		Expect(operator).NotTo(ContainSubstring("_"),
			"the identity carries controller-runtime's random suffix, so POD_NAME is not reaching it")

		// The dev profile runs one operator replica outside a rollout, and the
		// lease holder has to be that pod.
		Expect(podNames(operatorPods())).To(ConsistOf(operator), "the running operator pods")
	})

	It("answers checks on every replica", func() {
		// Every pod serves the Service. A replica serving from an empty
		// store betrays itself in its log: it reports "unknown rate limit
		// domain" on every check it serves.
		since := time.Now()
		time.Sleep(time.Second)
		for attempt := 1; attempt <= 4; attempt++ {
			Expect(gatewayBurst("public-gateway", probePath, 4, nil)).To(HaveEach(beAdmitted()),
				"burst %d of 4 under a limit far above it", attempt)
			time.Sleep(1200 * time.Millisecond)
		}
		Expect(checksLoggedSince(since)).To(BeNumerically(">=", 4),
			"too few checks reached the service; the traffic bypassed it")
		Expect(serviceLogsSince(since)()).NotTo(ContainSubstring("unknown rate limit domain"),
			"a replica answered from an empty store")
	})

	It("keeps answering checks while the operator pod is replaced", func() {
		since := time.Now()
		time.Sleep(time.Second)

		// Resolve, verify and delete under one retry, so a pod that dies
		// between the steps only restarts the resolution.
		Eventually(func(g Gomega) {
			holder := leaseHolderPod()
			g.Expect(holder).NotTo(BeEmpty())
			var pod corev1.Pod
			g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: holder}, &pod)).To(Succeed())
			g.Expect(k8s.Delete(ctx, &pod)).To(Succeed())
			operator = holder
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
			"no live operator to kill")

		// The service reads no API server object and holds no lease: the
		// operator's absence changes nothing on the data path, so every
		// burst has to stay clean.
		bursts := make([][]int, 0, 8)
		for range 8 {
			bursts = append(bursts, gatewayBurst("public-gateway", probePath, 4, nil))
			time.Sleep(1200 * time.Millisecond)
		}
		Expect(bursts).To(HaveEach(HaveEach(beAdmitted())),
			"checks degraded while the operator was replaced; the codes of the 8 bursts")
		Expect(checksLoggedSince(since)).To(BeNumerically(">=", 8),
			"too few checks reached the service during the handover")
		Expect(serviceLogsSince(since)()).NotTo(ContainSubstring("unknown rate limit domain"),
			"a replica answered from an empty store during the handover")
	})

	It("moves the lease to the replacement pod", func() {
		// Up to a full lease duration passes before the replacement may
		// take over, so this wait is generous rather than tight.
		Eventually(func(g Gomega) {
			holder := leaseHolderPod()
			g.Expect(holder).NotTo(BeEmpty(), "the lease names no holder")
			g.Expect(holder).NotTo(Equal(operator), "the lease still names the killed pod")
			var pod corev1.Pod
			g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: holder}, &pod)).To(Succeed(),
				"the lease names pod %s", holder)
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
			"the lease did not move off the killed operator pod to a live one")
	})

	It("resumes the status writes from the replacement pod", func() {
		// Status is the operator's work, so a replacement that never took it
		// up would strand every policy without a condition.
		//
		// Bump the limit rather than patch the domain with its own value,
		// which the API server never turns into a new generation, so
		// observedGeneration has a real new generation to catch up with.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Limits[0].Rules[0].Rates[0].Requests = 1001
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(policyCondition(domain, v1.ConditionAccepted)).
			WithTimeout(2*time.Minute).WithPolling(5*time.Second).Should(Equal("True"),
			"the replacement operator did not accept a policy after the handover")
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(p.Status.ObservedGeneration).To(Equal(p.Generation), "observedGeneration of %s", domain)
		}).WithTimeout(time.Minute).Should(Succeed(),
			"observedGeneration does not match generation after the handover")
	})
})

// leaseHolderPod is the identity on the lease, which is the holder's pod name
// and nothing else.
//
// The operator signs the lease with POD_NAME from the Downward API rather than
// letting controller-runtime sign it with the hostname and a random suffix.
// That is what makes this equal to a pod name a caller can Get. The spec
// "signs the lease with the operator's pod name" pins the equality.
func leaseHolderPod() string {
	var lease coordinationv1.Lease
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "ratelimit.netcracker.com"},
		&lease); err != nil {
		return ""
	}
	if lease.Spec.HolderIdentity == nil {
		return ""
	}
	return *lease.Spec.HolderIdentity
}

// checksLoggedSince counts the per-check Debug lines across every replica:
// direct proof the checks reached the service instead of being failed open
// around it.
func checksLoggedSince(since time.Time) int {
	return strings.Count(serviceLogsSince(since)(), "rate limit check")
}

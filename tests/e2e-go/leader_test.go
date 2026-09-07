//go:build e2e

package e2e

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Leader election gates status writes and nothing else. The store updater and
// the gRPC endpoint report NeedLeaderElection() false, so every replica
// answers checks whether or not it holds the lease. Killing the leader must
// therefore not interrupt rate limiting - and the new leader must pick up
// status writes.
//
// This is the one property that cannot be seen with a single replica, so
// unlike the rest of the suite this container scales the release, and
// restores the original replica count on the way out.
var _ = Describe("leader election", Ordered, Label("leader"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-leader"
	)
	var (
		release          string
		originalReplicas int32
		leader           string
	)

	BeforeAll(func() {
		var dep appsv1.Deployment
		Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: operatorDeployment()}, &dep)).
			To(Succeed())
		release = dep.Annotations["meta.helm.sh/release-name"]
		Expect(release).NotTo(BeEmpty(), "cannot determine the Helm release owning %s", dep.Name)
		originalReplicas = 1
		if dep.Spec.Replicas != nil {
			originalReplicas = *dep.Spec.Replicas
		}

		// What this suite measures is whether every replica answers, not
		// whether a limit bites, so its policy declares a limit far above any
		// burst it sends: a refusal below is a fault, not the limit at work.
		Expect(apply(newPolicy(domain, totalLimits(1000, 60)))).To(Succeed())
	})
	AfterAll(func() {
		deletePolicies(domain)
		if release != "" {
			helmScale(release, originalReplicas)
		}
	})

	It("elects one leader among two replicas", func() {
		helmScale(release, 2)

		var dep appsv1.Deployment
		Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: operatorDeployment()}, &dep)).
			To(Succeed())
		Expect(dep.Status.ReadyReplicas).To(Equal(int32(2)),
			"expected 2 ready replicas after the scale-up")

		// The burst assertions below measure the operator, so the gateway
		// must be past its own startup first.
		waitGatewayServes("public-gateway", probePath)

		// Every replica must log its own rebuild: the updater runs outside
		// leader election, and a follower without this line is exactly the
		// leader-only-store bug. Traffic cannot prove this - the gateway
		// multiplexes checks over one gRPC connection, so one replica may
		// legitimately serve them all.
		Eventually(func() bool {
			pods := operatorPods()
			if len(pods) < 2 {
				return false
			}
			for _, pod := range pods {
				if !strings.Contains(podLogs(pod.Name, nil), "rate limit store rebuilt") {
					return false
				}
			}
			return true
		}).WithTimeout(time.Minute).WithPolling(2*time.Second).Should(BeTrue(),
			"a replica never rebuilt its rule store; the updater is leader-gated")

		// The holder has to be a pod that exists, and the two conditions have
		// to be polled together: a lease keeps naming a dead pod until its
		// duration runs out, so right after another suite restarted the
		// operator the first non-empty holder can be the pod that restart
		// killed.
		Eventually(func() string {
			holder := leaseHolderPod()
			if holder == "" {
				return ""
			}
			var pod corev1.Pod
			if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: holder}, &pod); err != nil {
				return ""
			}
			leader = holder
			return holder
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).ShouldNot(BeEmpty(),
			"no live replica acquired the lease")
	})

	It("answers checks on every replica, not just the leader", func() {
		// Every pod serves the Service. A store filled only on the leader
		// betrays itself in the follower's log: a replica with an empty store
		// reports "unknown rate limit domain" on every check it serves.
		since := time.Now()
		time.Sleep(time.Second)
		for attempt := 1; attempt <= 4; attempt++ {
			Expect(burstClean(probePath)).To(BeTrue(),
				"burst %d was refused or failed under a limit far above it", attempt)
			time.Sleep(1200 * time.Millisecond)
		}
		Expect(checksLoggedSince(since)).To(BeNumerically(">=", 4),
			"too few checks reached the operator; the traffic bypassed it")
		Expect(operatorLogsSince(since)()).NotTo(ContainSubstring("unknown rate limit domain"),
			"a replica answered from an empty store")
	})

	It("keeps answering checks while the leader is replaced", func() {
		since := time.Now()
		time.Sleep(time.Second)

		// The leader is re-resolved here rather than carried over from the
		// first spec: a helm upgrade in this suite reverts the restartedAt
		// annotation another suite's rollout restart left on the template,
		// and that rollover replaces every pod - the one elected there
		// included. Resolve, verify and delete under one retry so a pod
		// that dies between the steps only restarts the resolution.
		Eventually(func(g Gomega) {
			holder := leaseHolderPod()
			g.Expect(holder).NotTo(BeEmpty())
			var pod corev1.Pod
			g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: holder}, &pod)).To(Succeed())
			g.Expect(k8s.Delete(ctx, &pod)).To(Succeed())
			leader = holder
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
			"no live leader to kill")

		// The preStop pause keeps the leaving pod serving until xDS stops
		// routing to it, so every burst has to stay clean: a dirty one means
		// a check was failed open mid-rollover, which N4 rules out.
		clean := 0
		for i := 0; i < 8; i++ {
			if burstClean(probePath) {
				clean++
			}
			time.Sleep(1200 * time.Millisecond)
		}
		Expect(clean).To(Equal(8),
			"checks degraded while the leader was replaced (%d/8 clean bursts)", clean)
		Expect(checksLoggedSince(since)).To(BeNumerically(">=", 8),
			"too few checks reached the operator during the handover")
		Expect(operatorLogsSince(since)()).NotTo(ContainSubstring("unknown rate limit domain"),
			"a replica answered from an empty store during the handover")
	})

	It("moves the lease to the surviving replica", func() {
		// Up to a full lease duration passes before the survivor may take
		// over, so this wait is generous rather than tight.
		Eventually(leaseHolderPod).WithTimeout(2*time.Minute).WithPolling(3*time.Second).
			Should(SatisfyAll(Not(BeEmpty()), Not(Equal(leader))),
				"the lease did not move off the killed leader")
	})

	It("writes policy status from the new leader", func() {
		// Status is the only leader-gated work, so a handover that leaves
		// nobody writing it would strand every policy without a condition.
		//
		// The bash suite patched the domain with its own value, which the API
		// server never turns into a new generation. Bump the limit instead,
		// so observedGeneration has a real new generation to catch up with.
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		p.Spec.Limits[0].Rules[0].Rates[0].Requests = 1001
		Expect(k8s.Update(ctx, p)).To(Succeed())

		Eventually(policyCondition(domain, "Accepted")).
			WithTimeout(2*time.Minute).WithPolling(5*time.Second).Should(Equal("True"),
			"the new leader did not accept a policy after the handover")
		Eventually(func() bool {
			p, err := getPolicy(domain)
			return err == nil && p.Status.ObservedGeneration == p.Generation
		}).WithTimeout(time.Minute).Should(BeTrue(),
			"observedGeneration does not match generation after the handover")
	})
})

// leaseHolderPod is the pod half of the lease holder, which is "<pod>_<uuid>".
func leaseHolderPod() string {
	var lease coordinationv1.Lease
	if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: "ratelimit.netcracker.com"},
		&lease); err != nil {
		return ""
	}
	if lease.Spec.HolderIdentity == nil {
		return ""
	}
	return strings.SplitN(*lease.Spec.HolderIdentity, "_", 2)[0]
}

// burstClean sends four requests and reports whether the gateway admitted
// every one: 2xx or 404 from the routed probe backend. 429 is a refusal, 0 a
// transport error, and 5xx a gateway answering on its own - none of them
// count. Passing traffic alone still cannot distinguish a healthy endpoint
// from one the gateway failed open around; the log detectors supply that
// half of the proof.
func burstClean(path string) bool {
	for _, code := range gatewayBurst("public-gateway", path, 4, nil) {
		if (code < 200 || code > 299) && code != 404 {
			return false
		}
	}
	return true
}

// checksLoggedSince counts the per-check Debug lines across every replica:
// direct proof the checks reached the operator instead of being failed open
// around it.
func checksLoggedSince(since time.Time) int {
	return strings.Count(operatorLogsSince(since)(), "rate limit check")
}

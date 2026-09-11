//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dto "github.com/prometheus/client_model/go"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// A replica the leader cannot reach is the case Stalled exists for: a broken
// informer, a pod behind a policy, a node that lost the mesh. The unit tests
// pin what the leader concludes from a fabricated probe; only a real fleet
// shows the leader concluding it from a pod that is Ready by every other
// measure and silent to the one that matters.
//
// The replica is silenced with an AuthorizationPolicy that denies its metrics
// port, which is where the leader reads /debug/applied. Two things about the
// recipe are not obvious and both were measured rather than assumed:
//
// The leader is replaced after the policy lands, because the probe keeps its
// connections alive and ztunnel enforces a new DENY on new connections only.
// A policy applied under a running leader changes nothing until that leader
// reconnects; a fresh leader connects afresh and finds the pod silent.
//
// Two followers are denied, not one, because the replaced leader's lease can
// go to any pod - a denied one included - and ztunnel does not enforce a DENY
// on a pod's connection to its own IP. A single denied pod that wins the
// lease probes itself through, probes everyone else through, and reports the
// fleet whole. With two denied, whichever pod wins probes at least one denied
// peer afresh, and at least one pod answers, so the verdict is ReplicaStale
// and never ProbeFailed, regardless of the election.
var _ = Describe("a replica the leader cannot reach", Ordered, Label("lagging"), func() {
	const (
		domain   = "gateway.lagging"
		policy   = "e2e-lagging-deny"
		silenced = "e2e-lagging" // the label the DENY selects by
	)
	var (
		applied bool
		fleet   *fleetScale
		denied  []string
	)

	BeforeAll(func() {
		fleet = scaleFleet(3)

		Expect(apply(newPolicy(domain, totalLimits(10, 60)))).To(Succeed())
		applied = true

		Eventually(func() string {
			p, err := getPolicy(domain)
			if err != nil {
				return ""
			}
			return p.Status.Replicas.Summary
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(Equal("3/3"),
			"the fleet was not whole before the replica was silenced")
	})
	AfterAll(func() {
		_ = k8s.Delete(ctx, denyPolicy(policy, silenced))
		if applied {
			deletePolicies(domain)
		}
		if fleet != nil {
			fleet.restore()
		}
	})

	It("reports the silent replica stale, and names it", func() {
		leader := leaseHolderPod()
		Expect(leader).NotTo(BeEmpty(), "no pod holds the lease")

		for _, pod := range operatorPods() {
			if pod.Name == leader || len(denied) == 2 {
				continue
			}
			labelPod(pod, silenced, "true")
			denied = append(denied, pod.Name)
		}
		Expect(denied).To(HaveLen(2), "the fleet has fewer than two followers to silence")

		Expect(apply(denyPolicy(policy, silenced))).To(Succeed())
		Expect(k8s.Delete(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: leader}})).To(Succeed())

		// Propagating first: a fresh leader sees the silent replicas at once,
		// and for the length of the propagation deadline that is a rollout
		// as far as it can tell. The window is thirty seconds wide, so a poll
		// every second cannot miss it.
		Eventually(readyReason(domain)).WithTimeout(90*time.Second).WithPolling(time.Second).
			Should(Equal(v1alpha1.ReasonPropagating),
				"the new leader never reported the silent replicas as propagating")

		// Then ReplicaStale, once the deadline passes with the pod still
		// silent. This is the transition worth alerting on, and the message
		// has to name the pod: an operator gets nothing from "a replica".
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())

			stalled := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionStalled)
			g.Expect(stalled).NotTo(BeNil())
			g.Expect(stalled.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(stalled.Reason).To(Equal(v1alpha1.ReasonReplicaStale))

			ready := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionReady)
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(ready.Reason).To(Equal(v1alpha1.ReasonReplicaStale))
			g.Expect(ready.Message).To(ContainSubstring("did not answer"))
			g.Expect(namesOneOf(ready.Message, denied)).To(BeTrue(),
				"the message names none of the silenced pods %v: %q", denied, ready.Message)

			g.Expect(p.Status.Replicas.Applied).To(BeNumerically("<", p.Status.Replicas.Total),
				"a stale fleet reported whole: %s", p.Status.Replicas.Summary)
		}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
	})

	It("publishes the stall on the leader's scrape", func() {
		holder := leaseHolderPod()
		Expect(holder).NotTo(BeEmpty())
		families := scrapePod(holder)
		Expect(gaugeValue(families, "ratelimit_policy_stalled",
			map[string]string{"domain": domain, "reason": v1alpha1.ReasonReplicaStale})).To(Equal(1.0),
			"the leader's scrape does not carry the stall")
		Expect(gaugeValue(families, "ratelimit_leader", nil)).To(Equal(1.0))
	})

	It("recovers once the replica is reachable again", func() {
		Expect(k8s.Delete(ctx, denyPolicy(policy, silenced))).To(Succeed())

		// The probe's connections to the silenced pods were refused, so there
		// is nothing kept alive to outlast the policy: the next probe opens
		// fresh and gets through.
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(readyReason(domain)()).To(Equal(v1alpha1.ReasonAllReplicas))
			g.Expect(p.Status.Replicas.Summary).To(Equal("3/3"))

			stalled := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionStalled)
			g.Expect(stalled).NotTo(BeNil())
			g.Expect(stalled.Status).To(Equal(metav1.ConditionFalse))
		}).WithTimeout(2 * time.Minute).WithPolling(2 * time.Second).Should(Succeed())
	})
})

// denyPolicy is the AuthorizationPolicy that silences the labelled pods'
// metrics port. It selects by a label the spec puts on a pod object directly,
// so it follows the pod and not the Deployment: a replacement pod carries the
// template's labels and not this one, which is what keeps the restored fleet
// clean without a second cleanup.
func denyPolicy(name, label string) *unstructured.Unstructured {
	deny := &unstructured.Unstructured{}
	deny.SetAPIVersion("security.istio.io/v1")
	deny.SetKind("AuthorizationPolicy")
	deny.SetNamespace(namespace)
	deny.SetName(name)
	deny.Object["spec"] = map[string]any{
		"selector": map[string]any{"matchLabels": map[string]any{label: "true"}},
		"action":   "DENY",
		"rules": []any{map[string]any{
			"to": []any{map[string]any{
				"operation": map[string]any{"ports": []any{"8080"}},
			}},
		}},
	}
	return deny
}

// labelPod adds one label to a running pod object.
func labelPod(pod corev1.Pod, key, value string) {
	before := pod.DeepCopy()
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[key] = value
	Expect(k8s.Patch(ctx, &pod, client.MergeFrom(before))).To(Succeed(),
		"could not label pod %s", pod.Name)
}

// readyReason returns the reason of the Ready condition, "" while absent.
func readyReason(name string) func() string {
	return func() string {
		p, err := getPolicy(name)
		if err != nil {
			return ""
		}
		c := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionReady)
		if c == nil {
			return ""
		}
		return c.Reason
	}
}

// namesOneOf reports whether the message mentions at least one of the pods.
func namesOneOf(message string, pods []string) bool {
	for _, pod := range pods {
		if strings.Contains(message, pod) {
			return true
		}
	}
	return false
}

// scrapePod fetches and parses /metrics from one pod by name.
func scrapePod(name string) map[string]*dto.MetricFamily {
	for _, pod := range operatorPods() {
		if pod.Name == name {
			merged := map[string]*dto.MetricFamily{}
			mergeScrape(merged, pod)
			return merged
		}
	}
	Fail(fmt.Sprintf("pod %s is not running", name))
	return nil
}

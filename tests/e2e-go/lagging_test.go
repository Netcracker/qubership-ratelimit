//go:build e2e

package e2e

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dto "github.com/prometheus/client_model/go"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// A replica the operator cannot reach is the case Stalled exists for: a pod
// behind a policy, a node that lost the mesh. The unit tests pin what the
// operator concludes from a fabricated probe; only a real fleet shows it
// concluding that from a pod that is Ready by every other measure and silent
// to the one that matters.
//
// The replica is silenced with an AuthorizationPolicy that denies its metrics
// port, which is where the operator reads /debug/applied. The operator is
// replaced after the policy lands, because the probe keeps its connections
// alive and ztunnel enforces a new DENY on new connections only: a policy
// applied under a running operator changes nothing until it reconnects, and
// a fresh one connects afresh and finds the pods silent. Two of three
// replicas are denied so that the verdict is ReplicaStale on a fleet that
// still has an answering member, never ProbeFailed on a fleet with none.
var _ = Describe("a replica the operator cannot reach", Ordered, Label("lagging"), func() {
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
		// The fleet is restored first: the cleanup wait can fail, and nothing
		// after a failed step in this closure runs.
		if fleet != nil {
			fleet.restore()
		}
		if applied {
			deletePolicies(domain)
		}
	})

	It("reports the silenced replicas as ReplicaStale by pod name", func() {
		operator := leaseHolderPod()
		Expect(operator).NotTo(BeEmpty(), "no operator pod holds the lease")

		for _, pod := range servicePods() {
			if len(denied) == 2 {
				break
			}
			labelPod(pod, silenced, "true")
			denied = append(denied, pod.Name)
		}
		Expect(denied).To(HaveLen(2), "the fleet has fewer than two replicas to silence")

		// The operator is replaced after the policy lands, because the probe
		// keeps its connections and a DENY in ambient mode applies to new
		// connections only: a fresh operator connects afresh and finds the
		// pods silent.
		Expect(apply(denyPolicy(policy, silenced))).To(Succeed())
		Expect(k8s.Delete(ctx, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: operator}})).To(Succeed())

		// Propagating first: a fresh operator sees the silent replicas at
		// once, and for the length of the propagation deadline that is a
		// rollout as far as it can tell. The deadline is ninety seconds in
		// the split, so a poll every second cannot miss the window.
		Eventually(readyReason(domain)).WithTimeout(2*time.Minute).WithPolling(time.Second).
			Should(Equal(v1.ReasonPropagating),
				"the new operator never reported the silent replicas as propagating")

		// Then ReplicaStale, once the deadline passes with the pod still
		// silent. This is the transition worth alerting on, and the message
		// has to name the pod: an operator gets nothing from "a replica".
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(meta.FindStatusCondition(p.Status.Conditions, v1.ConditionStalled)).To(
				gstruct.PointTo(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
					"Status": Equal(metav1.ConditionTrue),
					"Reason": Equal(v1.ReasonReplicaStale),
				})), "the Stalled condition")

			ready := meta.FindStatusCondition(p.Status.Conditions, v1.ConditionReady)
			g.Expect(ready).To(gstruct.PointTo(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
				"Status":  Equal(metav1.ConditionFalse),
				"Reason":  Equal(v1.ReasonReplicaStale),
				"Message": ContainSubstring("did not answer"),
			})), "the Ready condition")
			g.Expect(ready.Message).To(Or(ContainSubstring(denied[0]), ContainSubstring(denied[1])),
				"the Ready message names none of the silenced pods %v", denied)

			g.Expect(p.Status.Replicas.Applied).To(BeNumerically("<", p.Status.Replicas.Total),
				"a stale fleet reported whole: %s", p.Status.Replicas.Summary)
		}).WithTimeout(3*time.Minute).WithPolling(2*time.Second).Should(Succeed(),
			"the operator to report the silenced replicas as ReplicaStale")
	})

	It("publishes the stall on the operator's scrape", func() {
		holder := leaseHolderPod()
		Expect(holder).NotTo(BeEmpty())
		families := scrapePod(holder)
		gauges := struct{ PolicyStalled, Leader float64 }{
			PolicyStalled: gaugeValue(families, "ratelimit_policy_stalled",
				map[string]string{"domain": domain, "reason": v1.ReasonReplicaStale}),
			Leader: gaugeValue(families, "ratelimit_leader", nil),
		}
		Expect(gauges).To(gstruct.MatchAllFields(gstruct.Fields{
			"PolicyStalled": Equal(1.0),
			"Leader":        Equal(1.0),
		}), "the gauges on the scrape of %s, the lease holder", holder)
	})

	It("recovers once the replica is reachable again", func() {
		Expect(k8s.Delete(ctx, denyPolicy(policy, silenced))).To(Succeed())

		// The probe's connections to the silenced pods were refused, so there
		// is nothing kept alive to outlast the policy: the next probe opens
		// fresh and gets through.
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(readyReason(domain)()).To(Equal(v1.ReasonAllReplicas), "the reason of the Ready condition")
			g.Expect(p.Status.Replicas.Summary).To(Equal("3/3"), "the replica summary")

			g.Expect(meta.FindStatusCondition(p.Status.Conditions, v1.ConditionStalled)).To(
				gstruct.PointTo(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
					"Status": Equal(metav1.ConditionFalse),
				})), "the Stalled condition")
		}).WithTimeout(2*time.Minute).WithPolling(2*time.Second).Should(Succeed(),
			"the fleet to report every replica again once the DENY is gone")
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

// scrapePod fetches and parses /metrics from one pod of either chart by name.
func scrapePod(name string) map[string]*dto.MetricFamily {
	for _, pod := range append(operatorPods(), servicePods()...) {
		if pod.Name == name {
			merged := map[string]*dto.MetricFamily{}
			mergeScrape(merged, pod)
			return merged
		}
	}
	Fail(fmt.Sprintf("pod %s is not running", name))
	return nil
}

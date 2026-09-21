//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// apply is the kubectl-apply of the suite: server-side, forcing ownership so a
// leftover from an earlier run cannot make a fixture fail on a field conflict.
func apply(obj client.Object) error {
	return k8s.Patch(ctx, obj, client.Apply, client.ForceOwnership, client.FieldOwner("e2e"))
}

// getPolicy re-reads a policy; the Eventually closures below lean on it.
func getPolicy(name string) (*v1alpha1.RateLimitPolicy, error) {
	var p v1alpha1.RateLimitPolicy
	err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &p)
	return &p, err
}

// policyCondition returns the status of one condition, "" while it is absent -
// the shape Eventually wants.
func policyCondition(name, conditionType string) func() string {
	return func() string {
		p, err := getPolicy(name)
		if err != nil {
			return ""
		}
		c := meta.FindStatusCondition(p.Status.Conditions, conditionType)
		if c == nil {
			return ""
		}
		return string(c.Status)
	}
}

// generations returns (observed, active), zeros while the status is not there.
func generations(name string) func() [2]int64 {
	return func() [2]int64 {
		p, err := getPolicy(name)
		if err != nil {
			return [2]int64{}
		}
		return [2]int64{p.Status.ObservedGeneration, p.Status.ActiveGeneration}
	}
}

// serviceLogsSince concatenates the logs of every service replica written
// after the given moment. A replica reads its configuration from its own
// volume, so the pod's own log is the only proof it saw a change, and the
// check lines are written by whichever replica the gateway reached.
func serviceLogsSince(since time.Time) func() string {
	return func() string {
		var pods corev1.PodList
		if err := k8s.List(ctx, &pods, client.InNamespace(namespace),
			client.MatchingLabels{"app.kubernetes.io/name": serviceChart}); err != nil {
			return ""
		}
		var out strings.Builder
		sinceTime := metav1.NewTime(since)
		for i := range pods.Items {
			req := clientset.CoreV1().Pods(namespace).GetLogs(pods.Items[i].Name,
				&corev1.PodLogOptions{SinceTime: &sinceTime})
			stream, err := req.Stream(ctx)
			if err != nil {
				continue
			}
			logs, _ := io.ReadAll(stream)
			_ = stream.Close()
			out.Write(logs)
		}
		return out.String()
	}
}

// printedRow fetches the object the way kubectl get renders it - a server-side
// Table - and returns its cells joined by spaces. It is how the suite proves
// the printer columns of the installed CRD, not of the one in the repository.
func printedRow(resource, name string) string {
	cfg, err := ctrlconfig.GetConfig()
	Expect(err).NotTo(HaveOccurred())
	cfg.GroupVersion = &schema.GroupVersion{Group: v1alpha1.GroupVersion.Group, Version: v1alpha1.GroupVersion.Version}
	cfg.APIPath = "/apis"
	cfg.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	rc, err := rest.RESTClientFor(cfg)
	Expect(err).NotTo(HaveOccurred())

	var table metav1.Table
	err = rc.Get().
		Namespace(namespace).
		Resource(resource).
		Name(name).
		SetHeader("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io").
		Do(ctx).
		Into(&table)
	Expect(err).NotTo(HaveOccurred())
	Expect(table.Rows).NotTo(BeEmpty())

	var cells []string
	for _, cell := range table.Rows[0].Cells {
		cells = append(cells, fmt.Sprintf("%v", cell))
	}
	return strings.Join(cells, " ")
}

// --- Shared fixtures: the Go form of the bash apply_policy/apply_mapping. ---

func typeMetaFor(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: kind}
}

// newPolicy builds the one policy of a domain. Its name is its domain: object
// names are unique within a namespace, so that is what makes a second policy
// for the domain unrepresentable. Suites run serially, so each one owns the
// policy of its domain for its duration.
func newPolicy(domain string, limits []v1alpha1.LimitBlock) *v1alpha1.RateLimitPolicy {
	return &v1alpha1.RateLimitPolicy{
		TypeMeta:   typeMetaFor("RateLimitPolicy"),
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: domain},
		Spec:       v1alpha1.RateLimitPolicySpec{Domain: domain, Limits: limits},
	}
}

// totalLimits is the bash apply_policy body: one block, one unconditional
// rule, one fixed window.
func totalLimits(requests, periodSeconds int32) []v1alpha1.LimitBlock {
	return []v1alpha1.LimitBlock{{Name: "everything", Rules: []v1alpha1.Rule{{
		Name: "total",
		Rates: []v1alpha1.Rate{{
			Requests: requests, PeriodSeconds: periodSeconds, Algorithm: v1alpha1.AlgorithmFixedWindow,
		}},
	}}}}
}

// prefixLimits is totalLimits scoped to a path prefix, in a block named
// probe. Ginkgo shuffles the top-level containers, so a suite whose window
// outlives its own run - the hour-long redis and metrics budgets - must not
// see traffic the other suites send; a domain-wide block would.
func prefixLimits(prefix, rule string, counters []string, requests, periodSeconds int32) []v1alpha1.LimitBlock {
	return []v1alpha1.LimitBlock{{
		Name: "probe",
		Target: &v1alpha1.Target{Routes: []v1alpha1.Route{{
			Path: v1alpha1.PathMatch{Type: v1alpha1.PathMatchPrefix, Value: prefix},
		}}},
		Rules: []v1alpha1.Rule{{
			Name:     rule,
			Counters: counters,
			Rates: []v1alpha1.Rate{{
				Requests: requests, PeriodSeconds: periodSeconds, Algorithm: v1alpha1.AlgorithmFixedWindow,
			}},
		}},
	}}
}

// deletePolicies removes the policies of the given domains from the baseline
// namespace and returns once every running replica reports the domain gone,
// so that a container's cleanup cannot leave the next container a domain
// still enforced somewhere. A domain without a policy is skipped; any other
// failure to delete fails the cleanup, because a policy left behind claims
// the domain in the next container.
func deletePolicies(domains ...string) {
	for _, domain := range domains {
		err := k8s.Delete(ctx, newPolicy(domain, nil))
		if apierrors.IsNotFound(err) {
			continue
		}
		Expect(err).NotTo(HaveOccurred(), "could not delete the policy of %s", domain)
		Eventually(func() []string {
			return replicasReporting(domain, func(d applied.Domain, ok bool) bool { return ok })
		}).WithTimeout(propagationTimeout).WithPolling(2*time.Second).Should(BeEmpty(),
			"replicas that still enforce %s after its policy was removed", domain)
	}
}

// nextWindow sleeps into the first tenth of the next wall-clock second.
// FixedWindow buckets align to the clock, so a burst that starts here owns
// its whole one-second window; without this a warm-up probe or an earlier
// attempt of the same spec lands in the same second and spends the budget
// the burst is about to count. The bash suites never needed it - every curl
// paid seconds of port-forward setup between steps.
func nextWindow() {
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(1100 * time.Millisecond).Sub(now))
}

// appliedLine is what a service replica logs when it swaps a configuration
// in.
const appliedLine = "configuration applied"

// waitApplied is the bash wait_for_domain: it returns once every running
// service replica reports the current generation of every named policy on
// /debug/applied, the same report the operator judges Ready from. A change
// reaches a replica through the operator's ConfigMap and the kubelet's
// projection of it, one replica at a time on its own node's clock, and the
// report is the one signal that says the replica has it. Counting the
// replica's apply lines instead, the way earlier suites counted
// rebuilds, misreads a change the kubelet folded into another: two writes
// inside one sync period project once, and a write undone inside one
// project not at all, and neither leaves a line to count.
//
// The generation waited for is the active one, which the operator writes
// into the ConfigMap: the latest for a policy that compiles, the last-good
// for one whose latest does not. The status has to have observed the latest
// generation first, or the active one read is the previous edit's.
func waitApplied(domains ...string) {
	for _, domain := range domains {
		var want applied.Domain
		Eventually(func(g Gomega) {
			p, err := getPolicy(domain)
			g.Expect(err).NotTo(HaveOccurred(), "no policy for %s to wait on", domain)
			g.Expect(p.Status.ObservedGeneration).To(Equal(p.Generation), "the operator has not observed the edit")
			g.Expect(p.Status.ActiveGeneration).NotTo(BeZero(), "no generation of %s is enforced", domain)
			want = applied.Domain{Generation: p.Status.ActiveGeneration, UID: string(p.UID)}
		}).WithTimeout(time.Minute).WithPolling(time.Second).Should(Succeed())
		Eventually(func() []string {
			return replicasReporting(domain, func(d applied.Domain, ok bool) bool {
				return !ok || d.Generation != want.Generation || d.UID != want.UID
			})
		}).WithTimeout(propagationTimeout).WithPolling(2*time.Second).Should(BeEmpty(),
			"replicas that do not report generation %d of %s", want.Generation, domain)
	}
}

// replicasReporting names the running service replicas whose report of a
// domain satisfies the predicate, which is given the domain's entry and
// whether the report carries one at all; sorted by name, for a message.
func replicasReporting(domain string, predicate func(d applied.Domain, ok bool) bool) []string {
	var names []string
	for _, pod := range servicePods() {
		entry, ok := appliedReport(pod).Domains[domain]
		if predicate(entry, ok) {
			names = append(names, pod.Name)
		}
	}
	slices.Sort(names)
	return names
}

// propagationTimeout bounds one wait for the kubelet's projection: its sync
// period with the jitter kubelet adds, a minute and a half at the default,
// with room for the operator's write and the replica's apply on top. The
// e2e clusters run a period of seconds and never come near it.
const propagationTimeout = 3 * time.Minute

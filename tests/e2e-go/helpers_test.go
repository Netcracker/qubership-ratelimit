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

// operatorLogsSince concatenates the logs of every ratelimit pod written after
// the given moment. The store updater subscribes to informers directly, so the
// pod's own log is the only proof it saw an event.
func operatorLogsSince(since time.Time) func() string {
	return func() string {
		var pods corev1.PodList
		if err := k8s.List(ctx, &pods, client.InNamespace(namespace),
			client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"}); err != nil {
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
// namespace and returns once every running replica has logged the rebuild
// each removal causes, so that a container's cleanup cannot satisfy the next
// container's waitStoreRebuilt. A domain without a policy is skipped; any
// other failure to delete fails the cleanup, because a policy left behind
// claims the domain in the next container.
func deletePolicies(domains ...string) {
	for _, domain := range domains {
		before := storeRebuildsPerPod()
		err := k8s.Delete(ctx, newPolicy(domain, nil))
		if apierrors.IsNotFound(err) {
			continue
		}
		Expect(err).NotTo(HaveOccurred(), "could not delete the policy of %s", domain)
		Eventually(func() []string {
			return podsNotRebuiltSince(before)
		}).WithPolling(500*time.Millisecond).Should(BeEmpty(),
			"replicas that did not rebuild the store after the policy of %s was removed", domain)
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

// storeRebuilds counts the rebuild lines in the logs of the running
// replicas. A restarted pod starts a fresh log, so counts only compare
// within one stable set of pods.
func storeRebuilds() int {
	total := 0
	for _, n := range storeRebuildsPerPod() {
		total += n
	}
	return total
}

// storeRebuildsPerPod counts the rebuild lines per running replica, keyed by
// pod name.
func storeRebuildsPerPod() map[string]int {
	counts := map[string]int{}
	for _, pod := range operatorPods() {
		counts[pod.Name] = strings.Count(podLogs(pod.Name, nil), "rate limit store rebuilt")
	}
	return counts
}

// podsNotRebuiltSince names the replicas of before that are still running and
// have logged no rebuild since before was taken, sorted by name. A replica
// that has gone away is not named: nobody counts its log any more.
func podsNotRebuiltSince(before map[string]int) []string {
	now := storeRebuildsPerPod()
	var lagging []string
	for pod, n := range before {
		if got, ok := now[pod]; ok && got <= n {
			lagging = append(lagging, pod)
		}
	}
	slices.Sort(lagging)
	return lagging
}

// waitStoreRebuilt is the bash wait_for_domain: the store updater logs one
// line per rebuild, and that line is the only signal the running pod saw the
// event. Callers snapshot storeRebuilds() before their change and wait for
// the count to grow. Waiting for "a line after time T" instead would race:
// the log API filters timestamps at whole-second granularity, so a
// neighbouring suite's rebuild from the same wall second satisfies it and
// traffic then runs against a store that has not seen the change. The count
// is a signal only while no earlier rebuild is still in flight; deletePolicies
// therefore waits, per replica, for the rebuild its own removal causes.
func waitStoreRebuilt(before int) {
	Eventually(storeRebuilds).Should(BeNumerically(">", before),
		"the store never rebuilt after the change")
}

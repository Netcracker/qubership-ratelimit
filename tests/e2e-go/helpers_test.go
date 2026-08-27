//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
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

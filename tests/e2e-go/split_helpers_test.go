//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
)

// The channel between the two halves: the ConfigMap the operator writes and
// the service mounts, and the report a replica publishes about what it
// applied. These helpers read both the way the binaries do, through the
// shared decoder and the shared report type, so a format change breaks the
// suite where it breaks the components.

// configMap reads the configuration ConfigMap of the namespace.
func configMap() (*corev1.ConfigMap, error) {
	var cm corev1.ConfigMap
	err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: contract.ConfigMapName}, &cm)
	return &cm, err
}

// configManifest decodes the manifest the operator wrote, with the decoder
// the service reads it with.
func configManifest() (manifest.Manifest, error) {
	cm, err := configMap()
	if err != nil {
		return manifest.Manifest{}, err
	}
	return manifest.Decode([]byte(cm.Data[contract.ManifestKey]))
}

// manifestGeneration returns the generation the manifest carries for a
// domain, zero when the object or the domain is absent; the suites poll it
// the way they poll the policy status.
func manifestGeneration(domain string) func() int64 {
	return func() int64 {
		m, err := configManifest()
		if err != nil {
			return 0
		}
		return m.Domains[domain].Generation
	}
}

// appliedReport reads a service replica's report over a port-forward to its
// metrics port, the way the operator's probe reads it through the Service.
func appliedReport(pod corev1.Pod) applied.Report {
	port := 0
	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			if p.Name == contract.MetricsPortName {
				port = int(p.ContainerPort)
			}
		}
	}
	Expect(port).NotTo(BeZero(), "pod %s exposes no metrics port", pod.Name)

	addr, stop := forwardToPod(pod.Name, port)
	defer stop()
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + addr + contract.AppliedPath)
	Expect(err).NotTo(HaveOccurred(), "pod %s did not answer on %s", pod.Name, contract.AppliedPath)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK), "pod %s answered %d on %s: %s",
		pod.Name, resp.StatusCode, contract.AppliedPath, body)

	var report applied.Report
	Expect(json.Unmarshal(body, &report)).To(Succeed(), "pod %s published a report the suite cannot read: %s",
		pod.Name, body)
	return report
}

// readyServiceEndpoints counts the ready endpoints of the Service ratelimit,
// the set the gateways route to and the operator probes.
func readyServiceEndpoints() int {
	var slices discoveryv1.EndpointSliceList
	if err := k8s.List(ctx, &slices, client.InNamespace(namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: contract.ServiceName}); err != nil {
		return -1
	}
	ready := 0
	for _, slice := range slices.Items {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready {
				ready++
			}
		}
	}
	return ready
}

// podReady reports whether a pod's Ready condition is true.
func podReady(pod corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// describeReplicas renders the replica fraction of a policy for a message.
func describeReplicas(domain string) string {
	p, err := getPolicy(domain)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%s (%s)", p.Status.Replicas.Summary, readyReason(domain)())
}

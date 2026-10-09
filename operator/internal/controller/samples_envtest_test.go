package controller

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	ratelimitv1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// samplesDir holds the sample policies the documentation points at.
var samplesDir = filepath.Join("..", "..", "..", "config", "samples")

// sampleFiles names the sample policies in samplesDir, leaving out the
// kustomization that lists them. It runs while the specs are being built, so
// it reports a failed read as no samples, which the spec that counts them
// turns into a failure.
func sampleFiles() []string {
	paths, err := filepath.Glob(filepath.Join(samplesDir, "*.yaml"))
	if err != nil {
		return nil
	}
	var names []string
	for _, path := range paths {
		if name := filepath.Base(path); name != "kustomization.yaml" {
			names = append(names, name)
		}
	}
	return names
}

// The samples are documentation that runs. A sample the API server rejects
// teaches the wrong schema to whoever copies it, and nothing else in the build
// would notice: they are never applied by a test, a chart, or an install.
var _ = Describe("the samples in config/samples", func() {
	const namespace = "ratelimit-samples"
	samples := sampleFiles()

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		err := k8sClient.Create(ctx, ns)
		if err != nil {
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
	})

	// apply creates the sample of file name in the namespace, deletes it when
	// the spec ends, and returns its key.
	apply := func(name string) client.ObjectKey {
		raw, err := os.ReadFile(filepath.Join(samplesDir, name))
		Expect(err).NotTo(HaveOccurred())
		object := &unstructured.Unstructured{}
		Expect(yaml.Unmarshal(raw, object)).To(Succeed(), "decoding sample %s", name)
		Expect(object.GetKind()).To(Equal("RateLimitPolicy"), "the kind of sample %s", name)
		object.SetNamespace(namespace)

		Expect(k8sClient.Create(ctx, object)).To(Succeed(), "creating sample %s", name)
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed())
		})
		return client.ObjectKeyFromObject(object)
	}

	It("are found", func() {
		Expect(samples).NotTo(BeEmpty(), "no samples were found in %s; has the directory moved?", samplesDir)
	})

	// The reconciler has no probe, so the status it writes reports the fleet
	// unobserved; what the spec establishes is that the API server accepts
	// that status for the sample.
	for _, name := range samples {
		It("reconcile "+name+" once the API server accepts it", func() {
			key := apply(name)
			reconciler := &RateLimitPolicyReconciler{
				Client: k8sClient, Scheme: k8sClient.Scheme(), Namespace: namespace,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})

			Expect(err).NotTo(HaveOccurred(), "Reconcile of sample %s", name)
		})
	}

	// Each sample declares the keys its own rules reference, because a domain
	// is one object. A sample that left a problem behind would be documenting
	// a policy nobody should copy.
	DescribeTable("compile without a single problem",
		func(name string) {
			key := apply(name)
			reconciler := &RateLimitPolicyReconciler{
				Client: k8sClient, Scheme: k8sClient.Scheme(), Namespace: namespace,
			}
			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: key})
			Expect(err).NotTo(HaveOccurred(), "Reconcile of sample %s", name)

			reconciled := &ratelimitv1.RateLimitPolicy{}
			Expect(k8sClient.Get(ctx, key, reconciled)).To(Succeed())
			Expect(reconciled.Status.RuleProblems).To(BeEmpty(), "status.ruleProblems of sample %s", name)
		},
		Entry("the public sample", "ratelimit_v1_ratelimitpolicy_public.yaml"),
		Entry("the tiered sample", "ratelimit_v1_ratelimitpolicy_tiered.yaml"),
		Entry("the private sample", "ratelimit_v1_ratelimitpolicy_private.yaml"),
	)
})

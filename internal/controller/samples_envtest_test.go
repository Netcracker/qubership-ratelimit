package controller

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// The samples are documentation that runs. A sample the API server rejects
// teaches the wrong schema to whoever copies it, and nothing else in the build
// would notice: they are never applied by a test, a chart, or an install.
var _ = Describe("the samples in config/samples", func() {
	const namespace = "ratelimit-samples"

	BeforeEach(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		err := k8sClient.Create(ctx, ns)
		if err != nil {
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
	})

	It("are accepted by the API server, and reconcile", func() {
		paths, err := filepath.Glob(filepath.Join("..", "..", "config", "samples", "*.yaml"))
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).NotTo(BeEmpty(), "no samples were found; has the directory moved?")

		policies := &RateLimitPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		mappings := &RateLimitMappingReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

		for _, path := range paths {
			name := filepath.Base(path)
			if name == "kustomization.yaml" {
				continue
			}

			By("applying " + name)
			raw, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())

			object := &unstructured.Unstructured{}
			Expect(yaml.Unmarshal(raw, object)).To(Succeed())
			object.SetNamespace(namespace)

			Expect(k8sClient.Create(ctx, object)).To(Succeed(), "sample %s", name)
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed())
			})

			By("reconciling " + name)
			request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}
			switch object.GetKind() {
			case "RateLimitPolicy":
				_, err = policies.Reconcile(ctx, request)
			case "RateLimitMapping":
				_, err = mappings.Reconcile(ctx, request)
			default:
				Fail("unexpected kind " + object.GetKind() + " in " + name)
			}
			Expect(err).NotTo(HaveOccurred(), "sample %s", name)
		}
	})

	It("compile without a spec error, and only the problems they document", func() {
		// The public sample carries one rule that references a mapped key, and the
		// mapping sample declares it. Applied together they leave no problem
		// behind, which is the claim the two samples make about each other.
		for _, name := range []string{
			"ratelimit_v1alpha1_ratelimitmapping.yaml",
			"ratelimit_v1alpha1_ratelimitpolicy_public.yaml",
			"ratelimit_v1alpha1_ratelimitpolicy_quote_api.yaml",
		} {
			raw, err := os.ReadFile(filepath.Join("..", "..", "config", "samples", name))
			Expect(err).NotTo(HaveOccurred())

			object := &unstructured.Unstructured{}
			Expect(yaml.Unmarshal(raw, object)).To(Succeed())
			object.SetNamespace(namespace)
			Expect(k8sClient.Create(ctx, object)).To(Succeed(), "sample %s", name)
			DeferCleanup(func() {
				Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, object))).To(Succeed())
			})
		}

		reconciler := &RateLimitPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		for _, policyName := range []string{"order-management", "quote-api-v1"} {
			request := ctrl.Request{NamespacedName: client.ObjectKey{Namespace: namespace, Name: policyName}}
			_, err := reconciler.Reconcile(ctx, request)
			Expect(err).NotTo(HaveOccurred())

			reconciled := &unstructured.Unstructured{}
			reconciled.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   "ratelimit.netcracker.com",
				Version: "v1alpha1",
				Kind:    "RateLimitPolicy",
			})
			Expect(k8sClient.Get(ctx, request.NamespacedName, reconciled)).To(Succeed())

			problems, found, err := unstructured.NestedSlice(reconciled.Object, "status", "ruleProblems")
			Expect(err).NotTo(HaveOccurred())
			Expect(found && len(problems) > 0).To(BeFalse(),
				"sample %s reports %v", policyName, describe(problems))
		}
	})
})

// describe renders the problems of a status for a failure message.
func describe(problems []any) string {
	var reasons []string
	for _, problem := range problems {
		entry, ok := problem.(map[string]any)
		if !ok {
			continue
		}
		reasons = append(reasons, entry["block"].(string)+"/"+entry["rule"].(string)+": "+entry["reason"].(string))
	}
	return strings.Join(reasons, "; ")
}

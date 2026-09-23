package config

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

const testNamespace = "ratelimit-config-envtest"

// The writer against a real API server. What a fake client cannot show is
// the object as the service will mount it: the keys, the manifest under
// data, the payloads under binaryData, and the ownerReference the garbage
// collector reads.
var _ = Describe("the configuration writer", Ordered, func() {
	var (
		store      *Store
		reconciler *Reconciler
	)

	policyWith := func(domain string, blocks ...v1.LimitBlock) *v1.RateLimitPolicy {
		return &v1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: domain},
			Spec:       v1.RateLimitPolicySpec{Domain: domain, Limits: blocks},
		}
	}
	oneRule := func(name string) v1.LimitBlock {
		return v1.LimitBlock{Name: name, Rules: []v1.Rule{{
			Name: "total", Rates: []v1.Rate{{Requests: 10, PeriodSeconds: 60}}}}}
	}
	// wide is a block payload large enough to measure against a small limit:
	// many blocks on disjoint paths with names that compress poorly, under
	// the 128-bucket budget.
	wide := func(prefix string, blocks int) []v1.LimitBlock {
		out := make([]v1.LimitBlock, 0, blocks)
		for i := range blocks {
			out = append(out, v1.LimitBlock{
				Name: fmt.Sprintf("%s-%d-%x", prefix, i, i*2654435761),
				Target: &v1.Target{Routes: []v1.Route{{
					Path: v1.PathMatch{Type: v1.PathMatchPrefix, Value: fmt.Sprintf("/%s/%d/", prefix, i)}}}},
				Rules: []v1.Rule{{Name: fmt.Sprintf("r-%x", i*40503),
					Rates: []v1.Rate{{Requests: int32(100 + i), PeriodSeconds: 60}}}},
			})
		}
		return out
	}
	reconcile := func() {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{
			Namespace: testNamespace, Name: contract.ConfigMapName}})
		Expect(err).NotTo(HaveOccurred())
	}
	read := func() (*corev1.ConfigMap, manifest.Manifest) {
		var object corev1.ConfigMap
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: testNamespace, Name: contract.ConfigMapName},
			&object)).To(Succeed())
		m, err := manifest.Decode([]byte(object.Data[contract.ManifestKey]))
		Expect(err).NotTo(HaveOccurred(), "the manifest the writer wrote does not decode")
		return &object, m
	}
	create := func(policy *v1.RateLimitPolicy) {
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed())
		})
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
	}

	BeforeAll(func() {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
		Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, ns))).To(Succeed())

		store = New(k8sClient, testNamespace, map[string]string{"app.kubernetes.io/managed-by": "test"},
			"0.0.0-test", logf.Log.WithName("config"))
		reconciler = &Reconciler{Client: k8sClient, Namespace: testNamespace, Store: store}
	})
	AfterEach(func() {
		// Every spec starts from no object, so what it reads is what it wrote.
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: contract.ConfigMapName}}))).To(Succeed())
		reconciler.Limit = 0
	})

	It("writes an empty manifest when the namespace holds no policy", func() {
		reconcile()

		object, m := read()
		Expect(m.Domains).To(BeEmpty())
		Expect(m.FormatVersion).To(Equal(manifest.FormatVersion))
		Expect(m.OperatorVersion).To(Equal("0.0.0-test"))
		Expect(object.BinaryData).To(BeEmpty(), "no domain, no payload")
	})

	It("writes one payload and one manifest entry for one domain", func() {
		policy := policyWith("gateway.one", oneRule("a"))
		create(policy)
		reconcile()

		object, m := read()
		Expect(m.Domains).To(HaveLen(1))
		entry := m.Domains["gateway.one"]
		Expect(entry.Generation).To(Equal(policy.Generation))
		Expect(entry.UID).To(Equal(string(policy.UID)))

		raw, ok := object.BinaryData[manifest.PayloadKey("gateway.one")]
		Expect(ok).To(BeTrue(), "the payload key is <domain>.json.gz")
		var spec v1.RateLimitPolicySpec
		hash, err := manifest.DecodePayload(raw, &spec)
		Expect(err).NotTo(HaveOccurred())
		Expect(hash).To(Equal(entry.Hash), "the manifest's hash is the payload's")
		Expect(spec.Domain).To(Equal("gateway.one"))
		Expect(spec.Limits).To(HaveLen(1))
	})

	It("writes every domain of the namespace", func() {
		create(policyWith("gateway.a", oneRule("a")))
		create(policyWith("gateway.b", oneRule("b")))
		reconcile()

		object, m := read()
		Expect(m.Domains).To(HaveKey("gateway.a"))
		Expect(m.Domains).To(HaveKey("gateway.b"))
		Expect(object.BinaryData).To(HaveLen(2))
	})

	It("drops a domain whose policy is gone", func() {
		policy := policyWith("gateway.gone", oneRule("a"))
		create(policy)
		reconcile()
		_, m := read()
		Expect(m.Domains).To(HaveKey("gateway.gone"))

		Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
		reconcile()

		object, m := read()
		Expect(m.Domains).NotTo(HaveKey("gateway.gone"))
		Expect(object.BinaryData).NotTo(HaveKey(manifest.PayloadKey("gateway.gone")),
			"the object is replaced whole; a retired domain's payload does not linger")
	})

	It("keeps a generation that does not fit out, and last-good in", func() {
		small := policyWith("gateway.size", oneRule("a"))
		create(small)
		reconcile()
		_, m := read()
		Expect(m.Domains["gateway.size"].Generation).To(Equal(int64(1)))

		// A limit the small generation fits and the wide one does not.
		reconciler.Limit = 1024
		var latest v1.RateLimitPolicy
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(small), &latest)).To(Succeed())
		latest.Spec.Limits = wide("wide", 100)
		Expect(k8sClient.Update(ctx, &latest)).To(Succeed())
		Expect(latest.Generation).To(Equal(int64(2)))
		reconcile()

		object, m := read()
		Expect(m.Domains["gateway.size"].Generation).To(Equal(int64(1)),
			"the generation that does not fit is not written; last-good stays")
		var spec v1.RateLimitPolicySpec
		_, err := manifest.DecodePayload(object.BinaryData[manifest.PayloadKey("gateway.size")], &spec)
		Expect(err).NotTo(HaveOccurred())
		Expect(spec.Limits).To(HaveLen(1), "the payload is the last-good spec")
	})

	It("recreates the object when it is deleted", func() {
		create(policyWith("gateway.back", oneRule("a")))
		reconcile()
		object, _ := read()
		Expect(k8sClient.Delete(ctx, object)).To(Succeed())
		Eventually(func() bool {
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(object), &corev1.ConfigMap{})
			return apierrors.IsNotFound(err)
		}).WithTimeout(10 * time.Second).Should(BeTrue())

		reconcile()

		_, m := read()
		Expect(m.Domains).To(HaveKey("gateway.back"), "the recreated object carries the namespace's state again")
	})

	It("owns the object through the operator's Deployment", func() {
		deployment := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "ratelimit-operator"},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "op"}},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "op"}},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{
						Name: "operator", Image: "example/operator"}}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, deployment)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, deployment))).To(Succeed()) })
		store.SetOwner(deployment, "apps/v1", "Deployment")
		DeferCleanup(func() { store.owner = nil })

		reconcile()

		object, _ := read()
		Expect(object.OwnerReferences).To(HaveLen(1))
		Expect(object.OwnerReferences[0].Kind).To(Equal("Deployment"))
		Expect(object.OwnerReferences[0].Name).To(Equal("ratelimit-operator"))
		Expect(object.OwnerReferences[0].UID).To(Equal(deployment.UID),
			"the ConfigMap goes with the operator, never with a policy")
	})

	It("reads back what it wrote as last-good", func() {
		policy := policyWith("gateway.read", oneRule("a"))
		create(policy)
		reconcile()

		bundles, err := store.Load(ctx, []string{"gateway.read", "gateway.absent"})
		Expect(err).NotTo(HaveOccurred())
		Expect(bundles).To(HaveLen(1))
		Expect(bundles["gateway.read"].UID).To(Equal(string(policy.UID)))
		Expect(bundles["gateway.read"].GoodGeneration).To(Equal(policy.Generation))
		Expect(bundles["gateway.read"].GoodSpec.Domain).To(Equal("gateway.read"))
	})
})

var _ = Describe("the writer's registration", func() {
	It("registers with a manager", func() {
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: k8sClient.Scheme()})
		Expect(err).NotTo(HaveOccurred())
		r := &Reconciler{Client: mgr.GetClient(), Namespace: testNamespace,
			Store: New(k8sClient, testNamespace, nil, "t", logf.Log)}
		Expect(r.SetupWithManager(mgr)).To(Succeed())
	})
})

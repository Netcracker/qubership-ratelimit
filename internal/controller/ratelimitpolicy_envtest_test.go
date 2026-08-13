package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ratelimitv1alpha1 "github.com/netcracker/qubership-ratelimit-operator/api/v1alpha1"
)

var _ = Describe("RateLimitPolicy", func() {
	const namespace = "ratelimit-envtest"

	var reconciler *RateLimitPolicyReconciler

	BeforeEach(func() {
		reconciler = &RateLimitPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		err := k8sClient.Create(ctx, ns)
		if err != nil {
			Expect(client.IgnoreAlreadyExists(err)).To(Succeed())
		}
	})

	It("rejects a policy without a domain", func() {
		policy := &ratelimitv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "no-domain"},
		}

		Expect(k8sClient.Create(ctx, policy)).To(MatchError(ContainSubstring("spec.domain")))
	})

	It("rejects an empty domain", func() {
		policy := &ratelimitv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "empty-domain"},
			Spec:       ratelimitv1alpha1.RateLimitPolicySpec{Domain: ""},
		}

		Expect(k8sClient.Create(ctx, policy)).To(MatchError(ContainSubstring("should be at least 1 chars long")))
	})

	It("accepts a policy and records the generation it saw", func() {
		name := types.NamespacedName{Namespace: namespace, Name: "public-gateway"}
		policy := &ratelimitv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name},
			Spec:       ratelimitv1alpha1.RateLimitPolicySpec{Domain: "gateway.public"},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed())
		})

		By("reconciling the created resource")
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		reconciled := &ratelimitv1alpha1.RateLimitPolicy{}
		Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
		Expect(reconciled.Status.ObservedGeneration).To(Equal(reconciled.Generation))

		accepted := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
		Expect(accepted).NotTo(BeNil())
		Expect(accepted.Status).To(Equal(metav1.ConditionTrue))
		Expect(accepted.Reason).To(Equal("Accepted"))
		Expect(accepted.ObservedGeneration).To(Equal(reconciled.Generation))

		By("keeping the spec out of the status subresource")
		Expect(reconciled.Spec.Domain).To(Equal("gateway.public"))
	})

	It("tracks a spec change through a new generation", func() {
		name := types.NamespacedName{Namespace: namespace, Name: "moving-gateway"}
		policy := &ratelimitv1alpha1.RateLimitPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: name.Namespace, Name: name.Name},
			Spec:       ratelimitv1alpha1.RateLimitPolicySpec{Domain: "gateway.public"},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, policy))).To(Succeed())
		})
		_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		By("changing the domain the policy binds to")
		updated := &ratelimitv1alpha1.RateLimitPolicy{}
		Expect(k8sClient.Get(ctx, name, updated)).To(Succeed())
		updated.Spec.Domain = "gateway.private"
		Expect(k8sClient.Update(ctx, updated)).To(Succeed())

		_, err = reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: name})
		Expect(err).NotTo(HaveOccurred())

		reconciled := &ratelimitv1alpha1.RateLimitPolicy{}
		Expect(k8sClient.Get(ctx, name, reconciled)).To(Succeed())
		Expect(reconciled.Status.ObservedGeneration).To(Equal(reconciled.Generation))
		accepted := meta.FindStatusCondition(reconciled.Status.Conditions, ratelimitv1alpha1.ConditionAccepted)
		Expect(accepted).NotTo(BeNil())
		Expect(accepted.Message).To(ContainSubstring("gateway.private"))
	})

	It("ignores a policy that is already gone", func() {
		_, err := reconciler.Reconcile(ctx, ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: namespace, Name: "never-existed"},
		})

		Expect(err).NotTo(HaveOccurred())
	})
})

//go:build e2e

// Package e2e drives the operator in a real cluster. It installs nothing and
// uninstalls nothing: CI installs Istio, the gateways, and the chart first,
// then runs this suite - the same split the bash suites use, which this
// package replaces one suite at a time.
//
// Environment:
//
//	NAMESPACE - business namespace holding the release (default: core)
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

var (
	ctx       context.Context
	k8s       client.Client
	clientset *kubernetes.Clientset
	namespace string
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ratelimit e2e")
}

var _ = BeforeSuite(func() {
	ctx = context.Background()
	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(3 * time.Second)

	namespace = os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "core"
	}

	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred(), "no kubeconfig; the suite needs a cluster with the chart installed")

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(v1alpha1.AddToScheme(scheme)).To(Succeed())
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	clientset, err = kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	// Preflight, so a missing install fails with a plain sentence rather than
	// somewhere inside a test with a confusing one.
	Expect(k8s.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})).
		To(Succeed(), "namespace %s not found", namespace)

	var deployments appsv1.DeploymentList
	Expect(k8s.List(ctx, &deployments, client.InNamespace(namespace),
		client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"})).To(Succeed())
	Expect(deployments.Items).NotTo(BeEmpty(),
		"no ratelimit Deployment in %s; install the chart before running the suite", namespace)
	operator := deployments.Items[0].Name
	Eventually(func() bool {
		var d appsv1.Deployment
		if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: operator}, &d); err != nil {
			return false
		}
		return d.Status.ReadyReplicas == *d.Spec.Replicas
	}).Should(BeTrue(), "the ratelimit deployment is not ready")
})

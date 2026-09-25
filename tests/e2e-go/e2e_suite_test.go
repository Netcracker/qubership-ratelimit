//go:build e2e

// Package e2e drives the two components in a real cluster. It installs
// nothing and uninstalls nothing: CI installs Istio, the gateways, and the
// two charts first, the operator and then the service, and then runs this
// suite.
//
// Environment:
//
//	NAMESPACE - business namespace holding the release (default: core)
//	E2E_SATELLITE_NAMESPACE - a satellite of that namespace: its own gateways
//	    and both charts in satellite mode. Optional; the composite suite skips
//	    without it, and every other suite runs against NAMESPACE alone.
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

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

var (
	ctx       context.Context
	k8s       client.Client
	clientset *kubernetes.Clientset
	namespace string

	// satellite is the namespace installed as a satellite of namespace, or
	// empty when the stand has none.
	satellite string
)

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ratelimit e2e")
}

var _ = BeforeSuite(func() {
	ctx = context.Background()
	// The default wait covers the kubelet's projection at its production period
	// plus the operator's probe cycle; see propagationTimeout.
	SetDefaultEventuallyTimeout(propagationTimeout)
	SetDefaultEventuallyPollingInterval(3 * time.Second)

	namespace = os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "core"
	}
	satellite = os.Getenv("E2E_SATELLITE_NAMESPACE")

	cfg, err := config.GetConfig()
	Expect(err).NotTo(HaveOccurred(), "no kubeconfig; the suite needs a cluster with the chart installed")

	scheme := runtime.NewScheme()
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())
	Expect(v1.AddToScheme(scheme)).To(Succeed())
	k8s, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())
	clientset, err = kubernetes.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	// Preflight, so a missing install fails with a plain sentence rather than
	// somewhere inside a test with a confusing one.
	Expect(k8s.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})).
		To(Succeed(), "namespace %s not found", namespace)

	// Both halves of the split have to be up: the operator that writes the
	// status and the configuration, and the service replicas that enforce
	// it. A service alone waits NotReady for an operator that never comes,
	// and an operator alone reports NoReplicas on every policy.
	for _, chart := range []string{operatorChart, serviceChart} {
		var deployments appsv1.DeploymentList
		Expect(k8s.List(ctx, &deployments, client.InNamespace(namespace),
			client.MatchingLabels{"app.kubernetes.io/name": chart})).To(Succeed())
		Expect(deployments.Items).NotTo(BeEmpty(),
			"no %s Deployment in %s; install both charts before running the suite", chart, namespace)
		name := deployments.Items[0].Name
		Eventually(func() bool {
			var d appsv1.Deployment
			if err := k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &d); err != nil {
				return false
			}
			return d.Status.ReadyReplicas == *d.Spec.Replicas
		}).Should(BeTrue(), "the %s deployment is not ready", name)
	}
})

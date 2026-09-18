//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/transport/spdy"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
)

// The two charts of the split label their pods with the chart name under
// app.kubernetes.io/name: ratelimit-operator on the one operator pod,
// ratelimit-service on the service replicas. Releases can be called
// anything, and CI names them after the chart plus a suffix so that the
// suite cannot mistake a name derived from the release for a fixed one.
const (
	operatorChart = "ratelimit-operator"
	serviceChart  = "ratelimit-service"
)

// chartDeployment resolves the one Deployment of a chart by its label.
func chartDeployment(chart string) string {
	var deployments appsv1.DeploymentList
	Expect(k8s.List(ctx, &deployments, client.InNamespace(namespace),
		client.MatchingLabels{"app.kubernetes.io/name": chart})).To(Succeed())
	Expect(deployments.Items).To(HaveLen(1), "expected one %s Deployment in %s", chart, namespace)
	return deployments.Items[0].Name
}

// serviceDeployment is the Deployment of the service replicas, the ones that
// answer checks; operatorDeployment is the Deployment of the operator, the
// one that writes the status and the configuration.
func serviceDeployment() string  { return chartDeployment(serviceChart) }
func operatorDeployment() string { return chartDeployment(operatorChart) }

// chartPods lists the running pods of a chart.
func chartPods(chart string) []corev1.Pod {
	var pods corev1.PodList
	Expect(k8s.List(ctx, &pods, client.InNamespace(namespace),
		client.MatchingLabels{"app.kubernetes.io/name": chart})).To(Succeed())
	running := make([]corev1.Pod, 0, len(pods.Items))
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			running = append(running, p)
		}
	}
	return running
}

// servicePods are the running service replicas; operatorPods the running
// operator pods, one outside a rollout.
func servicePods() []corev1.Pod  { return chartPods(serviceChart) }
func operatorPods() []corev1.Pod { return chartPods(operatorChart) }

// execPod runs one command in a container and returns its stdout - the
// kubectl exec of the suite.
func execPod(pod, container string, command ...string) (string, error) {
	return execPodIn(namespace, pod, container, command...)
}

func execPodIn(ns, pod, container string, command ...string) (string, error) {
	cfg, err := ctrlconfig.GetConfig()
	if err != nil {
		return "", err
	}
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("exec").
		Param("stdout", "true").Param("stderr", "true")
	if container != "" {
		req.Param("container", container)
	}
	for _, c := range command {
		req.Param("command", c)
	}
	executor, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// forwardToPod opens a port-forward to one pod port and returns the local
// address plus a stop function - the suite's kubectl port-forward.
func forwardToPod(pod string, port int) (string, func()) {
	return forwardToPodIn(namespace, pod, port)
}

// forwardToPodIn is forwardToPod for a pod outside the release namespace: the
// satellite suite reaches gateways that live in a namespace of their own.
func forwardToPodIn(ns, pod string, port int) (string, func()) {
	cfg, err := ctrlconfig.GetConfig()
	Expect(err).NotTo(HaveOccurred())
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	Expect(err).NotTo(HaveOccurred())
	url := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(ns).Name(pod).SubResource("portforward").URL()
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, "POST", url)

	stopCh := make(chan struct{})
	readyCh := make(chan struct{})
	fw, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"},
		[]string{fmt.Sprintf("0:%d", port)}, stopCh, readyCh, io.Discard, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	go func() {
		defer GinkgoRecover()
		_ = fw.ForwardPorts()
	}()
	select {
	case <-readyCh:
	case <-time.After(20 * time.Second):
		close(stopCh)
		Fail(fmt.Sprintf("port-forward to %s:%d never became ready", pod, port))
	}
	ports, err := fw.GetPorts()
	Expect(err).NotTo(HaveOccurred())
	return fmt.Sprintf("127.0.0.1:%d", ports[0].Local), func() { close(stopCh) }
}

// gatewayPod resolves one pod that serves the gateway.
func gatewayPod(gateway string) corev1.Pod {
	return gatewayPodIn(namespace, gateway)
}

func gatewayPodIn(ns, gateway string) corev1.Pod {
	var pods corev1.PodList
	Expect(k8s.List(ctx, &pods, client.InNamespace(ns),
		client.MatchingLabels{"gateway.networking.k8s.io/gateway-name": gateway})).To(Succeed())
	Expect(pods.Items).NotTo(BeEmpty(), "no pod serves gateway %s in %s", gateway, ns)
	return pods.Items[0]
}

// gatewayEndpoint resolves the pod and container port behind the gateway
// Service's HTTP port, the way kubectl port-forward svc/... would.
func gatewayEndpoint(gateway string) (string, int) {
	return gatewayEndpointIn(namespace, gateway)
}

func gatewayEndpointIn(ns, gateway string) (string, int) {
	var svc corev1.Service
	Expect(k8s.Get(ctx, client.ObjectKey{Namespace: ns, Name: gateway + "-istio"}, &svc)).
		To(Succeed(), "no Service for gateway %s in %s", gateway, ns)
	var target intstr.IntOrString
	for _, p := range svc.Spec.Ports {
		if p.Port == 8080 {
			target = p.TargetPort
			break
		}
	}
	Expect(target).NotTo(Equal(intstr.IntOrString{}), "the %s-istio Service has no port 8080", gateway)

	pod := gatewayPodIn(ns, gateway)

	if target.Type == intstr.Int {
		return pod.Name, target.IntValue()
	}
	for _, c := range pod.Spec.Containers {
		for _, cp := range c.Ports {
			if cp.Name == target.StrVal {
				return pod.Name, int(cp.ContainerPort)
			}
		}
	}
	Fail(fmt.Sprintf("gateway pod %s carries no port named %q", pod.Name, target.StrVal))
	return "", 0
}

// gatewayGet sends one request through a gateway; 0 stands for a transport
// error, the bash suites' 000.
func gatewayGet(gateway, path string, headers map[string]string) int {
	return gatewayBurst(gateway, path, 1, headers)[0]
}

func gatewayGetIn(ns, gateway, path string, headers map[string]string) int {
	return gatewayBurstIn(ns, gateway, path, 1, headers)[0]
}

// gatewayGetBody sends one request through a gateway and returns the body
// with the status code; 0 stands for a transport error, as gatewayGet does.
// The bursts above discard bodies, which is all a rate-limit code needs; an
// API answer has to be read.
func gatewayGetBody(gateway, path string, headers map[string]string) (string, int) {
	return gatewayRequest(gateway, http.MethodGet, path, "", headers)
}

// gatewayRequest is gatewayGetBody with a method and a body: the management
// suite drives mutations through the gateway with it. A JSON body is sent as
// such; an empty body sends none.
func gatewayRequest(gateway, method, path, body string, headers map[string]string) (string, int) {
	pod, port := gatewayEndpoint(gateway)
	addr, stop := forwardToPod(pod, port)
	defer stop()

	var payload io.Reader
	if body != "" {
		payload = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+addr+path, payload)
	Expect(err).NotTo(HaveOccurred())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Mutations wait longer than a probe: a bulk sweep runs to its recorded
	// outcome inside the call.
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err.Error(), 0
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	return string(answer), resp.StatusCode
}

// gatewayBurst mirrors curl_gw_burst: one port-forward, sequential requests,
// one status code each.
func gatewayBurst(gateway, path string, count int, headers map[string]string) []int {
	return gatewayBurstIn(namespace, gateway, path, count, headers)
}

func gatewayBurstIn(ns, gateway, path string, count int, headers map[string]string) []int {
	pod, port := gatewayEndpointIn(ns, gateway)
	addr, stop := forwardToPodIn(ns, pod, port)
	defer stop()

	httpClient := &http.Client{Timeout: 10 * time.Second}
	codes := make([]int, 0, count)
	for i := 0; i < count; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
		Expect(err).NotTo(HaveOccurred())
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			codes = append(codes, 0)
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	return codes
}

// waitGatewayServes warms a gateway up until the routed probe answers a
// terminal code - the bash wait_for_gateway.
func waitGatewayServes(gateway, path string) {
	waitGatewayServesIn(namespace, gateway, path)
}

func waitGatewayServesIn(ns, gateway, path string) {
	Eventually(func() bool {
		code := gatewayGetIn(ns, gateway, path, nil)
		return (code >= 200 && code < 300) || code == 404
	}).WithTimeout(2*time.Minute).WithPolling(2*time.Second).Should(BeTrue(),
		"the gateway %s in %s never served %s", gateway, ns, path)
}

// podLogs returns one pod's log, whole when since is nil. serviceLogsSince
// concatenates every replica; this is for the assertions that need to know
// which replica wrote a line.
func podLogs(pod string, since *time.Time) string {
	opts := &corev1.PodLogOptions{}
	if since != nil {
		t := metav1.NewTime(*since)
		opts.SinceTime = &t
	}
	stream, err := clientset.CoreV1().Pods(namespace).GetLogs(pod, opts).Stream(ctx)
	if err != nil {
		return ""
	}
	defer func() { _ = stream.Close() }()
	logs, _ := io.ReadAll(stream)
	return string(logs)
}

// rolloutRestart is kubectl rollout restart plus its status wait. A restart
// goes through a rollout rather than a pod deletion: deleting pods leaves the
// Deployment's generation untouched, so a status wait racing the controller
// can report success while the replacement is still coming up. The annotation
// bump makes the wait real, and surge brings the new pod up before the old
// one goes.
func rolloutRestart(name string) {
	rolloutRestartNoWait(name)
	waitRolloutSettled(name)
}

// rolloutRestartNoWait bumps the template and returns at once, for a spec
// that expects the rollout to stall on a replacement that never turns Ready.
func rolloutRestartNoWait(name string) {
	var dep appsv1.Deployment
	Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &dep)).To(Succeed())
	if dep.Spec.Template.Annotations == nil {
		dep.Spec.Template.Annotations = map[string]string{}
	}
	dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
	Expect(k8s.Update(ctx, &dep)).To(Succeed())
}

// waitRolloutSettled waits until every replica of the Deployment is updated
// and available.
func waitRolloutSettled(name string) {
	Eventually(func(g Gomega) {
		var d appsv1.Deployment
		g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &d)).To(Succeed())
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		g.Expect(d.Status.ObservedGeneration).To(BeNumerically(">=", d.Generation))
		g.Expect(d.Status.UpdatedReplicas).To(Equal(want))
		g.Expect(d.Status.Replicas).To(Equal(want))
		g.Expect(d.Status.AvailableReplicas).To(Equal(want))
	}).WithTimeout(3*time.Minute).WithPolling(3*time.Second).Should(Succeed(),
		"the %s Deployment did not come back after the restart", name)
}

// helmScale sets the service release's replica count through Helm: a kubectl
// scale would take field-manager ownership of .spec.replicas and make every
// later helm upgrade conflict.
//
// Values are reset to the chart's defaults and re-overlaid with what the
// install set, rather than reused wholesale: a release installed from an
// older chart lacks the values that chart has grown since, and reusing them
// fails the render on the first new required value.
func helmScale(release string, replicas int32) {
	chart, err := filepath.Abs(filepath.Join("..", "..", "helm-templates", serviceChart))
	Expect(err).NotTo(HaveOccurred())
	cmd := exec.CommandContext(ctx, "helm", "upgrade", release, chart,
		"-n", namespace, "--reset-then-reuse-values",
		"--set", fmt.Sprintf("REPLICAS=%d", replicas),
		"--wait", "--timeout", "3m")
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "helm upgrade failed: %s", out)
}

// fleetScale is the service release scaled for one container, remembering
// what to put back. The suites that need more than one replica, a rollout
// with a surviving replica, a follower the operator cannot reach, go through
// it so that the scale-up and the restore are one pair, and a container that
// fails halfway leaves the release the size it found it.
type fleetScale struct {
	release  string
	original int32
}

// scaleFleet sets the replica count of the service release and returns what
// restores it. The release and its current count are read from the
// Deployment rather than assumed.
func scaleFleet(replicas int32) *fleetScale {
	var dep appsv1.Deployment
	Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: serviceDeployment()}, &dep)).
		To(Succeed())
	release := dep.Annotations["meta.helm.sh/release-name"]
	Expect(release).NotTo(BeEmpty(), "cannot determine the Helm release owning %s", dep.Name)
	scale := &fleetScale{release: release, original: 1}
	if dep.Spec.Replicas != nil {
		scale.original = *dep.Spec.Replicas
	}
	helmScale(release, replicas)
	return scale
}

func (f *fleetScale) restore() {
	helmScale(f.release, f.original)
}

// scaleDeployment sets a Deployment's replica count through the scale
// subresource and waits for the count to settle. It is for the operator,
// whose chart has no replica value to go through Helm with: the scale
// subresource leaves its own field manager on .spec.replicas, and a later
// helm upgrade that applies the same value as the chart's meets no
// conflict, so a suite that puts the count back leaves the release clean.
func scaleDeployment(name string, replicas int32) {
	scale, err := clientset.AppsV1().Deployments(namespace).GetScale(ctx, name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	scale.Spec.Replicas = replicas
	_, err = clientset.AppsV1().Deployments(namespace).UpdateScale(ctx, name, scale, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		var d appsv1.Deployment
		g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &d)).To(Succeed())
		g.Expect(d.Status.Replicas).To(Equal(replicas))
		g.Expect(d.Status.ReadyReplicas).To(Equal(replicas))
		// The Deployment's count leaves a terminating pod out, and a
		// terminating operator keeps writing until its grace period ends:
		// a spec that scaled it to zero has to see every pod gone.
		var pods corev1.PodList
		g.Expect(k8s.List(ctx, &pods, client.InNamespace(namespace),
			client.MatchingLabels(d.Spec.Selector.MatchLabels))).To(Succeed())
		g.Expect(pods.Items).To(HaveLen(int(replicas)), "pods of %s still around", name)
	}).WithTimeout(3*time.Minute).WithPolling(2*time.Second).Should(Succeed(),
		"the %s Deployment did not settle at %d replicas", name, replicas)
}

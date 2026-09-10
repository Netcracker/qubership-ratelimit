//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The management port is reachable through the private gateway and nowhere
// else. Both halves of that are cluster behavior: the render checks in
// go-build.yml prove the chart writes the right principal into the policy,
// and nothing in them shows that ztunnel enforces it or that the gateway
// routes to 8082. Only this suite does.
//
// The full set of management scenarios is a separate task; what is here is the
// reachability contract the port and its AuthorizationPolicy ship as one
// change.
var _ = Describe("the management port through the private gateway", Ordered, Label("management"), func() {
	const (
		domain   = "gateway.management"
		route    = "e2e-management"
		outsider = "e2e-management-outsider"
		basePath = "/ratelimit/v1"
	)
	var (
		applied bool
		port    int32
	)

	BeforeAll(func() {
		port = managementPort()
		if port == 0 {
			Skip("the release runs without management.enabled; the chart renders no management port")
		}

		Expect(apply(newPolicy(domain, totalLimits(10, 60)))).To(Succeed())
		applied = true

		// The chart ships no HTTPRoute: on the platform the route to an
		// internal API is the deployer's, not this chart's. The suite makes
		// its own so the request travels the path the policy is written for -
		// through the gateway's identity, not a port-forward.
		Expect(apply(managementRoute(route, basePath, port))).To(Succeed())

		// The single gate, on the answer the specs actually read. There is no
		// waitGatewayServes warm-up first, because this suite routes no probe
		// to the echo backend: the mesh fallback answers an unrouted path with
		// a 503 forever, so a warm-up on a path outside the echo route never
		// reaches a terminal code. It carries the token because the
		// unauthenticated answer is a 401 either way.
		//
		// The condition is the domain, not the status code. Three things
		// arrive at their own pace here - a cold gateway, the route reaching
		// it, and the policy reaching the rule store this API reads - and a
		// 200 only covers the first two: the listing answers 200 with an empty
		// set for as long as the store is still rebuilding, which on a fast
		// runner is exactly where the first spec used to land.
		Eventually(func() []string {
			body, code := gatewayGetBody("private-gateway", basePath+"/domains",
				map[string]string{"Authorization": "Bearer " + managementToken("e2e@example.com", "viewer")})
			if code != http.StatusOK {
				return nil
			}
			domains, err := listedDomains(body)
			if err != nil {
				return nil
			}
			return domains
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(ContainElement(domain),
			"the private gateway never served %s with the domain this suite applied", basePath)
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
			_ = k8s.Delete(ctx, managementRoute(route, basePath, port))
			_ = k8s.Delete(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: outsider}})
		}
	})

	It("answers a viewer through the gateway and lists the domain", func() {
		body, code := gatewayGetBody("private-gateway", basePath+"/domains",
			map[string]string{"Authorization": "Bearer " + managementToken("e2e@example.com", "viewer")})
		Expect(code).To(Equal(http.StatusOK),
			"the gateway did not reach the management port; body: %s", body)

		domains, err := listedDomains(body)
		Expect(err).NotTo(HaveOccurred(), "body: %s", body)
		Expect(domains).To(ContainElement(domain),
			"the listing does not carry the domain this suite applied")
	})

	It("refuses a caller outside the allowed list", func() {
		// The same request the gateway just got a 200 for, sent from a pod
		// under the default ServiceAccount, which the policy does not name.
		//
		// It is an HTTP request rather than a TCP connect on purpose: with a
		// waypoint in the namespace the connect terminates at the waypoint and
		// succeeds whatever the destination policy says, so a handshake proves
		// nothing. What the answer has to show is that the API never saw the
		// request - it answers 200 with this token and 401 without one, so
		// neither code may come back.
		code, body := httpProbeFromPod(outsider,
			fmt.Sprintf("http://%s:%d%s/domains", serviceHost(), port, basePath),
			"Authorization: Bearer "+managementToken("outsider@example.com", "viewer"))

		Expect(code).NotTo(Equal(http.StatusOK),
			"a pod outside the allowed list read the enforced rule set; body: %s", body)

		// The code alone cannot say who answered: the mesh refuses with a 403
		// of its own, and so does the API for a token without the role. What
		// separates them is the body, because every answer the API writes is
		// either a listing or a TMF error carrying an RLS code. A refusal that
		// carries neither never reached the service.
		if code != 0 {
			Expect(body).NotTo(ContainSubstring(errorCodePrefix),
				"the refusal came from the API, so the port is open to the whole mesh")
			Expect(body).NotTo(ContainSubstring(`"items"`),
				"the API answered a pod outside the allowed list")
		}
	})
})

// managementPort reports the container port the release exposes for the
// management API, 0 when the chart rendered without it.
func managementPort() int32 {
	pods := operatorPods()
	Expect(pods).NotTo(BeEmpty(), "no running replica to read the ports of")
	for _, c := range pods[0].Spec.Containers {
		for _, p := range c.Ports {
			if p.Name == "management" {
				return p.ContainerPort
			}
		}
	}
	return 0
}

// serviceHost is the release's Service, which is what an in-mesh caller
// resolves and what ztunnel applies the policy to.
func serviceHost() string {
	var services corev1.ServiceList
	Expect(k8s.List(ctx, &services, client.InNamespace(namespace),
		client.MatchingLabels{"app.kubernetes.io/name": "ratelimit"})).To(Succeed())
	Expect(services.Items).NotTo(BeEmpty(), "no ratelimit Service in %s", namespace)
	return services.Items[0].Name + "." + namespace + ".svc.cluster.local"
}

// managementRoute attaches one prefix of the private gateway to the release's
// management port. Unstructured rather than typed: this is the only Gateway
// API object the suite writes, and it is not worth the dependency.
func managementRoute(name, prefix string, port int32) *unstructured.Unstructured {
	route := &unstructured.Unstructured{}
	route.SetAPIVersion("gateway.networking.k8s.io/v1")
	route.SetKind("HTTPRoute")
	route.SetNamespace(namespace)
	route.SetName(name)
	route.Object["spec"] = map[string]any{
		"parentRefs": []any{map[string]any{"name": "private-gateway"}},
		"rules": []any{map[string]any{
			"matches": []any{map[string]any{
				"path": map[string]any{"type": "PathPrefix", "value": prefix},
			}},
			"backendRefs": []any{map[string]any{
				"name": strings.SplitN(serviceHost(), ".", 2)[0],
				"port": int64(port),
			}},
		}},
	}
	return route
}

// managementToken builds the alg-none token the management API reads. The
// service never verifies the signature - the gateway's JWT filter does - so
// the suite needs no signing key, and the AuthorizationPolicy is what keeps
// that from being a way in.
func managementToken(subject string, roles ...string) string {
	seg := func(v any) string {
		raw, err := json.Marshal(v)
		Expect(err).NotTo(HaveOccurred())
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := seg(map[string]string{"alg": "none", "typ": "JWT"})
	payload := seg(map[string]any{"sub": subject, "roles": roles})
	return header + "." + payload + "."
}

// errorCodePrefix opens every code the API puts in a TMF error, which is how
// an answer it wrote is told apart from one the mesh wrote for it.
const errorCodePrefix = "RLS-"

// httpProbeFromPod sends one request from a short-lived pod under the default
// ServiceAccount and returns the status code with the body. The code is 0 when
// nothing answered - the shape a reset connection arrives in, and the reason
// the pod reports the code rather than failing on it.
func httpProbeFromPod(name, url, header string) (int, string) {
	const marker = "HTTP:"
	log := runInNamespace(name, []string{"sh", "-c", fmt.Sprintf(
		"curl -sS -w '\\n%s%%{http_code}\\n' --max-time 15 -H %q %q || true",
		marker, header, url)})

	lines := strings.Split(log, "\n")
	for i, line := range lines {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), marker)
		if !found {
			continue
		}
		code, err := strconv.Atoi(rest)
		Expect(err).NotTo(HaveOccurred(), "the probe wrote an unreadable code: %s", line)
		return code, strings.Join(lines[:i], "\n")
	}
	Fail(fmt.Sprintf("the probe pod reported no status code; log: %s", log))
	return -1, ""
}

// runInNamespace runs one short-lived pod under the default ServiceAccount and
// returns its log, whatever the exit code: a refused connection is the result
// this suite reads, not a failure of the probe.
func runInNamespace(name string, command []string) string {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:    "probe",
				Image:   "curlimages/curl:8.11.1",
				Command: command,
			}},
		},
	}
	_ = k8s.Delete(ctx, pod)
	Eventually(func() bool {
		err := k8s.Get(ctx, client.ObjectKeyFromObject(pod), &corev1.Pod{})
		return apierrors.IsNotFound(err)
	}).WithTimeout(time.Minute).Should(BeTrue(), "the previous probe pod never went away")
	Expect(k8s.Create(ctx, pod)).To(Succeed())

	var finished corev1.Pod
	Eventually(func(g Gomega) {
		g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(pod), &finished)).To(Succeed())
		g.Expect(finished.Status.Phase).To(BeElementOf(corev1.PodSucceeded, corev1.PodFailed))
	}).WithTimeout(3*time.Minute).Should(Succeed(), "the probe pod never finished")

	return podLogs(name, nil)
}

// listedDomains reads the domains out of a GET /domains body. It is shared by
// the readiness gate and the spec so that the two agree on what "the listing
// carries the domain" means.
func listedDomains(body string) ([]string, error) {
	var listing struct {
		Items []struct {
			Domain string `json:"domain"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &listing); err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(listing.Items))
	for _, item := range listing.Items {
		domains = append(domains, item.Domain)
	}
	return domains, nil
}

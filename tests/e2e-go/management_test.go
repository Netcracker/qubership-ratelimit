//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
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
		unlisted = "e2e-management-unlisted"
		basePath = "/ratelimit/v1"
	)
	var (
		applied bool
		port    int32

		// The reset flows need counters to reset, and gateway.management has
		// no gateway sending it. gateway.private does, so a second policy
		// limits one path there, and the private gateway spends its budget
		// before each flow lifts it. Two requests, GCRA, so the third is
		// refused for half an hour with no calendar boundary in the way.
		limitedApplied bool
	)
	const (
		limitedDomain = "gateway.private"
		limitedPrefix = "/e2e-management-reset"
		limitedRule   = "probe/per-path"
		limit         = 2
	)

	BeforeAll(func() {
		port = managementPort()
		if port == 0 {
			Skip("the release runs without management.enabled; the chart renders no management port")
		}

		Expect(apply(newPolicy(domain, totalLimits(10, 60)))).To(Succeed())
		applied = true

		// The listing reads the snapshot a replica swaps in once the generation
		// compiles, and the gateway may reach any replica, so the policy has to
		// be enforced everywhere before a listing can be expected to carry it.
		Eventually(policyCondition(domain, v1.ConditionReady)).WithTimeout(2*time.Minute).
			Should(Equal("True"), "the policy of this suite never became Ready")

		// The chart ships no HTTPRoute: on the platform the route to an
		// internal API is the platform's, not this chart's. The suite makes
		// its own so the request travels the path the policy is written for -
		// through the gateway's identity, not a port-forward.
		Expect(apply(managementRoute(route, basePath, port))).To(Succeed())

		// The single gate, on the path the specs actually use. There is no
		// waitGatewayServes warm-up first, because this suite routes no probe
		// to the echo backend: the mesh fallback answers an unrouted path with
		// a 503 forever, so a warm-up on a path outside the echo route never
		// reaches a terminal code. Waiting for a listing that carries the
		// domain covers a cold gateway, a route that has not reached it yet,
		// and a replica that has not swapped the snapshot in, and it carries
		// the token because the unauthenticated answer is a 401 either way. A
		// bare 200 used to be the gate, and a listing without the domain
		// passed it.
		Eventually(func() []string {
			body, code := gatewayGetBody("private-gateway", basePath+"/domains",
				map[string]string{"Authorization": "Bearer " + managementToken()})
			if code != http.StatusOK {
				return nil
			}
			domains, _ := listedDomains(body)
			return domains
		}).WithTimeout(2*time.Minute).WithPolling(3*time.Second).Should(ContainElement(domain),
			"the private gateway never served a listing with %s through %s", domain, basePath)
	})
	AfterAll(func() {
		if applied {
			// The route and the probe pod go first: the cleanup wait can fail,
			// and nothing after a failed step in this closure runs.
			_ = k8s.Delete(ctx, managementRoute(route, basePath, port))
			_ = k8s.Delete(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: outsider}})
			_ = k8s.Delete(ctx, &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: unlisted}})
			deletePolicies(domain)
		}
		// Last, because the cleanup wait inside can fail and end this closure:
		// nothing below it would run, and the route and the pod above would
		// leak.
		if limitedApplied {
			deletePolicies(limitedDomain)
		}
	})

	It("lists the domain to a viewer through the gateway", func() {
		body, code := gatewayGetBody("private-gateway", basePath+"/domains",
			map[string]string{"Authorization": "Bearer " + managementToken()})
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
			"Authorization: Bearer "+managementToken())

		Expect(code).NotTo(Equal(http.StatusOK),
			"a pod outside the allowed list read the enforced rule set; body: %s", body)

		// The code alone cannot say who answered: the mesh refuses with a 403
		// of its own, and so does the API for a token without the role. What
		// separates them is the body, because every answer the API writes is
		// either a listing or a TMF error carrying an RLS code. A refusal that
		// carries neither never reached the service. For a connection the
		// mesh reset, code 0, the body is curl's error line, which carries
		// neither as well.
		Expect(body).NotTo(ContainSubstring(errorCodePrefix),
			"the refusal came from the API, so the port is open to the whole mesh")
		Expect(body).NotTo(ContainSubstring(`"items"`),
			"the API answered a pod outside the allowed list")
	})

	// The service verifies every token itself. Each request below reaches the
	// API through the gateway the policy admits, so the answer is the API's,
	// and its code says which check refused the token.
	It("refuses a ServiceAccount the release does not list", func() {
		token := serviceAccountToken(namespace, unlisted, readManagementCaller().audience)
		body, code := gatewayGetBody("private-gateway", basePath+"/domains",
			map[string]string{"Authorization": "Bearer " + token})

		Expect(code).To(Equal(http.StatusForbidden), "body: %s", body)
		Expect(body).To(ContainSubstring(`"RLS-0403"`), "the refusal is not the API's; body: %s", body)
	})

	It("refuses a listed caller's token issued for another audience", func() {
		caller := readManagementCaller()
		token := serviceAccountToken(caller.namespace, caller.name, "e2e-another-audience")
		body, code := gatewayGetBody("private-gateway", basePath+"/domains",
			map[string]string{"Authorization": "Bearer " + token})

		Expect(code).To(Equal(http.StatusUnauthorized), "body: %s", body)
		Expect(body).To(ContainSubstring(`"RLS-0401"`), "the refusal is not the API's; body: %s", body)
		Expect(body).To(ContainSubstring("audience"), "the refusal does not name the audience; body: %s", body)
	})

	It("refuses an unsigned token of the shape it read before it verified tokens", func() {
		body, code := gatewayGetBody("private-gateway", basePath+"/domains",
			map[string]string{"Authorization": "Bearer " + unsignedToken(map[string]any{"sub": "e2e@example.com", "roles": []string{"operator"}})})

		Expect(code).To(Equal(http.StatusUnauthorized), "body: %s", body)
		Expect(body).To(ContainSubstring(`"RLS-0401"`), "the refusal is not the API's; body: %s", body)
	})

	// The reset flows. Each spends a path's budget through the private
	// gateway until it is refused, lifts it through the management API, and
	// proves the lift by the gateway admitting the path again. That last step
	// is the point: an API answer alone says what the API believes it did,
	// the gateway says what the counters now are.
	It("lifts a spent budget through a previewed, executed, and retried bulk reset", func() {
		probePath := spendBudget(limitedDomain, limitedPrefix, limitedRule, limit, &limitedApplied)

		operator := map[string]string{
			"Authorization": "Bearer " + managementToken()}
		resets := basePath + "/domains/" + limitedDomain + "/counter-resets"
		selector := `{"selector":{"ruleIds":["` + limitedRule + `"]}`

		// Step one, the preview: a match as of now, and the confirmation
		// token the execution needs. Its own Idempotency-Key, because a
		// preview and its execution are different commands.
		previewKey := idempotencyKey("preview")
		body, code := gatewayRequest("private-gateway", http.MethodPost, resets,
			selector+`,"dryRun":true}`, with(operator, "Idempotency-Key", previewKey))
		Expect(code).To(Equal(http.StatusOK), "the preview did not answer 200; body: %s", body)
		preview := decodeBulk(body)
		Expect(preview).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"DryRun":            BeTrue(),
			"ConfirmationToken": Not(BeEmpty()),
			"MatchedCount":      gstruct.PointTo(BeNumerically(">=", 1)),
		}), "the preview answer: %s", body)

		// Step two, the execution, with the previewed token and a key of its
		// own.
		executeKey := idempotencyKey("execute")
		execute := selector + `,"confirmationToken":"` + preview.ConfirmationToken + `"}`
		body, code = gatewayRequest("private-gateway", http.MethodPost, resets, execute,
			with(operator, "Idempotency-Key", executeKey))
		Expect(code).To(Equal(http.StatusOK), "the execution did not answer 200; body: %s", body)
		executed := decodeBulk(body)
		Expect(executed).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"DryRun":     BeFalse(),
			"ResetCount": gstruct.PointTo(BeNumerically(">=", 1)),
		}), "the execution answer: %s", body)

		// The retry: the same key and the same command answer the recorded
		// outcome, not a second sweep. The token was consumed by the
		// execution, so a second sweep would have been a 410; a replay is a
		// 200 with the body already recorded.
		retryBody, code := gatewayRequest("private-gateway", http.MethodPost, resets, execute,
			with(operator, "Idempotency-Key", executeKey))
		Expect(code).To(Equal(http.StatusOK), "the retry did not replay; body: %s", retryBody)
		Expect(decodeBulk(retryBody).ResetCount).To(Equal(executed.ResetCount),
			"the retry answered a different outcome than the one recorded")

		// And the gateway agrees: the budget is whole again.
		Expect(gatewayGet("private-gateway", probePath, nil)).To(beAdmitted(),
			"GET %s through private-gateway after the bulk reset", probePath)
	})

	It("lifts a spent budget through an addressed DELETE of its counter", func() {
		probePath := spendBudget(limitedDomain, limitedPrefix, limitedRule, limit, &limitedApplied)

		operator := map[string]string{
			"Authorization": "Bearer " + managementToken()}

		// One rule, one value for each of its axes: the keys are computed
		// from the snapshot, never scanned, and a partial axis set is refused.
		address := basePath + "/domains/" + limitedDomain + "/counters?ruleId=" +
			url.QueryEscape(limitedRule) + "&axis.path=" + url.QueryEscape(probePath)
		body, code := gatewayRequest("private-gateway", http.MethodDelete, address, "",
			with(operator, "Idempotency-Key", idempotencyKey("delete")))
		Expect(code).To(Equal(http.StatusOK), "the addressed DELETE did not answer 200; body: %s", body)

		var reset struct {
			RuleID     string   `json:"ruleId"`
			Keys       []string `json:"keys"`
			ResetCount *int     `json:"resetCount"`
		}
		Expect(json.Unmarshal([]byte(body), &reset)).To(Succeed(), "body: %s", body)
		Expect(reset).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"RuleID":     Equal(limitedRule),
			"Keys":       Not(BeEmpty()),
			"ResetCount": gstruct.PointTo(BeNumerically(">=", 1)),
		}), "the DELETE answer: %s", body)

		Expect(gatewayGet("private-gateway", probePath, nil)).To(beAdmitted(),
			"GET %s through private-gateway after the addressed reset", probePath)
	})
})

// spendBudget limits one fresh path under prefix in the domain, applies the
// policy on first use, and spends the path's budget through the private
// gateway until the gateway refuses it. It returns the path, whose counter
// is now the one the caller resets. A fresh path per call: the counter is
// keyed by path, and a reset is what the caller is about to test, so a path
// another call already spent would prove nothing.
func spendBudget(domain, prefix, rule string, limit int32, applied *bool) string {
	if !*applied {
		blocks := hourlyGCRALimits(prefix, "per-path", limit)
		Expect(apply(newPolicy(domain, blocks))).To(Succeed())
		*applied = true
		waitApplied(domain)
		Expect(rule).To(Equal(blocks[0].Name+"/"+blocks[0].Rules[0].Name),
			"the rule id the flows address is not the one the policy declares")
	}
	path := prefix + "/" + strconv.FormatInt(time.Now().UnixNano(), 10)
	waitGatewayServes("private-gateway", path)

	codes := gatewayBurst("private-gateway", path, int(limit)+1, nil)
	Expect(codes[len(codes)-1]).To(Equal(429),
		"the budget was never spent, so there is no counter to reset: %v", codes)
	return path
}

// bulkAnswer holds the fields of a bulk answer the flows assert on.
type bulkAnswer struct {
	DryRun            bool   `json:"dryRun"`
	ConfirmationToken string `json:"confirmationToken"`
	MatchedCount      *int   `json:"matchedCount"`
	ResetCount        *int   `json:"resetCount"`
}

// decodeBulk reads a bulk answer.
func decodeBulk(body string) bulkAnswer {
	var result bulkAnswer
	Expect(json.Unmarshal([]byte(body), &result)).To(Succeed(), "body: %s", body)
	return result
}

// idempotencyKey mints a key unique to this run, in the pattern the API
// accepts. Unique, because the record outlives the run by a day: a key a
// previous run bound would replay that run's outcome.
func idempotencyKey(step string) string {
	return "e2e-" + step + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

// with returns headers plus one more, leaving the original untouched.
func with(headers map[string]string, name, value string) map[string]string {
	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		out[k] = v
	}
	out[name] = value
	return out
}

// listedDomains reads the domain names out of a listing body.
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

// managementPort reports the container port the release exposes for the
// management API, 0 when the chart rendered without it.
func managementPort() int32 {
	pods := servicePods()
	Expect(pods).NotTo(BeEmpty(), "no running replica to read the ports of")
	return int32(namedPort(pods[0], "management"))
}

// serviceHost is the contract's Service, which is what an in-mesh caller
// resolves and what ztunnel applies the policy to. Read from the cluster
// rather than assumed, so a chart that renamed it fails here.
func serviceHost() string {
	var services corev1.ServiceList
	Expect(k8s.List(ctx, &services, client.InNamespace(namespace),
		client.MatchingLabels{"app.kubernetes.io/name": serviceChart})).To(Succeed())
	Expect(services.Items).NotTo(BeEmpty(), "no %s Service in %s", serviceChart, namespace)
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

// managementCaller is whom the release told the service to accept: the first
// ServiceAccount of MANAGEMENT_CALLERS, in its own namespace, and the audience
// of MANAGEMENT_M2M_AUDIENCE. Read from the running pod's environment, which
// is what the chart rendered, so the tokens this suite mints are the ones the
// service was configured to accept, and the suite proves the values reached
// the service, not only the Deployment.
type managementCaller struct {
	namespace string
	name      string
	audience  string
}

func readManagementCaller() managementCaller {
	pods := servicePods()
	Expect(pods).NotTo(BeEmpty(), "no running replica to read the callers of")
	caller := managementCaller{audience: "netcracker"}
	for _, c := range pods[0].Spec.Containers {
		for _, env := range c.Env {
			switch env.Name {
			case "MANAGEMENT_CALLERS":
				first := strings.TrimSpace(strings.SplitN(env.Value, ",", 2)[0])
				caller.namespace, caller.name = namespace, first
				if ns, name, qualified := strings.Cut(first, "/"); qualified {
					caller.namespace, caller.name = ns, name
				}
			case "MANAGEMENT_M2M_AUDIENCE":
				caller.audience = env.Value
			}
		}
	}
	Expect(caller.name).NotTo(BeEmpty(), "the release lists no management caller")
	return caller
}

// managementToken is a token the API server issues for the release's first
// caller with the release's audience: the credential every listed caller
// presents.
func managementToken() string {
	caller := readManagementCaller()
	return serviceAccountToken(caller.namespace, caller.name, caller.audience)
}

// serviceAccountToken creates the ServiceAccount when it does not exist and
// returns a token the API server issues for it with the audience, valid for
// an hour, as a projected token is.
func serviceAccountToken(ns, name, audience string) string {
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	if err := k8s.Create(ctx, account); err != nil && !apierrors.IsAlreadyExists(err) {
		Expect(err).NotTo(HaveOccurred(), "create the ServiceAccount %s/%s", ns, name)
	}
	expiration := int64(3600)
	issued, err := clientset.CoreV1().ServiceAccounts(ns).CreateToken(ctx, name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{Audiences: []string{audience}, ExpirationSeconds: &expiration},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred(), "issue a token for %s/%s", ns, name)
	return issued.Status.Token
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
	Eventually(func() error {
		return k8s.Get(ctx, client.ObjectKeyFromObject(pod), &corev1.Pod{})
	}).WithTimeout(time.Minute).Should(Satisfy(apierrors.IsNotFound), "the previous probe pod %s never went away", name)
	Expect(k8s.Create(ctx, pod)).To(Succeed())

	var finished corev1.Pod
	Eventually(func(g Gomega) {
		g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(pod), &finished)).To(Succeed())
		g.Expect(finished.Status.Phase).To(BeElementOf(corev1.PodSucceeded, corev1.PodFailed))
	}).WithTimeout(3*time.Minute).Should(Succeed(), "the probe pod never finished")

	return podLogs(name, nil)
}

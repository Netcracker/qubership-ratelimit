//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
		// internal API is the deployer's, not this chart's. The suite makes
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
				map[string]string{"Authorization": "Bearer " + managementToken("e2e@example.com", "viewer")})
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
			deletePolicies(domain)
		}
		// Last, because the cleanup wait inside can fail and end this closure:
		// nothing below it would run, and the route and the pod above would
		// leak.
		if limitedApplied {
			deletePolicies(limitedDomain)
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

	// The reset flows. Each spends a path's budget through the private
	// gateway until it is refused, lifts it through the management API, and
	// proves the lift by the gateway admitting the path again. That last step
	// is the point: an API answer alone says what the API believes it did,
	// the gateway says what the counters now are.
	It("runs the bulk flow: preview, execute, retry", func() {
		probePath := spendBudget(limitedDomain, limitedPrefix, limitedRule, limit, &limitedApplied)

		operator := map[string]string{
			"Authorization": "Bearer " + managementToken("e2e@example.com", "operator")}
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
		Expect(preview.DryRun).To(BeTrue())
		Expect(preview.ConfirmationToken).NotTo(BeEmpty(), "the preview minted no confirmation token")
		Expect(preview.MatchedCount).NotTo(BeNil())
		Expect(*preview.MatchedCount).To(BeNumerically(">=", 1),
			"the preview matched no counter, so there was nothing to reset: %s", body)

		// Step two, the execution, with the previewed token and a key of its
		// own.
		executeKey := idempotencyKey("execute")
		execute := selector + `,"confirmationToken":"` + preview.ConfirmationToken + `"}`
		body, code = gatewayRequest("private-gateway", http.MethodPost, resets, execute,
			with(operator, "Idempotency-Key", executeKey))
		Expect(code).To(Equal(http.StatusOK), "the execution did not answer 200; body: %s", body)
		executed := decodeBulk(body)
		Expect(executed.DryRun).To(BeFalse())
		Expect(executed.ResetCount).NotTo(BeNil())
		Expect(*executed.ResetCount).To(BeNumerically(">=", 1), "the execution reset nothing: %s", body)

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
		Expect(gatewayGet("private-gateway", probePath, nil)).To(BeNumerically("<", 300),
			"the private gateway still refuses the path after the bulk reset")
	})

	It("runs the addressed DELETE", func() {
		probePath := spendBudget(limitedDomain, limitedPrefix, limitedRule, limit, &limitedApplied)

		operator := map[string]string{
			"Authorization": "Bearer " + managementToken("e2e@example.com", "operator")}

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
		Expect(reset.RuleID).To(Equal(limitedRule))
		Expect(reset.Keys).NotTo(BeEmpty(), "the DELETE addressed no key")
		Expect(reset.ResetCount).NotTo(BeNil())
		Expect(*reset.ResetCount).To(BeNumerically(">=", 1), "the DELETE reset nothing: %s", body)

		Expect(gatewayGet("private-gateway", probePath, nil)).To(BeNumerically("<", 300),
			"the private gateway still refuses the path after the addressed reset")
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
		blocks := prefixLimits(prefix, "per-path", []string{"path"}, limit, 3600)
		blocks[0].Rules[0].Rates[0].Algorithm = v1.AlgorithmGCRA
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

// decodeBulk reads the fields of a bulk answer the flows assert on.
func decodeBulk(body string) struct {
	DryRun            bool   `json:"dryRun"`
	ConfirmationToken string `json:"confirmationToken"`
	MatchedCount      *int   `json:"matchedCount"`
	ResetCount        *int   `json:"resetCount"`
} {
	var result struct {
		DryRun            bool   `json:"dryRun"`
		ConfirmationToken string `json:"confirmationToken"`
		MatchedCount      *int   `json:"matchedCount"`
		ResetCount        *int   `json:"resetCount"`
	}
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

// managementPort reports the container port the release exposes for the
// management API, 0 when the chart rendered without it.
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

func managementPort() int32 {
	pods := servicePods()
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

// managementIdentity is how the release told the service to read a token:
// the claim the subject is in, the claim the roles are in (a dotted path for
// a nested claim), and the IdP's names for the two canonical roles. Read from
// the running pod's environment, which is what the chart rendered, so the
// tokens this suite mints are shaped the way the service was configured to
// read them - and the suite proves the values reached the service, not only
// the Deployment. Absent variables mean the service's defaults.
type managementIdentity struct {
	subjectClaim string
	rolesClaim   string
	viewer       string
	operator     string
}

func readManagementIdentity() managementIdentity {
	pods := servicePods()
	Expect(pods).NotTo(BeEmpty(), "no running replica to read the identity of")
	identity := managementIdentity{
		subjectClaim: "sub", rolesClaim: "roles", viewer: "viewer", operator: "operator"}
	for _, c := range pods[0].Spec.Containers {
		for _, env := range c.Env {
			first := func(csv string) string { return strings.SplitN(csv, ",", 2)[0] }
			switch env.Name {
			case "MANAGEMENT_CLAIMS_SUBJECT":
				identity.subjectClaim = env.Value
			case "MANAGEMENT_CLAIMS_ROLES":
				identity.rolesClaim = env.Value
			case "MANAGEMENT_ROLES_VIEWER":
				identity.viewer = first(env.Value)
			case "MANAGEMENT_ROLES_OPERATOR":
				identity.operator = first(env.Value)
			}
		}
	}
	return identity
}

// managementToken builds the alg-none token the management API reads. The
// service never verifies the signature - the gateway's JWT filter does - so
// the suite needs no signing key, and the AuthorizationPolicy is what keeps
// that from being a way in.
//
// roles are the canonical names, viewer and operator. They are translated to
// the names the release configured and placed under the claim the release
// configured, so a service that ignored its identity configuration would
// refuse every token this suite sends when CI installs non-default values.
func managementToken(subject string, roles ...string) string {
	identity := readManagementIdentity()
	issued := make([]string, 0, len(roles))
	for _, role := range roles {
		switch role {
		case "viewer":
			issued = append(issued, identity.viewer)
		case "operator":
			issued = append(issued, identity.operator)
		default:
			issued = append(issued, role)
		}
	}

	payload := map[string]any{}
	setClaim(payload, identity.subjectClaim, subject)
	setClaim(payload, identity.rolesClaim, issued)

	seg := func(v any) string {
		raw, err := json.Marshal(v)
		Expect(err).NotTo(HaveOccurred())
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := seg(map[string]string{"alg": "none", "typ": "JWT"})
	return header + "." + seg(payload) + "."
}

// setClaim writes a value at a dotted path, creating the objects along it:
// realm_access.roles becomes {"realm_access":{"roles":...}}.
func setClaim(claims map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	node := claims
	for _, part := range parts[:len(parts)-1] {
		child, ok := node[part].(map[string]any)
		if !ok {
			child = map[string]any{}
			node[part] = child
		}
		node = child
	}
	node[parts[len(parts)-1]] = value
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

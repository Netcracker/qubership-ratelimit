package management

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestStatus_reportsWhatThisReplicaServes(t *testing.T) {
	h := newTestAPI(t)
	h.api.Replica = "ratelimit-6c9d-x2v"
	h.api.CounterBackend = "in-process, counted per replica"

	var status StatusView
	decode(t, h.call(t, http.MethodGet, BasePath+"/status", viewerRoles(), nil), http.StatusOK, &status)

	require.Equal(t, "ratelimit-6c9d-x2v", status.Replica)
	require.Equal(t, "in-process, counted per replica", status.CounterStore.Backend)
	require.Equal(t, map[string]string{testDomain: h.version}, status.RuleSetVersions)
	require.NotNil(t, status.SnapshotSwappedAt, "the rule set was swapped when the fixture built it")
}

// The version a replica reports for a domain is the one its own rule listing
// reports: comparing the two across pods is how a rollout skew is spotted.
func TestStatus_agreesWithTheRuleListing(t *testing.T) {
	h := newTestAPI(t)

	var status StatusView
	decode(t, h.call(t, http.MethodGet, BasePath+"/status", viewerRoles(), nil), http.StatusOK, &status)

	var rules struct {
		RuleSetVersion string `json:"ruleSetVersion"`
	}
	decode(t, h.call(t, http.MethodGet, BasePath+"/domains/"+testDomain+"/rules", viewerRoles(), nil),
		http.StatusOK, &rules)

	require.Equal(t, rules.RuleSetVersion, status.RuleSetVersions[testDomain])
}

func TestSpecification_isServedAsTheDocumentTheBinaryCarries(t *testing.T) {
	h := newTestAPI(t)

	recorder := h.call(t, http.MethodGet, BasePath+"/openapi.yaml", viewerRoles(), nil)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "application/yaml", recorder.Header().Get("Content-Type"))
	require.Equal(t, string(specification), recorder.Body.String())
}

// The embedded document is what this binary was built against, so the routes
// and the paths in it have to be the same set — in both directions. A route
// nobody documented is invisible; a documented path nobody serves is a promise
// the binary does not keep, which is exactly what the audit endpoints would be
// here if the document still carried them.
func TestSpecification_describesExactlyTheRoutesTheAppServes(t *testing.T) {
	h := newTestAPI(t)

	var document struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(specification, &document))

	documented := map[string]bool{}
	for path, operations := range document.Paths {
		for method := range operations {
			if method == "parameters" || method == "description" || method == "summary" {
				continue
			}
			documented[strings.ToUpper(method)+" "+BasePath+path] = true
		}
	}

	served := map[string]bool{}
	for _, routes := range h.app.Stack() {
		for _, route := range routes {
			if route.Method == http.MethodHead || route.Path == "/" || route.Path == BasePath {
				// The router registers a HEAD for every GET, and mounts each
				// piece of middleware as a route on the group's own path;
				// neither is an endpoint.
				continue
			}
			served[route.Method+" "+openAPIPath(route.Path)] = true
		}
	}

	require.Equal(t, sortedSet(documented), sortedSet(served))
}

// openAPIPath renders a router path the way the document spells it: the router
// writes :domain, the document writes {domain}.
func openAPIPath(path string) string {
	return regexp.MustCompile(`:([A-Za-z]+)`).ReplaceAllString(path, "{$1}")
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// The audit endpoints are not built, so nothing may advertise them.
func TestSpecification_carriesNoUnimplementedEndpoints(t *testing.T) {
	var document struct {
		Paths map[string]any `json:"paths"`
		Tags  []struct {
			Name string `json:"name"`
		} `json:"tags"`
	}
	require.NoError(t, yaml.Unmarshal(specification, &document))

	for path := range document.Paths {
		require.NotContains(t, path, "/audit")
	}
	for _, tag := range document.Tags {
		require.NotEqual(t, "audit", tag.Name)
	}
}

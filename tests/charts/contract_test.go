// Package charts renders the two namespace charts and compares what they
// render with the constants of api/contract, and checks that the CRD chart
// alone renders the CRD. The templates carry the Service
// name, its ports, the ConfigMap name, and the mount path as fixed strings,
// because a satellite computes the RLS address from the constants alone;
// this test is what keeps those strings equal to the ones the binaries
// import. It needs the helm binary and skips without it, unless
// CHARTS_TEST_REQUIRE_HELM is set, which the CI helm job does.
package charts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/netcracker/qubership-ratelimit/api/contract"
)

const (
	operatorChart = "ratelimit-operator"
	serviceChart  = "ratelimit-service"
	// imageTag is the TAG of every render unless a --set in its arguments
	// overrides it.
	imageTag = "test"
	// deploymentSession is the DEPLOYMENT_SESSION_ID of every render unless a
	// --set in its arguments overrides it.
	deploymentSession = "test-session"

	envoyFilterKind = "EnvoyFilter"
)

// namespaceCharts are the two charts the platform installs in every namespace
// of a composite, the baseline and each satellite alike.
var namespaceCharts = []string{operatorChart, serviceChart}

// object is one rendered manifest, read as a generic map.
type object map[string]any

func (o object) kind() string { return o.str("kind") }
func (o object) name() string { return o.at("metadata", "name").str2() }
func (o object) str(key string) string {
	s, _ := o[key].(string)
	return s
}

// at walks nested maps; a missing step yields an empty node.
func (o object) at(path ...string) node { return node{v: map[string]any(o)}.at(path...) }

type node struct{ v any }

func (n node) at(path ...string) node {
	cur := n.v
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return node{}
		}
		cur = m[p]
	}
	return node{v: cur}
}
func (n node) str2() string { s, _ := n.v.(string); return s }
func (n node) list() []node {
	items, _ := n.v.([]any)
	out := make([]node, 0, len(items))
	for _, item := range items {
		out = append(out, node{v: item})
	}
	return out
}
func (n node) num() float64 {
	switch v := n.v.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return -1
}

// keyed indexes the items of a list by the string each item holds at path,
// such as a container's env by name or its volume mounts by mountPath. An
// item without the path is indexed under the empty string.
func keyed(list node, path ...string) map[string]node {
	out := map[string]node{}
	for _, item := range list.list() {
		out[item.at(path...).str2()] = item
	}
	return out
}

// render runs helm template on a chart with the dev profile and the given
// extra arguments, and parses every document it produced. NAMESPACE is the
// release namespace, TAG is imageTag, and DEPLOYMENT_SESSION_ID is
// deploymentSession unless a --set in the extra arguments overrides them; a
// values file there cannot, because helm applies every --set after the files.
// The platform sets all three on every installation, and both schemas require
// them.
func render(t *testing.T, chart, namespace string, extra ...string) []object {
	t.Helper()
	out, err := renderErr(chart, namespace, extra...)
	require.NoError(t, err, "%s", out)
	return parse(t, out)
}

// parse splits the output of helm template into its documents and returns
// every one that is an object; empty documents and comment-only ones, which
// a template disabled by a condition leaves, are dropped.
func parse(t *testing.T, out []byte) []object {
	t.Helper()
	var objects []object
	for doc := range bytes.SplitSeq(out, []byte("\n---")) {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var o object
		require.NoError(t, yaml.Unmarshal(doc, &o), "document:\n%s", doc)
		if o != nil && o.kind() != "" {
			objects = append(objects, o)
		}
	}
	return objects
}

// renderErr is render without the expectation that it succeeds: the schema
// tests assert that a value is refused, and a refusal is helm's exit code.
// The output is helm's alone; the error also names the command.
func renderErr(chart, namespace string, extra ...string) ([]byte, error) {
	platform := []string{"--set", "NAMESPACE=" + namespace, "--set", "TAG=" + imageTag,
		"--set", "DEPLOYMENT_SESSION_ID=" + deploymentSession}
	return helmTemplate(chart, namespace, append(platform, extra...)...)
}

// helmTemplate is renderErr without the platform parameters renderErr sets,
// for the tests of what the schemas do with an installation that leaves them
// out.
func helmTemplate(chart, namespace string, extra ...string) ([]byte, error) {
	args := append([]string{"template", "t", chartFile(chart), "-n", namespace,
		"-f", profileFile(chart, "dev")}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("helm %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return out, nil
}

// chartFile is the path of a chart under helm-templates, or of a file in it
// when path names one.
func chartFile(chart string, path ...string) string {
	return filepath.Join(append([]string{"..", "..", "helm-templates", chart}, path...)...)
}

// profileFile is the path of one of a chart's resource profiles.
func profileFile(chart, profile string) string {
	return chartFile(chart, "resource-profiles", profile+".yaml")
}

// argsOf lists a container's args as strings.
func argsOf(container node) []string { return strs(container.at("args")) }

// strs reads a list of strings.
func strs(n node) []string {
	items := n.list()
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.str2())
	}
	return out
}

// ofKind lists the objects of one kind, in the order helm rendered them.
func ofKind(objects []object, kind string) []object {
	var found []object
	for _, o := range objects {
		if o.kind() == kind {
			found = append(found, o)
		}
	}
	return found
}

// only returns the one object of kind, and stops the test when the rendering
// holds none or several.
func only(t *testing.T, objects []object, kind string) object {
	t.Helper()
	found := ofKind(objects, kind)
	require.Len(t, found, 1, "objects of kind %s", kind)
	return found[0]
}

// kinds lists the kinds among objects, each once, in the order of first
// appearance.
func kinds(objects []object) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range objects {
		if !seen[o.kind()] {
			seen[o.kind()] = true
			out = append(out, o.kind())
		}
	}
	return out
}

// containerOf returns the one container of the Deployment among objects.
func containerOf(t *testing.T, objects []object) node {
	t.Helper()
	containers := only(t, objects, "Deployment").at("spec", "template", "spec", "containers").list()
	require.Len(t, containers, 1, "containers of the Deployment")
	return containers[0]
}

// jsonOf marshals a rendered object, or a part of one, to JSON.
func jsonOf(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return string(raw)
}

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("CHARTS_TEST_REQUIRE_HELM") != "" {
			fmt.Fprintln(os.Stderr, "helm is not on PATH and CHARTS_TEST_REQUIRE_HELM is set")
			os.Exit(1)
		}
		fmt.Println("helm is not on PATH; the chart contract tests are skipped")
		return
	}
	os.Exit(m.Run())
}

// The service chart's Service carries the contract's name and the two ports
// the chart's filters and the operator binary address it by.
func TestServiceChart_rendersTheServiceOfTheContract(t *testing.T) {
	service := only(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}"), "Service")

	assert.Equal(t, contract.ServiceName, service.name(), "metadata.name of the Service")
	ports := keyed(service.at("spec", "ports"), "name")
	require.Contains(t, ports, contract.GRPCPortName, "ports of the Service")
	assert.Equal(t, float64(contract.GRPCPort), ports[contract.GRPCPortName].at("port").num(),
		"port of the %s port", contract.GRPCPortName)
	assert.Equal(t, "grpc", ports[contract.GRPCPortName].at("appProtocol").str2(),
		"without appProtocol Istio takes the port for HTTP/1.1")
	assert.Contains(t, ports, contract.MetricsPortName, "the operator reads the applied generation on this port")
	assert.Contains(t, ports, "management", "ports of the Service")
}

// The service chart's pod binds the gRPC listener to the contract's port, and
// mounts the ConfigMap of the contract's name read-only at the contract's
// path.
func TestServiceChart_podServesTheContractsPortAndMountsItsConfigMap(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}")
	pod := only(t, objects, "Deployment").at("spec", "template", "spec")
	container := containerOf(t, objects)

	args := argsOf(container)
	assert.Contains(t, args, fmt.Sprintf("--rls-bind-address=:%d", contract.GRPCPort))
	assert.Contains(t, args, "--config-dir="+contract.MountPath)
	containerPorts := keyed(container.at("ports"), "name")
	assert.Equal(t, float64(contract.GRPCPort), containerPorts[contract.GRPCPortName].at("containerPort").num(),
		"containerPort of the %s port", contract.GRPCPortName)
	assert.Contains(t, containerPorts, contract.MetricsPortName, "ports of the container")

	mounts := keyed(container.at("volumeMounts"), "mountPath")
	require.Contains(t, mounts, contract.MountPath, "volume mounts of the container")
	assert.Equal(t, true, mounts[contract.MountPath].at("readOnly").v, "readOnly of the mount at %s", contract.MountPath)
	volumes := keyed(pod.at("volumes"), "configMap", "name")
	require.Contains(t, volumes, contract.ConfigMapName, "ConfigMap volumes of the pod")
	assert.Equal(t, true, volumes[contract.ConfigMapName].at("configMap", "optional").v,
		"the pod starts before the operator has written")
}

// The data plane reaches no API server object: no Role, no RoleBinding, and
// no token automounted in the pod or offered by its ServiceAccount. The one
// token the pod holds is the one the chart mounts for the management API,
// which TestServiceChart_mountsTheServiceAccountTokenForTheManagementAPIAlone
// covers.
func TestServiceChart_reachesNoAPIServerObject(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}")

	assert.NotContains(t, kinds(objects), "Role")
	assert.NotContains(t, kinds(objects), "RoleBinding")
	assert.Equal(t, false, only(t, objects, "Deployment").at("spec", "template", "spec", "automountServiceAccountToken").v,
		"automountServiceAccountToken of the pod")
	assert.Equal(t, false, only(t, objects, "ServiceAccount")["automountServiceAccountToken"],
		"automountServiceAccountToken of the ServiceAccount")
}

// The probes, the PodMonitors, the Service, and the operator reach a listener
// through the container port named after it, so a flag that binds any other
// port leaves them calling a port nothing listens on.
func TestCharts_bindEachListenerToItsDeclaredPort(t *testing.T) {
	for chart, listeners := range map[string]map[string]string{
		operatorChart: {
			"probes":                 "--health-probe-bind-address",
			contract.MetricsPortName: "--metrics-bind-address",
		},
		serviceChart: {
			contract.GRPCPortName:    "--rls-bind-address",
			"probes":                 "--health-probe-bind-address",
			contract.MetricsPortName: "--metrics-bind-address",
			"management":             "--management-bind-address",
		},
	} {
		t.Run(chart, func(t *testing.T) {
			container := containerOf(t, render(t, chart, "biz", "--set", "management.enabled=true",
				"--set", "management.callers={ui-backend}"))
			args := argsOf(container)
			declared := keyed(container.at("ports"), "name")

			for name, flag := range listeners {
				t.Run(name, func(t *testing.T) {
					require.Contains(t, declared, name, "ports of the container")
					assert.Contains(t, args, fmt.Sprintf("%s=:%d", flag, int(declared[name].at("containerPort").num())))
				})
			}
		})
	}
}

// The service chart's filters address the Service by the contract's name
// and port, in NAMESPACE or in the baseline's: one filter per enabled
// gateway, named after the chart.
func TestServiceChart_filtersAddressTheServiceOfTheContract(t *testing.T) {
	t.Run("in the baseline they address NAMESPACE", func(t *testing.T) {
		assertFiltersAddress(t, render(t, serviceChart, "biz"), "biz")
	})
	t.Run("in a satellite they address BASELINE_ORIGIN", func(t *testing.T) {
		objects := render(t, serviceChart, "sat", "--set", "BASELINE_ORIGIN=base", "--set", "MONITORING_ENABLED=true",
			"--set", "management.enabled=true", "--set", "management.callers={ui-backend}")
		assertFiltersAddress(t, objects, "base")
	})
}

// assertFiltersAddress asserts that the EnvoyFilters among objects are the
// service chart's pair, one per gateway, and that each sends its checks to
// the contract's Service in namespace.
func assertFiltersAddress(t *testing.T, objects []object, namespace string) {
	t.Helper()
	authority := fmt.Sprintf("%s.%s.svc.cluster.local", contract.ServiceName, namespace)
	cluster := fmt.Sprintf("outbound|%d||%s.%s.svc.cluster.local", contract.GRPCPort, contract.ServiceName, namespace)
	filters := ofKind(objects, envoyFilterKind)
	names := make([]string, 0, len(filters))
	for _, filter := range filters {
		names = append(names, filter.name())
		assert.Equal(t, serviceChart, filter.at("metadata", "labels", "app.kubernetes.io/name").str2(),
			"app.kubernetes.io/name label of %s", filter.name())
		raw, err := yaml.Marshal(filter)
		require.NoError(t, err)
		assert.Contains(t, string(raw), "authority: "+authority, filter.name())
		assert.Contains(t, string(raw), "cluster_name: "+cluster, filter.name())
	}
	assert.ElementsMatch(t, []string{"ratelimit-service-public-gateway", "ratelimit-service-private-gateway"}, names,
		"one filter per enabled gateway")
}

// A satellite runs no service, so the service chart renders the gateway
// filters there and nothing else, whatever the values switch on.
func TestServiceChart_rendersOnlyTheFiltersInASatellite(t *testing.T) {
	objects := render(t, serviceChart, "sat", "--set", "BASELINE_ORIGIN=base", "--set", "MONITORING_ENABLED=true",
		"--set", "management.enabled=true", "--set", "management.callers={ui-backend}")

	assert.Equal(t, []string{envoyFilterKind}, kinds(objects))
}

// The operator chart renders no gateway filter: a second set beside the
// service chart's would check every request twice.
func TestOperatorChart_rendersNoFilter(t *testing.T) {
	assert.NotContains(t, kinds(render(t, operatorChart, "biz", "--set", "MONITORING_ENABLED=true")), envoyFilterKind)
}

// A dial of the filter, runtime.enforcedPercent, runtime.enabledPercent, or
// filter.failClosed, changes the EnvoyFilters and no other object of the
// release, so a brake pulled through Helm leaves the service pods running.
func TestServiceChart_aDialChangesTheFiltersAlone(t *testing.T) {
	values := []string{"--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}"}
	defaultFilters, defaultRest := splitFilters(t, render(t, serviceChart, "biz", values...))
	require.Len(t, defaultFilters, 2, "one filter per enabled gateway")

	for _, dial := range []string{"runtime.enforcedPercent=0", "runtime.enabledPercent=0", "filter.failClosed=true"} {
		t.Run(dial, func(t *testing.T) {
			filters, rest := splitFilters(t, render(t, serviceChart, "biz", slices.Concat(values, []string{"--set", dial})...))

			assert.Equal(t, defaultRest, rest, "the objects other than the filters")
			assert.NotEqual(t, defaultFilters, filters, "the filters")
		})
	}
}

// splitFilters marshals every object to JSON, the EnvoyFilters keyed by name
// and the rest by kind and name.
func splitFilters(t *testing.T, objects []object) (filters, rest map[string]string) {
	t.Helper()
	filters, rest = map[string]string{}, map[string]string{}
	for _, o := range objects {
		if o.kind() == envoyFilterKind {
			filters[o.name()] = jsonOf(t, o)
		} else {
			rest[o.kind()+"/"+o.name()] = jsonOf(t, o)
		}
	}
	return filters, rest
}

// grant is one rule of a Role on one resource: the resourceNames it is
// narrowed to, nil where it reaches every object of the resource, and its
// verbs, sorted.
type grant struct {
	Names []string
	Verbs []string
}

// grantsOn lists the rules of role that name resource among their resources.
func grantsOn(role object, resource string) []grant {
	var out []grant
	for _, rule := range role.at("rules").list() {
		if !slices.Contains(strs(rule.at("resources")), resource) {
			continue
		}
		g := grant{Verbs: slices.Sorted(slices.Values(strs(rule.at("verbs"))))}
		if names := strs(rule.at("resourceNames")); len(names) > 0 {
			g.Names = names
		}
		out = append(out, g)
	}
	return out
}

// The operator adopts its own Deployment by the name the chart gives it, and
// its Role reaches one ConfigMap and one Deployment by name: create is the
// only verb granted on ConfigMaps in general, since RBAC cannot narrow it.
// Anything wider would let a compromised operator pod read or overwrite the
// configuration of the other applications in the namespace. There is no
// ClusterRole. The verbs are the ones docs/helm-chart.md lists for Role.yaml.
func TestOperatorChart_reachesItsOwnObjectsByName(t *testing.T) {
	objects := render(t, operatorChart, "biz")
	deployment := only(t, objects, "Deployment")
	role := only(t, objects, "Role")

	assert.Contains(t, argsOf(containerOf(t, objects)), "--deployment="+deployment.name())
	assert.NotContains(t, kinds(objects), "ClusterRole")
	assert.ElementsMatch(t, []grant{
		{Verbs: []string{"create"}},
		{Names: []string{contract.ConfigMapName}, Verbs: []string{"get", "list", "update", "watch"}},
	}, grantsOn(role, "configmaps"), "rules on configmaps")
	assert.Equal(t, []grant{{Names: []string{deployment.name()}, Verbs: []string{"get"}}},
		grantsOn(role, "deployments"), "rules on deployments")
	assert.Equal(t, []grant{{Verbs: []string{"update"}}}, grantsOn(role, "ratelimitpolicies/status"),
		"the status is written with Update, never patched")
}

// A BASELINE_ORIGIN equal to NAMESPACE is refused by both charts, whether
// NAMESPACE is the release namespace or another one. Rendered as a satellite
// of itself, the namespace used to lose its operator and its service in one
// upgrade, with filters left pointing at the Service that upgrade removed.
func TestCharts_refuseABaselineOriginOfTheirOwnNamespace(t *testing.T) {
	cases := []struct {
		name             string
		releaseNamespace string
		args             []string
	}{
		{"NAMESPACE is the release namespace", "team-a", []string{"--set", "BASELINE_ORIGIN=team-a"}},
		{"NAMESPACE differs from the release namespace", "release-ns",
			[]string{"--set", "NAMESPACE=biz", "--set", "BASELINE_ORIGIN=biz"}},
	}
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					out, err := renderErr(chart, c.releaseNamespace, c.args...)

					require.Error(t, err, "helm template %s", strings.Join(c.args, " "))
					assert.Contains(t, string(out), "is this release's own namespace")
				})
			}
		})
	}
}

// Without CLOUD_TOPOLOGIES both Deployments spread their pods the way the
// platform's other services do: one constraint on CLOUD_TOPOLOGY_KEY, the
// node by default, selecting the Deployment's own pods.
func TestCharts_spreadTheirPodsOverTheNodesByDefault(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			deployment := only(t, render(t, chart, "biz"), "Deployment")

			spread := deployment.at("spec", "template", "spec", "topologySpreadConstraints").list()
			require.Len(t, spread, 1, "topologySpreadConstraints")
			assert.Equal(t, "kubernetes.io/hostname", spread[0].at("topologyKey").str2(), "topologyKey")
			assert.EqualValues(t, 1, spread[0].at("maxSkew").v, "maxSkew")
			assert.Equal(t, "ScheduleAnyway", spread[0].at("whenUnsatisfiable").str2(), "whenUnsatisfiable")
			assert.Equal(t, deployment.at("spec", "selector", "matchLabels").v,
				spread[0].at("labelSelector", "matchLabels").v, "the constraint selects pods the Deployment does not own")
		})
	}
}

// CLOUD_TOPOLOGIES replaces the default with one constraint per entry, each
// with its own topologyKey, maxSkew, and whenUnsatisfiable, and
// ScheduleAnyway where the entry leaves whenUnsatisfiable out.
func TestCharts_spreadTheirPodsOnceForEachCloudTopology(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			deployment := only(t, render(t, chart, "biz",
				"--set", "CLOUD_TOPOLOGIES[0].topologyKey=topology.kubernetes.io/zone",
				"--set", "CLOUD_TOPOLOGIES[1].topologyKey=kubernetes.io/hostname",
				"--set", "CLOUD_TOPOLOGIES[1].maxSkew=2",
				"--set", "CLOUD_TOPOLOGIES[1].whenUnsatisfiable=DoNotSchedule"), "Deployment")

			spread := deployment.at("spec", "template", "spec", "topologySpreadConstraints").list()
			require.Len(t, spread, 2, "topologySpreadConstraints")
			assert.Equal(t, "topology.kubernetes.io/zone", spread[0].at("topologyKey").str2(),
				"topologyKey of the zone entry")
			assert.Equal(t, "ScheduleAnyway", spread[0].at("whenUnsatisfiable").str2(),
				"whenUnsatisfiable of the zone entry")
			assert.Equal(t, "kubernetes.io/hostname", spread[1].at("topologyKey").str2(),
				"topologyKey of the hostname entry")
			assert.EqualValues(t, 2, spread[1].at("maxSkew").v, "maxSkew of the hostname entry")
			assert.Equal(t, "DoNotSchedule", spread[1].at("whenUnsatisfiable").str2(),
				"whenUnsatisfiable of the hostname entry")
		})
	}
}

// The schemas refuse a whenUnsatisfiable of a CLOUD_TOPOLOGIES entry other
// than ScheduleAnyway and DoNotSchedule.
func TestCharts_refuseAnUnknownWhenUnsatisfiable(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			out, err := renderErr(chart, "biz", "--set", "CLOUD_TOPOLOGIES[0].topologyKey=x",
				"--set", "CLOUD_TOPOLOGIES[0].whenUnsatisfiable=Sometimes")

			require.Error(t, err, "helm template with CLOUD_TOPOLOGIES[0].whenUnsatisfiable=Sometimes")
			assert.Contains(t, string(out), "whenUnsatisfiable", "the refusal names the key it refused")
		})
	}
}

// The management port's AuthorizationPolicy is worth something only in the
// exact shape it has: DENY on the management port for every principal except
// the callers. A <name> caller is the ServiceAccount of that name in
// NAMESPACE, and a <namespace>/<name> caller the one in its own namespace.
// The check reads the structure, so a policy that keeps the same principals
// under principals, or turns into an ALLOW, fails here.
func TestServiceChart_managementPolicyDeniesAllButTheCallers(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend,platform/ops-backend}")
	policy := only(t, objects, "AuthorizationPolicy")
	deployment := only(t, objects, "Deployment")

	assert.Equal(t, "DENY", policy.at("spec", "action").str2(), "spec.action")
	assert.Equal(t, deployment.at("spec", "selector", "matchLabels").v,
		policy.at("spec", "selector", "matchLabels").v, "the policy does not select the service's pods")
	rules := policy.at("spec", "rules").list()
	require.Len(t, rules, 1, "spec.rules")
	to := rules[0].at("to").list()
	require.Len(t, to, 1, "spec.rules[0].to")
	ports := strs(to[0].at("operation", "ports"))
	require.Len(t, ports, 1, "spec.rules[0].to[0].operation.ports")
	assert.Contains(t, argsOf(containerOf(t, objects)), "--management-bind-address=:"+ports[0],
		"the policy covers a port other than the one the management listener binds")
	source := policySource(t, policy)
	assert.ElementsMatch(t, []string{"cluster.local/ns/biz/sa/ui-backend", "cluster.local/ns/platform/sa/ops-backend"},
		strs(source.at("notPrincipals")), "spec.rules[0].from[0].source.notPrincipals")
	assert.Nil(t, source.at("principals").v, "a principals list turns the exception into the target")
}

// policySource returns the one source of the one rule of an
// AuthorizationPolicy, and stops the test where the policy holds another
// number of rules or of sources.
func policySource(t *testing.T, policy object) node {
	t.Helper()
	rules := policy.at("spec", "rules").list()
	require.Len(t, rules, 1, "spec.rules")
	from := rules[0].at("from").list()
	require.Len(t, from, 1, "spec.rules[0].from")
	return from[0].at("source")
}

// An explicit allowedServiceAccounts list replaces the callers as the
// principals, in the callers' grammar. A release sets it when the callers
// come through a gateway, whose workload the policy then sees, and lists a
// caller in another namespace that reaches the port directly beside it.
func TestServiceChart_managementPolicyTakesAnExplicitListOverTheCallers(t *testing.T) {
	policy := only(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}",
		"--set", "management.authorizationPolicy.allowedServiceAccounts={private-gateway-istio,platform/ops-backend}"),
		"AuthorizationPolicy")

	assert.ElementsMatch(t,
		[]string{"cluster.local/ns/biz/sa/private-gateway-istio", "cluster.local/ns/platform/sa/ops-backend"},
		strs(policySource(t, policy).at("notPrincipals")), "spec.rules[0].from[0].source.notPrincipals")
}

// The schema refuses an entry of management.callers or of
// management.authorizationPolicy.allowedServiceAccounts that is neither <name>
// nor <namespace>/<name>, rather than rendering a principal no workload holds.
func TestServiceChart_refusesAServiceAccountEntryOfAnotherShape(t *testing.T) {
	for _, c := range []struct {
		key  string
		args []string
	}{
		{"callers", []string{"--set", "management.callers={a/b/c}"}},
		{"allowedServiceAccounts", []string{"--set", "management.callers={ui-backend}",
			"--set", "management.authorizationPolicy.allowedServiceAccounts={a/b/c}"}},
	} {
		t.Run(c.key, func(t *testing.T) {
			out, err := renderErr(serviceChart, "biz", append([]string{"--set", "management.enabled=true"}, c.args...)...)

			require.Error(t, err, "helm template %s", strings.Join(c.args, " "))
			assert.Contains(t, string(out), c.key, "the refusal names the key it refused")
		})
	}
}

// The dashboard opens on its own release's namespace. Domain names repeat
// across namespaces, so a default of All merged one installation's panels with
// every other's; All stays available as a choice.
func TestServiceChart_dashboardOpensOnItsOwnNamespace(t *testing.T) {
	dashboard := only(t, render(t, serviceChart, "team-a", "--set", "MONITORING_ENABLED=true"), "GrafanaDashboard")
	type variable struct {
		Name    string `json:"name"`
		Current struct {
			Value any `json:"value"`
		} `json:"current"`
		IncludeAll bool `json:"includeAll"`
	}
	var model struct {
		Templating struct {
			List []variable `json:"list"`
		} `json:"templating"`
	}
	require.NoError(t, json.Unmarshal([]byte(dashboard.at("spec", "json").str2()), &model))

	i := slices.IndexFunc(model.Templating.List, func(v variable) bool { return v.Name == "namespace" })
	require.NotEqual(t, -1, i, "the dashboard has no namespace variable")
	namespace := model.Templating.List[i]
	assert.Equal(t, "team-a", namespace.Current.Value, "current value of the namespace variable")
	assert.True(t, namespace.IncludeAll, "includeAll of the namespace variable")
}

// The operator chart renders nothing in a satellite, whatever the values say:
// a satellite runs no operator, and its filters come from the service chart.
func TestOperatorChart_rendersNothingInASatellite(t *testing.T) {
	objects := render(t, operatorChart, "sat", "--set", "BASELINE_ORIGIN=base", "--set", "MONITORING_ENABLED=true")

	assert.Empty(t, objects)
}

// Neither chart renders the ConfigMap: the operator is its only writer.
func TestCharts_renderNoConfigMap(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			objects := render(t, chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true",
				"--set", "management.callers={ui-backend}")

			assert.NotContains(t, kinds(objects), "ConfigMap")
		})
	}
}

// The pods of each chart carry the chart's name, which is what the e2e
// helpers and the PodMonitors select by.
func TestCharts_labelThePodsByChartName(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			deployment := only(t, render(t, chart, "biz"), "Deployment")

			assert.Equal(t, chart, deployment.at("spec", "template", "metadata", "labels", "app.kubernetes.io/name").str2(),
				"app.kubernetes.io/name label of the pods")
		})
	}
}

// Both charts read the parameters the platform sets on every one of its
// services, the way its other services read them: the name, the image, the
// labels, the log level, the security context on Kubernetes, and the rollout.
func TestCharts_readThePlatformParameters(t *testing.T) {
	for _, c := range []struct{ chart, versionVariable string }{
		{operatorChart, "OPERATOR_VERSION"},
		{serviceChart, "SERVICE_VERSION"},
	} {
		t.Run(c.chart, func(t *testing.T) {
			objects := render(t, c.chart, "biz",
				"--set", "SERVICE_NAME=rl",
				"--set", "IMAGE_REPOSITORY=registry.example/rl",
				"--set", "TAG=1.2.3",
				"--set", "APPLICATION_NAME=app",
				"--set", "MANAGED_BY=platform",
				"--set", "ARTIFACT_DESCRIPTOR_VERSION=1.2.3-ad",
				"--set", "DEPLOYMENT_SESSION_ID=s",
				"--set", "LOG_LEVEL=DEBUG",
				"--set", "DEPLOYMENT_STRATEGY_TYPE=recreate")
			deployment := only(t, objects, "Deployment")
			container := containerOf(t, objects)

			assert.Equal(t, "rl", deployment.name(), "metadata.name")
			labels := deployment.at("metadata", "labels")
			assert.Equal(t, "app", labels.at("app.kubernetes.io/part-of").str2(), "app.kubernetes.io/part-of label")
			assert.Equal(t, "platform", labels.at("app.kubernetes.io/managed-by").str2(), "app.kubernetes.io/managed-by label")
			assert.Equal(t, "1.2.3-ad", labels.at("app.kubernetes.io/version").str2(), "app.kubernetes.io/version label")
			assert.Equal(t, "s", labels.at("deployment.netcracker.com/sessionId").str2(), "sessionId label")
			assert.Equal(t, "rl-biz", labels.at("app.kubernetes.io/instance").str2(), "app.kubernetes.io/instance label")
			assert.Nil(t, deployment.at("spec", "template", "metadata", "labels", "deployment.netcracker.com/sessionId").v,
				"a sessionId label on the pods restarts them on every deployment")
			assert.Equal(t, map[string]any{"name": "rl"}, deployment.at("spec", "selector", "matchLabels").v,
				"spec.selector.matchLabels")
			assert.Equal(t, "Recreate", deployment.at("spec", "strategy", "type").str2(), "spec.strategy.type")
			assert.Equal(t, "registry.example/rl:1.2.3", container.at("image").str2(), "image of the container")
			env := keyed(container.at("env"), "name")
			assert.Equal(t, "debug", env["LOGGING_LEVEL_ROOT"].at("value").str2(), "LOGGING_LEVEL_ROOT")
			assert.Equal(t, "1.2.3", env[c.versionVariable].at("value").str2(),
				"%s reports a version other than the image tag", c.versionVariable)
			security := container.at("securityContext")
			assert.Equal(t, true, security.at("readOnlyRootFilesystem").v, "securityContext.readOnlyRootFilesystem")
			assert.EqualValues(t, 10001, security.at("runAsGroup").v, "securityContext.runAsGroup")
		})
	}
}

// On OpenShift the platform assigns the container's group and the root
// filesystem is writable, so neither chart pins a group or a read-only root.
func TestCharts_leaveTheSecurityContextToOpenShift(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			container := containerOf(t, render(t, chart, "biz", "--set", "PAAS_PLATFORM=OPENSHIFT"))

			assert.Equal(t, false, container.at("securityContext", "readOnlyRootFilesystem").v,
				"securityContext.readOnlyRootFilesystem")
			assert.Nil(t, container.at("securityContext", "runAsGroup").v, "securityContext.runAsGroup")
		})
	}
}

// Both schemas refuse an installation that leaves NAMESPACE, TAG, or
// DEPLOYMENT_SESSION_ID at its empty default or removes it: the namespace goes
// into the RLS address and the policy principals, the tag into the image
// reference, and the session into the sessionId label of every object. Each
// case leaves one of the three out and sets the other two, and the refusal
// names the parameter left out.
func TestCharts_refuseAnInstallationWithoutARequiredPlatformParameter(t *testing.T) {
	cases := []struct{ name, set, key string }{
		{"NAMESPACE at its default", "TAG=1.2.3,DEPLOYMENT_SESSION_ID=s1", "NAMESPACE"},
		{"NAMESPACE removed", "TAG=1.2.3,DEPLOYMENT_SESSION_ID=s1,NAMESPACE=null", "NAMESPACE"},
		{"TAG at its default", "NAMESPACE=biz,DEPLOYMENT_SESSION_ID=s1", "TAG"},
		{"TAG removed", "NAMESPACE=biz,DEPLOYMENT_SESSION_ID=s1,TAG=null", "TAG"},
		{"DEPLOYMENT_SESSION_ID at its default", "NAMESPACE=biz,TAG=1.2.3", "DEPLOYMENT_SESSION_ID"},
		{"DEPLOYMENT_SESSION_ID removed", "NAMESPACE=biz,TAG=1.2.3,DEPLOYMENT_SESSION_ID=null", "DEPLOYMENT_SESSION_ID"},
	}
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					out, err := helmTemplate(chart, "biz", "--set", c.set)

					require.Error(t, err, "helm template --set %s", c.set)
					assert.Contains(t, string(out), c.key, "the refusal names the parameter left out")
				})
			}
		})
	}
}

// The platform passes one parameter set to both charts, so a value meant for
// one chart reaches the other. Each chart renders here with the other chart's
// values.yaml in place of that set; a block both charts closed under one name
// would refuse the keys only the other chart declares.
func TestCharts_acceptTheOtherChartsValues(t *testing.T) {
	for chart, other := range map[string]string{operatorChart: serviceChart, serviceChart: operatorChart} {
		t.Run(chart, func(t *testing.T) {
			_, err := renderErr(chart, "biz", "-f", chartFile(other, "values.yaml"), "--set", "MONITORING_ENABLED=true")

			assert.NoError(t, err, "helm template with the values.yaml of %s", other)
		})
	}
}

// Without the optional platform parameters, the Deployment runs the chart's
// own image from ghcr.io, carries an empty version label and Helm as its
// manager, and rolls out keeping every pod until its replacement is Ready.
func TestCharts_defaultTheOptionalPlatformParameters(t *testing.T) {
	for _, c := range []struct{ chart, image string }{
		{operatorChart, "ghcr.io/netcracker/qubership-ratelimit-operator:test"},
		{serviceChart, "ghcr.io/netcracker/qubership-ratelimit-service:test"},
	} {
		t.Run(c.chart, func(t *testing.T) {
			objects := render(t, c.chart, "biz")
			deployment := only(t, objects, "Deployment")

			assert.Equal(t, c.image, containerOf(t, objects).at("image").str2(), "image of the container")
			labels := deployment.at("metadata", "labels")
			assert.Equal(t, "", labels.at("app.kubernetes.io/version").v, "app.kubernetes.io/version label")
			assert.Equal(t, "Helm", labels.at("app.kubernetes.io/managed-by").str2(), "app.kubernetes.io/managed-by label")
			assert.JSONEq(t, `{"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}}`,
				jsonOf(t, deployment.at("spec", "strategy").v), "spec.strategy")
		})
	}
}

// NAMESPACE, the platform parameter, places every object of both charts,
// and the namespace-scoped references inside them follow it: the instance
// label, the scrape, and the rules. The satellite guard follows it too; that
// case is in TestCharts_refuseABaselineOriginOfTheirOwnNamespace.
func TestCharts_placeEveryObjectInThePlatformsNamespace(t *testing.T) {
	for _, c := range []struct{ chart, instance string }{
		{operatorChart, "ratelimit-operator-biz"},
		{serviceChart, "ratelimit-service-biz"},
	} {
		t.Run(c.chart, func(t *testing.T) {
			objects := render(t, c.chart, "release-ns", "--set", "NAMESPACE=biz", "--set", "MONITORING_ENABLED=true",
				"--set", "management.enabled=true", "--set", "management.callers={ui-backend}")

			for _, o := range objects {
				assert.Equal(t, "biz", o.at("metadata", "namespace").str2(), "metadata.namespace of %s %s", o.kind(), o.name())
			}
			assert.Equal(t, c.instance,
				only(t, objects, "Deployment").at("metadata", "labels", "app.kubernetes.io/instance").str2(),
				"app.kubernetes.io/instance label of the Deployment")
			assert.Equal(t, []string{"biz"},
				strs(only(t, objects, "PodMonitor").at("spec", "namespaceSelector", "matchNames")),
				"spec.namespaceSelector.matchNames of the PodMonitor")
			assert.NotContains(t, jsonOf(t, only(t, objects, "PrometheusRule")), "release-ns",
				"the PrometheusRule scopes a rule to the release namespace")
		})
	}
}

// The service chart renders the autoscaler the platform's other services
// render. Without HPA_ENABLED it is disabled in both directions, so REPLICAS
// alone sizes the Deployment.
func TestServiceChart_disablesTheAutoscalerWithoutHPAEnabled(t *testing.T) {
	hpa := only(t, render(t, serviceChart, "biz"), "HorizontalPodAutoscaler")

	assert.Equal(t, serviceChart, hpa.at("spec", "scaleTargetRef", "name").str2(), "spec.scaleTargetRef.name")
	assert.Equal(t, "Disabled", hpa.at("spec", "behavior", "scaleUp", "selectPolicy").str2(), "scaleUp.selectPolicy")
	assert.Equal(t, "Disabled", hpa.at("spec", "behavior", "scaleDown", "selectPolicy").str2(), "scaleDown.selectPolicy")
}

// With HPA_ENABLED the autoscaler scales between HPA_MIN_REPLICAS and
// HPA_MAX_REPLICAS, at a CPU target that is a share of the limit expressed
// against the request.
func TestServiceChart_scalesBetweenTheHPABoundsWithHPAEnabled(t *testing.T) {
	spec := only(t, render(t, serviceChart, "biz", "--set", "HPA_ENABLED=true", "--set", "HPA_MIN_REPLICAS=2",
		"--set", "HPA_MAX_REPLICAS=4", "--set", "CPU_REQUEST=100m", "--set", "CPU_LIMIT=1"),
		"HorizontalPodAutoscaler").at("spec")

	assert.EqualValues(t, 2, spec.at("minReplicas").v, "minReplicas")
	assert.EqualValues(t, 4, spec.at("maxReplicas").v, "maxReplicas")
	assert.Equal(t, "Max", spec.at("behavior", "scaleUp", "selectPolicy").str2(), "scaleUp.selectPolicy")
	metrics := spec.at("metrics").list()
	require.NotEmpty(t, metrics, "spec.metrics")
	assert.EqualValues(t, 750, metrics[0].at("resource", "target", "averageUtilization").v,
		"75% of a 1-CPU limit is 750% of a 100m request")
}

// Only the service's own Deployment gets an autoscaler. The operator has
// none, because its replicas beyond the Lease holder add no capacity, and a
// satellite runs no service at all.
func TestCharts_renderNoAutoscalerWithoutAServiceDeployment(t *testing.T) {
	for _, c := range []struct {
		name  string
		chart string
		args  []string
	}{
		{"the operator chart", operatorChart, nil},
		{"the service chart in a satellite", serviceChart, []string{"--set", "BASELINE_ORIGIN=base"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.NotContains(t, kinds(render(t, c.chart, "biz", c.args...)), "HorizontalPodAutoscaler")
		})
	}
}

// The operator reads REPLICAS like the service: the HA profiles run a
// standby beside the Lease holder, the others run the holder alone.
func TestOperatorChart_readsReplicasFromTheProfile(t *testing.T) {
	for _, c := range []struct {
		profile  string
		replicas int
	}{
		{"dev", 1},
		{"dev-ha", 2},
		{"prod-nonha", 1},
		{"prod", 2},
	} {
		t.Run(c.profile, func(t *testing.T) {
			deployment := only(t, render(t, operatorChart, "biz", "-f", profileFile(operatorChart, c.profile)), "Deployment")

			assert.EqualValues(t, c.replicas, deployment.at("spec", "replicas").v, "spec.replicas")
		})
	}
}

// secretsMountedBy lists the Secrets the pod mounts as volumes.
func secretsMountedBy(pod node) []string {
	var mounted []string
	for _, volume := range pod.at("volumes").list() {
		if name := volume.at("secret", "secretName").str2(); name != "" {
			mounted = append(mounted, name)
		}
	}
	return mounted
}

// SERVICE_NAME names every object of the service chart and every reference
// to one, not only the Deployment: a flag that differs from the claim's
// classifier leaves the service without its database, and an autoscaler
// aimed at another name scales nothing.
func TestServiceChart_namesEveryReferenceAfterServiceName(t *testing.T) {
	objects := render(t, serviceChart, "biz", "-f", profileFile(serviceChart, "prod"),
		"--set", "SERVICE_NAME=rl", "--set", "management.enabled=true", "--set", "management.callers={ui-backend}")
	pod := only(t, objects, "Deployment").at("spec", "template", "spec")

	assert.Equal(t, "rl", only(t, objects, "ServiceAccount").name(), "metadata.name of the ServiceAccount")
	assert.Equal(t, "rl", pod.at("serviceAccountName").str2(), "serviceAccountName of the pod")
	assert.Contains(t, argsOf(containerOf(t, objects)), "--redis-dbaas-microservice=rl")
	for _, kind := range []string{"InternalDatabase", "DatabaseSecretClaim"} {
		claim := only(t, objects, kind)
		assert.Equal(t, "rl-redis", claim.name(), "metadata.name of the %s", kind)
		assert.Equal(t, "rl", claim.at("spec", "classifier", "microserviceName").str2(),
			"spec.classifier.microserviceName of the %s", kind)
	}
	assert.Equal(t, "rl-redis", only(t, objects, "DatabaseSecretClaim").at("spec", "secretName").str2(),
		"spec.secretName of the DatabaseSecretClaim")
	assert.Equal(t, []string{"rl-redis"}, secretsMountedBy(pod), "the Deployment mounts a Secret the claim does not name")
	hpa := only(t, objects, "HorizontalPodAutoscaler")
	assert.Equal(t, "rl", hpa.name(), "metadata.name of the HorizontalPodAutoscaler")
	assert.Equal(t, "rl", hpa.at("spec", "scaleTargetRef", "name").str2(), "the autoscaler targets another Deployment")
}

// SERVICE_NAME names every object of the operator chart and every reference
// to one: an operator started with another --deployment owns nothing, and a
// RoleBinding or a Role rule that names another object leaves the operator
// without its permissions.
func TestOperatorChart_namesEveryReferenceAfterServiceName(t *testing.T) {
	objects := render(t, operatorChart, "biz", "--set", "SERVICE_NAME=rl")
	pod := only(t, objects, "Deployment").at("spec", "template", "spec")
	role := only(t, objects, "Role")
	binding := only(t, objects, "RoleBinding")

	assert.Equal(t, "rl", only(t, objects, "ServiceAccount").name(), "metadata.name of the ServiceAccount")
	assert.Equal(t, "rl", pod.at("serviceAccountName").str2(), "serviceAccountName of the pod")
	assert.Contains(t, argsOf(containerOf(t, objects)), "--deployment=rl")
	assert.Equal(t, "rl", role.name(), "metadata.name of the Role")
	assert.Equal(t, "rl", binding.name(), "metadata.name of the RoleBinding")
	assert.Equal(t, "rl", binding.at("roleRef", "name").str2(), "roleRef.name of the RoleBinding")
	subjects := binding.at("subjects").list()
	require.NotEmpty(t, subjects, "subjects of the RoleBinding")
	assert.Equal(t, "rl", subjects[0].at("name").str2(), "name of the RoleBinding's subject")
	deployments := grantsOn(role, "deployments")
	require.Len(t, deployments, 1, "rules on deployments")
	assert.Equal(t, []string{"rl"}, deployments[0].Names, "the operator may not read the Deployment it is told to adopt")
}

// The instance label is the name and the namespace, cut to the 63 characters
// a label value may hold: a 50-character SERVICE_NAME, the dash, and the
// first 12 characters of a 40-character NAMESPACE.
func TestServiceChart_cutsTheInstanceLabelTo63Characters(t *testing.T) {
	name, namespace := strings.Repeat("n", 50), strings.Repeat("s", 40)
	labels := only(t, render(t, serviceChart, namespace, "--set", "SERVICE_NAME="+name),
		"Deployment").at("metadata", "labels")

	assert.Equal(t, strings.Repeat("n", 50)+"-"+strings.Repeat("s", 12), labels.at("app.kubernetes.io/instance").str2(),
		"app.kubernetes.io/instance label")
}

// DEPLOYMENT_STRATEGY_TYPE is read the way the platform's other services read
// it, with this chart's own rollout when it is unset.
func TestCharts_rollOutByTheStrategyType(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unset", nil,
			`{"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}}`},
		{"ramped_slow_rollout", []string{"--set", "DEPLOYMENT_STRATEGY_TYPE=ramped_slow_rollout"},
			`{"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}}`},
		{"recreate", []string{"--set", "DEPLOYMENT_STRATEGY_TYPE=recreate"},
			`{"type": "Recreate"}`},
		{"best_effort_controlled_rollout", []string{"--set", "DEPLOYMENT_STRATEGY_TYPE=best_effort_controlled_rollout"},
			`{"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 0, "maxUnavailable": "80%"}}`},
		{"custom_rollout without its parameters", []string{"--set", "DEPLOYMENT_STRATEGY_TYPE=custom_rollout"},
			`{"type": "RollingUpdate", "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": "25%"}}`},
		{"custom_rollout with its parameters", []string{"--set", "DEPLOYMENT_STRATEGY_TYPE=custom_rollout",
			"--set", "DEPLOYMENT_STRATEGY_MAXSURGE=2", "--set-string", "DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=50%"},
			`{"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 2, "maxUnavailable": "50%"}}`},
	}
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					strategy := only(t, render(t, chart, "biz", c.args...), "Deployment").at("spec", "strategy")

					assert.JSONEq(t, c.want, jsonOf(t, strategy.v), "spec.strategy")
				})
			}
		})
	}
}

// Both charts read the container's own platform parameters: a writable root
// filesystem when READONLY_CONTAINER_FILE_SYSTEM_ENABLED is off, and the
// liveness delay.
func TestCharts_readTheContainerParameters(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			container := containerOf(t, render(t, chart, "biz", "--set", "READONLY_CONTAINER_FILE_SYSTEM_ENABLED=false",
				"--set", "LIVENESS_PROBE_INITIAL_DELAY_SECONDS=42"))

			assert.Equal(t, false, container.at("securityContext", "readOnlyRootFilesystem").v,
				"securityContext.readOnlyRootFilesystem")
			assert.EqualValues(t, 42, container.at("livenessProbe", "initialDelaySeconds").v,
				"livenessProbe.initialDelaySeconds")
		})
	}
}

// Each service profile sizes the autoscaler, and the Deployment leaves the
// count to it whenever it is on: a rendered count would conflict with the
// autoscaler's under server-side apply, or undo its scaling on an upgrade.
func TestServiceChart_profilesSizeTheAutoscaler(t *testing.T) {
	for _, c := range []struct {
		profile                  string
		replicas                 any
		minReplicas, maxReplicas float64
		scaleUpPolicy            string
	}{
		{"dev", float64(1), 1, 9999, "Disabled"},
		{"dev-ha", nil, 2, 5, "Max"},
		{"prod-nonha", nil, 1, 5, "Max"},
		{"prod", nil, 2, 5, "Max"},
	} {
		t.Run(c.profile, func(t *testing.T) {
			objects := render(t, serviceChart, "biz", "-f", profileFile(serviceChart, c.profile))
			spec := only(t, objects, "HorizontalPodAutoscaler").at("spec")

			assert.Equal(t, c.replicas, only(t, objects, "Deployment").at("spec", "replicas").v,
				"spec.replicas of the Deployment")
			assert.Equal(t, c.minReplicas, spec.at("minReplicas").v, "minReplicas")
			assert.Equal(t, c.maxReplicas, spec.at("maxReplicas").v, "maxReplicas")
			assert.Equal(t, c.scaleUpPolicy, spec.at("behavior", "scaleUp", "selectPolicy").str2(), "scaleUp.selectPolicy")
			assert.EqualValues(t, 60, spec.at("behavior", "scaleUp", "stabilizationWindowSeconds").v,
				"scaleUp.stabilizationWindowSeconds")
			assert.EqualValues(t, 300, spec.at("behavior", "scaleDown", "stabilizationWindowSeconds").v,
				"scaleDown.stabilizationWindowSeconds")
			for _, direction := range []string{"scaleUp", "scaleDown"} {
				assert.Equal(t, []any{map[string]any{"type": "Pods", "value": float64(1), "periodSeconds": float64(60)}},
					spec.at("behavior", direction, "policies").v, "%s.policies", direction)
			}
		})
	}
}

// HPA_AVG_CPU_UTILIZATION_TARGET_PERCENT sets the share of the CPU limit the
// autoscaler targets, and the HPA_SCALING_UP_PERCENT_* pair adds a Percent
// policy to scaling up.
func TestServiceChart_readsTheAutoscalerTuningParameters(t *testing.T) {
	spec := only(t, render(t, serviceChart, "biz", "--set", "HPA_ENABLED=true", "--set", "HPA_MAX_REPLICAS=3",
		"--set", "HPA_AVG_CPU_UTILIZATION_TARGET_PERCENT=50", "--set", "HPA_SCALING_UP_PERCENT_VALUE=100",
		"--set", "HPA_SCALING_UP_PERCENT_PERIOD_SECONDS=30"), "HorizontalPodAutoscaler").at("spec")

	metrics := spec.at("metrics").list()
	require.NotEmpty(t, metrics, "spec.metrics")
	assert.EqualValues(t, 2500, metrics[0].at("resource", "target", "averageUtilization").v,
		"50% of the dev profile's 500m limit is 2500% of its 10m request")
	assert.Contains(t, spec.at("behavior", "scaleUp", "policies").v,
		map[string]any{"type": "Percent", "value": float64(100), "periodSeconds": float64(30)}, "scaleUp.policies")
}

// jsonWithoutTheChartNameByDesign removes from o the two places that keep the
// chart's name whatever SERVICE_NAME says, and marshals the rest: the
// binary's path among a container's args, and the groups of a
// PrometheusRule, whose group name and alert text name the chart.
func jsonWithoutTheChartNameByDesign(t *testing.T, o object) string {
	t.Helper()
	if spec, ok := o["spec"].(map[string]any); ok && o.kind() == "PrometheusRule" {
		delete(spec, "groups")
	}
	for _, container := range o.at("spec", "template", "spec", "containers").list() {
		args := slices.DeleteFunc(argsOf(container), func(arg string) bool { return strings.HasPrefix(arg, "/app/") })
		container.v.(map[string]any)["args"] = args
	}
	return jsonOf(t, o)
}

// Every object of both charts reads NAMESPACE and SERVICE_NAME, and the
// platform's labels, from the platform parameters; no place keeps the release
// namespace or the chart's own name. A reference that drifted would leave an
// installation that does not work once a parameter differs from its default:
// a classifier in another namespace, a policy principal or a RoleBinding
// subject that matches nothing, a selector that selects no pod. The two
// places that keep the chart's name by design are left out of the search:
// the binary's path in the container's arguments, and the alert rules'
// groups.
func TestCharts_readTheParametersInEveryObject(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			objects := render(t, chart, "release-ns", "-f", profileFile(chart, "prod"),
				"--set", "NAMESPACE=biz", "--set", "SERVICE_NAME=rl", "--set", "IMAGE_REPOSITORY=registry.example/rl",
				"--set", "MANAGED_BY=platform", "--set", "DEPLOYMENT_SESSION_ID=session",
				"--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true",
				"--set", "management.callers={ui-backend}",
				"--set", "CLOUD_TOPOLOGIES[0].topologyKey=topology.kubernetes.io/zone")
			require.NotEmpty(t, objects)

			for _, o := range objects {
				what := o.kind() + " " + o.name()
				labels := o.at("metadata", "labels")
				assert.Equal(t, "platform", labels.at("app.kubernetes.io/managed-by").str2(),
					"app.kubernetes.io/managed-by label of %s", what)
				assert.Equal(t, "session", labels.at("deployment.netcracker.com/sessionId").str2(),
					"sessionId label of %s", what)
				assert.Equal(t, "rl", labels.at("app.kubernetes.io/name").str2(), "app.kubernetes.io/name label of %s", what)
				rendered := jsonWithoutTheChartNameByDesign(t, o)
				assert.NotContains(t, rendered, "release-ns", "%s reads the release namespace", what)
				assert.NotContains(t, rendered, chart, "%s keeps the chart's own name", what)
			}
			assert.Equal(t, "rl", only(t, objects, "Deployment").at("spec", "template", "metadata", "labels", "name").str2(),
				"the pods do not carry the label the selector reads")
		})
	}
}

// The CRD is cluster-scoped and has one owner, the ratelimit-crds release: it
// renders exactly the CRD the operator is built against, with the annotation
// that keeps an uninstall from taking every namespace's policies with it. The
// namespace charts render no copy, which would bring back the contest over
// its ownership between the releases of every namespace.
func TestCRDChart_ownsTheCRD(t *testing.T) {
	t.Run("the CRD chart renders the generated CRD under the keep policy", func(t *testing.T) {
		out, err := exec.Command("helm", "template", "t", chartFile("ratelimit-crds")).CombinedOutput()
		require.NoError(t, err, "%s", out)
		raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd", "bases",
			"ratelimit.netcracker.com_ratelimitpolicies.yaml"))
		require.NoError(t, err)
		var generated object
		require.NoError(t, yaml.Unmarshal(raw, &generated))

		crds := parse(t, out)
		require.Len(t, crds, 1, "objects the CRD chart renders")
		crd := crds[0]
		assert.Equal(t, "CustomResourceDefinition", crd.kind(), "kind")
		assert.Equal(t, "keep", crd.at("metadata", "annotations", "helm.sh/resource-policy").str2(),
			"helm.sh/resource-policy annotation")
		assert.Equal(t, generated.name(), crd.name(), "metadata.name")
		assert.Equal(t, generated.at("spec").v, crd.at("spec").v, "the chart's CRD drifted from config/crd/bases")
	})
	for _, chart := range namespaceCharts {
		t.Run(chart+" renders no CRD", func(t *testing.T) {
			objects := render(t, chart, "biz", "--set", "MONITORING_ENABLED=true")

			assert.NotContains(t, kinds(objects), "CustomResourceDefinition")
		})
	}
}

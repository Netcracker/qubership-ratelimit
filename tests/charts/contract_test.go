// Package charts renders the two charts of the split and compares what they
// render with the constants of api/contract. The templates carry the Service
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

	envoyFilterKind = "EnvoyFilter"
)

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

// render runs helm template on a chart with the dev profile and the given
// extra arguments, and parses every document it produced. NAMESPACE is the
// release namespace and TAG is imageTag unless a --set in the extra arguments
// overrides them; a values file there cannot, because helm applies every --set
// after the files. The platform sets both on every installation, and both
// schemas require them.
func render(t *testing.T, chart, namespace string, extra ...string) []object {
	t.Helper()
	out, err := renderErr(chart, namespace, extra...)
	require.NoError(t, err, "%s", out)

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
func renderErr(chart, namespace string, extra ...string) ([]byte, error) {
	platform := []string{"--set", "NAMESPACE=" + namespace, "--set", "TAG=" + imageTag}
	return helmTemplate(chart, namespace, append(platform, extra...)...)
}

// helmTemplate is renderErr without NAMESPACE and TAG, for the tests of what
// the schemas do with an installation that leaves them out.
func helmTemplate(chart, namespace string, extra ...string) ([]byte, error) {
	dir := filepath.Join("..", "..", "helm-templates", chart)
	args := append([]string{"template", "t", dir, "-n", namespace,
		"-f", filepath.Join(dir, "resource-profiles", "dev.yaml")}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("helm %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return out, nil
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

func only(t *testing.T, objects []object, kind string) object {
	t.Helper()
	var found []object
	for _, o := range objects {
		if o.kind() == kind {
			found = append(found, o)
		}
	}
	require.Len(t, found, 1, "expected exactly one %s", kind)
	return found[0]
}

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

// The Service of the service chart: the name and the two ports the chart's
// filters and the operator binary address it by.
func TestServiceChart_rendersTheServiceOfTheContract(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true")
	service := only(t, objects, "Service")
	assert.Equal(t, contract.ServiceName, service.name())

	ports := map[string]node{}
	for _, port := range service.at("spec", "ports").list() {
		ports[port.at("name").str2()] = port
	}
	require.Contains(t, ports, contract.GRPCPortName)
	assert.Equal(t, float64(contract.GRPCPort), ports[contract.GRPCPortName].at("port").num())
	assert.Equal(t, "grpc", ports[contract.GRPCPortName].at("appProtocol").str2(),
		"without appProtocol Istio takes the port for HTTP/1.1")
	require.Contains(t, ports, contract.MetricsPortName, "the operator reads the applied generation on this port")
	assert.Contains(t, ports, "management")

	// The pod: the gRPC listener on the contract's port, the mount at the
	// contract's path, the ConfigMap of the contract's name, and no token.
	deployment := only(t, objects, "Deployment")
	pod := deployment.at("spec", "template", "spec")
	assert.Equal(t, false, pod.at("automountServiceAccountToken").v)
	containers := pod.at("containers").list()
	require.Len(t, containers, 1)
	container := containers[0]
	args := argsOf(container)
	assert.Contains(t, args, fmt.Sprintf("--rls-bind-address=:%d", contract.GRPCPort))
	assert.Contains(t, args, "--config-dir="+contract.MountPath)

	containerPorts := map[string]float64{}
	for _, port := range container.at("ports").list() {
		containerPorts[port.at("name").str2()] = port.at("containerPort").num()
	}
	assert.Equal(t, float64(contract.GRPCPort), containerPorts[contract.GRPCPortName])
	assert.Contains(t, containerPorts, contract.MetricsPortName)

	var mounted bool
	for _, mount := range container.at("volumeMounts").list() {
		if mount.at("mountPath").str2() == contract.MountPath {
			mounted = true
			assert.Equal(t, true, mount.at("readOnly").v)
		}
	}
	assert.True(t, mounted, "the configuration is mounted at %s", contract.MountPath)
	var volume node
	for _, v := range pod.at("volumes").list() {
		if v.at("configMap", "name").str2() == contract.ConfigMapName {
			volume = v
		}
	}
	require.NotNil(t, volume.v, "the volume is the ConfigMap %s", contract.ConfigMapName)
	assert.Equal(t, true, volume.at("configMap", "optional").v, "the pod starts before the operator has written")

	// No Role, no RoleBinding: the data plane holds no credentials.
	assert.NotContains(t, kinds(objects), "Role")
	assert.NotContains(t, kinds(objects), "RoleBinding")
	assert.Equal(t, false, only(t, objects, "ServiceAccount")["automountServiceAccountToken"])
}

// The service chart's filters address the Service by the contract's name
// and port, in NAMESPACE or in the baseline's: one filter per enabled
// gateway, named after the chart.
func TestServiceChart_filtersAddressTheServiceOfTheContract(t *testing.T) {
	authority := func(namespace string) string {
		return fmt.Sprintf("%s.%s.svc.cluster.local", contract.ServiceName, namespace)
	}
	cluster := func(namespace string) string {
		return fmt.Sprintf("outbound|%d||%s", contract.GRPCPort, authority(namespace))
	}
	check := func(t *testing.T, objects []object, namespace string) {
		t.Helper()
		var names []string
		for _, o := range objects {
			if o.kind() != envoyFilterKind {
				continue
			}
			names = append(names, o.name())
			assert.Equal(t, serviceChart, o.at("metadata", "labels", "app.kubernetes.io/name").str2(), o.name())
			raw, err := yaml.Marshal(o)
			require.NoError(t, err)
			assert.Contains(t, string(raw), "authority: "+authority(namespace))
			assert.Contains(t, string(raw), "cluster_name: "+cluster(namespace))
		}
		assert.ElementsMatch(t, []string{serviceChart + "-public-gateway", serviceChart + "-private-gateway"}, names,
			"one filter per enabled gateway")
	}

	t.Run("baseline", func(t *testing.T) {
		check(t, render(t, serviceChart, "biz"), "biz")
	})
	t.Run("satellite", func(t *testing.T) {
		objects := render(t, serviceChart, "sat", "--set", "BASELINE_ORIGIN=base", "--set", "MONITORING_ENABLED=true",
			"--set", "management.enabled=true")
		assert.Equal(t, []string{envoyFilterKind}, kinds(objects), "a satellite gets the filters and nothing else")
		check(t, objects, "base")
	})
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
	split := func(objects []object) (filters, rest map[string]string) {
		filters, rest = map[string]string{}, map[string]string{}
		for _, o := range objects {
			raw, err := json.Marshal(o)
			require.NoError(t, err)
			if o.kind() == envoyFilterKind {
				filters[o.name()] = string(raw)
			} else {
				rest[o.kind()+"/"+o.name()] = string(raw)
			}
		}
		return filters, rest
	}
	all := []string{"--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true"}
	defaultFilters, defaultRest := split(render(t, serviceChart, "biz", all...))
	require.Len(t, defaultFilters, 2, "one filter per enabled gateway")
	for _, dial := range []string{"runtime.enforcedPercent=0", "runtime.enabledPercent=0", "filter.failClosed=true"} {
		filters, rest := split(render(t, serviceChart, "biz", append(all, "--set", dial)...))
		assert.Equal(t, defaultRest, rest, "%s changed an object other than the filters", dial)
		assert.NotEqual(t, defaultFilters, filters, "%s left the filters as they were", dial)
	}
}

// The operator adopts its own Deployment by the name the chart gives it, and
// its Role names that Deployment and the ConfigMap.
func TestOperatorChart_reachesItsOwnObjectsByName(t *testing.T) {
	objects := render(t, operatorChart, "biz")
	deployment := only(t, objects, "Deployment")
	containers := deployment.at("spec", "template", "spec", "containers").list()
	require.Len(t, containers, 1)
	assert.Contains(t, argsOf(containers[0]), "--deployment="+deployment.name())
	// The Role reaches one ConfigMap and one Deployment by name: create
	// is the only verb granted on ConfigMaps in general, since RBAC
	// cannot narrow it. Anything wider would let a compromised operator
	// pod read or overwrite the configuration of the other applications
	// in the namespace. There is no ClusterRole.
	assert.NotContains(t, kinds(objects), "ClusterRole")
	for _, rule := range only(t, objects, "Role").at("rules").list() {
		resources := strs(rule.at("resources"))
		verbs := strs(rule.at("verbs"))
		names := strs(rule.at("resourceNames"))
		switch {
		case slices.Contains(resources, "configmaps") && len(names) == 0:
			assert.Equal(t, []string{"create"}, verbs, "an unnamed ConfigMap rule grants create and nothing else")
		case slices.Contains(resources, "configmaps"):
			assert.Equal(t, []string{contract.ConfigMapName}, names)
			assert.NotContains(t, verbs, "delete")
			assert.NotContains(t, verbs, "patch")
		case slices.Contains(resources, "deployments"):
			assert.Equal(t, []string{deployment.name()}, names)
			assert.Equal(t, []string{"get"}, verbs)
		case slices.Contains(resources, "ratelimitpolicies/status"):
			assert.Equal(t, []string{"update"}, verbs, "the status is written with Update, never patched")
		}
	}
}

// A BASELINE_ORIGIN naming the release's own namespace is refused by both
// charts. Rendered as a satellite of itself, the namespace used to lose its
// operator and its service in one upgrade, with filters left pointing at the
// Service that upgrade removed.
func TestCharts_refuseABaselineOriginOfTheirOwnNamespace(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		out, err := renderErr(chart, "team-a", "--set", "BASELINE_ORIGIN=team-a")
		require.Error(t, err, "%s rendered a namespace as a satellite of itself", chart)
		assert.Contains(t, string(out), "is this release's own namespace", chart)
	}
}

// Both Deployments spread their pods the way the platform's other services
// do: one constraint on CLOUD_TOPOLOGY_KEY, the node by default, or one per
// entry of CLOUD_TOPOLOGIES, each selecting the Deployment's own pods.
func TestCharts_spreadTheirPodsOverTheTopology(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		deployment := only(t, render(t, chart, "biz"), "Deployment")
		spread := deployment.at("spec", "template", "spec", "topologySpreadConstraints").list()
		require.Len(t, spread, 1, chart)
		assert.Equal(t, "kubernetes.io/hostname", spread[0].at("topologyKey").str2(), chart)
		assert.EqualValues(t, 1, spread[0].at("maxSkew").v, chart)
		assert.Equal(t, "ScheduleAnyway", spread[0].at("whenUnsatisfiable").str2(), chart)
		assert.Equal(t, deployment.at("spec", "selector", "matchLabels").v,
			spread[0].at("labelSelector", "matchLabels").v, "%s spreads over pods it does not own", chart)

		deployment = only(t, render(t, chart, "biz",
			"--set", "CLOUD_TOPOLOGIES[0].topologyKey=topology.kubernetes.io/zone",
			"--set", "CLOUD_TOPOLOGIES[1].topologyKey=kubernetes.io/hostname",
			"--set", "CLOUD_TOPOLOGIES[1].maxSkew=2",
			"--set", "CLOUD_TOPOLOGIES[1].whenUnsatisfiable=DoNotSchedule"), "Deployment")
		spread = deployment.at("spec", "template", "spec", "topologySpreadConstraints").list()
		require.Len(t, spread, 2, chart)
		assert.Equal(t, "topology.kubernetes.io/zone", spread[0].at("topologyKey").str2(), chart)
		assert.Equal(t, "ScheduleAnyway", spread[0].at("whenUnsatisfiable").str2(), chart)
		assert.EqualValues(t, 2, spread[1].at("maxSkew").v, chart)
		assert.Equal(t, "DoNotSchedule", spread[1].at("whenUnsatisfiable").str2(), chart)

		_, err := renderErr(chart, "biz", "--set", "CLOUD_TOPOLOGIES[0].topologyKey=x",
			"--set", "CLOUD_TOPOLOGIES[0].whenUnsatisfiable=Sometimes")
		assert.Error(t, err, "%s accepts an unknown whenUnsatisfiable", chart)
	}
}

// The management port is safe only behind its AuthorizationPolicy, and the
// policy is only worth anything in the exact shape it has: DENY on the
// management port for every principal except the private gateway's service
// account, which Istio's automated deployment names after the gateway and its
// class. The check reads the structure, so a policy that keeps the same
// principal under principals, or turns into an ALLOW, fails here.
func TestServiceChart_managementPolicyDeniesAllButThePrivateGateway(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true")
	policy := only(t, objects, "AuthorizationPolicy")
	deployment := only(t, objects, "Deployment")

	assert.Equal(t, "DENY", policy.at("spec", "action").str2())
	assert.Equal(t, deployment.at("spec", "selector", "matchLabels").v,
		policy.at("spec", "selector", "matchLabels").v, "the policy does not select the service's pods")

	rules := policy.at("spec", "rules").list()
	require.Len(t, rules, 1)
	to := rules[0].at("to").list()
	require.Len(t, to, 1)
	assert.Equal(t, []string{"8082"}, strs(to[0].at("operation", "ports")), "the policy covers another port")

	from := rules[0].at("from").list()
	require.Len(t, from, 1)
	assert.Equal(t, []string{"cluster.local/ns/biz/sa/private-gateway-istio"},
		strs(from[0].at("source", "notPrincipals")), "the only exception is not the private gateway")
	assert.Nil(t, from[0].at("source", "principals").v, "a principals list turns the exception into the target")
}

// The dashboard opens on its own release's namespace. Domain names repeat
// across namespaces, so a default of All merged one installation's panels with
// every other's; All stays available as a choice.
func TestServiceChart_dashboardOpensOnItsOwnNamespace(t *testing.T) {
	dashboard := only(t, render(t, serviceChart, "team-a", "--set", "MONITORING_ENABLED=true"), "GrafanaDashboard")
	var model struct {
		Templating struct {
			List []struct {
				Name    string `json:"name"`
				Current struct {
					Value any `json:"value"`
				} `json:"current"`
				IncludeAll bool `json:"includeAll"`
			} `json:"list"`
		} `json:"templating"`
	}
	require.NoError(t, json.Unmarshal([]byte(dashboard.at("spec", "json").str2()), &model))
	for _, variable := range model.Templating.List {
		if variable.Name != "namespace" {
			continue
		}
		assert.Equal(t, "team-a", variable.Current.Value, "the dashboard does not open on its release's namespace")
		assert.True(t, variable.IncludeAll, "All is no longer a choice")
		return
	}
	t.Fatal("the dashboard has no namespace variable")
}

// The operator chart renders nothing in a satellite, whatever the values say:
// a satellite runs no operator, and its filters come from the service chart.
func TestOperatorChart_rendersNothingInASatellite(t *testing.T) {
	objects := render(t, operatorChart, "sat", "--set", "BASELINE_ORIGIN=base", "--set", "MONITORING_ENABLED=true")
	assert.Empty(t, objects)
}

// Neither chart renders the ConfigMap: the operator is its only writer.
func TestCharts_renderNoConfigMap(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		objects := render(t, chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true")
		assert.NotContains(t, kinds(objects), "ConfigMap", chart)
	}
}

// The pods of each chart carry the chart's name, which is what the e2e
// helpers and the PodMonitors select by.
func TestCharts_labelThePodsByChartName(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		deployment := only(t, render(t, chart, "biz"), "Deployment")
		assert.Equal(t, chart, deployment.at("spec", "template", "metadata", "labels", "app.kubernetes.io/name").str2())
	}
}

// Both charts read the parameters the platform sets on every one of its
// services, the way its other services read them: the name, the image, the
// labels, the log level, the security context, and the rollout.
func TestCharts_readThePlatformParameters(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		deployment := only(t, render(t, chart, "biz",
			"--set", "SERVICE_NAME=rl",
			"--set", "IMAGE_REPOSITORY=registry.example/rl",
			"--set", "TAG=1.2.3",
			"--set", "APPLICATION_NAME=app",
			"--set", "MANAGED_BY=platform",
			"--set", "ARTIFACT_DESCRIPTOR_VERSION=1.2.3-ad",
			"--set", "DEPLOYMENT_SESSION_ID=session",
			"--set", "LOG_LEVEL=DEBUG",
			"--set", "DEPLOYMENT_STRATEGY_TYPE=recreate"), "Deployment")
		assert.Equal(t, "rl", deployment.name(), chart)
		labels := deployment.at("metadata", "labels")
		assert.Equal(t, "app", labels.at("app.kubernetes.io/part-of").str2(), chart)
		assert.Equal(t, "platform", labels.at("app.kubernetes.io/managed-by").str2(), chart)
		assert.Equal(t, "1.2.3-ad", labels.at("app.kubernetes.io/version").str2(), chart)
		assert.Equal(t, "session", labels.at("deployment.netcracker.com/sessionId").str2(), chart)
		assert.Nil(t, deployment.at("spec", "template", "metadata", "labels", "deployment.netcracker.com/sessionId").v,
			"%s restarts its pods on every deployment", chart)
		assert.Equal(t, map[string]any{"name": "rl"}, deployment.at("spec", "selector", "matchLabels").v, chart)
		assert.Equal(t, "rl-biz", labels.at("app.kubernetes.io/instance").str2(), chart)
		assert.Equal(t, "Recreate", deployment.at("spec", "strategy", "type").str2(), chart)

		container := deployment.at("spec", "template", "spec", "containers").list()[0]
		assert.Equal(t, "registry.example/rl:1.2.3", container.at("image").str2(), chart)
		env := map[string]string{}
		for _, variable := range container.at("env").list() {
			env[variable.at("name").str2()] = variable.at("value").str2()
		}
		assert.Equal(t, "debug", env["LOGGING_LEVEL_ROOT"], chart)
		version := map[string]string{operatorChart: "OPERATOR_VERSION", serviceChart: "SERVICE_VERSION"}[chart]
		assert.Equal(t, "1.2.3", env[version], "%s reports a version other than its image tag", chart)

		security := container.at("securityContext")
		assert.Equal(t, true, security.at("readOnlyRootFilesystem").v, chart)
		assert.EqualValues(t, 10001, security.at("runAsGroup").v, chart)
		container = only(t, render(t, chart, "biz", "--set", "PAAS_PLATFORM=OPENSHIFT"), "Deployment").
			at("spec", "template", "spec", "containers").list()[0]
		assert.Equal(t, false, container.at("securityContext", "readOnlyRootFilesystem").v, chart)
		assert.Nil(t, container.at("securityContext", "runAsGroup").v, "%s pins a group on OpenShift", chart)
	}
}

// Both schemas refuse an installation that leaves NAMESPACE or TAG at its
// empty default or removes it: the namespace goes into the RLS address and the
// policy principals, and the tag into the image reference. Each case leaves
// one of the two out and sets the other.
func TestCharts_refuseAnInstallationWithoutNamespaceOrTag(t *testing.T) {
	cases := map[string]struct{ set, key string }{
		"NAMESPACE at its default": {"TAG=1.2.3", "NAMESPACE"},
		"NAMESPACE removed":        {"TAG=1.2.3,NAMESPACE=null", "NAMESPACE"},
		"TAG at its default":       {"NAMESPACE=biz", "TAG"},
		"TAG removed":              {"NAMESPACE=biz,TAG=null", "TAG"},
	}
	for _, chart := range []string{operatorChart, serviceChart} {
		for name, c := range cases {
			out, err := helmTemplate(chart, "biz", "--set", c.set)
			assert.Error(t, err, "%s with %s rendered", chart, name)
			assert.Contains(t, string(out), c.key, "%s with %s", chart, name)
		}
	}
}

// Without the optional platform parameters, the Deployment runs the chart's
// own image from ghcr.io, carries an empty version label and Helm as its
// manager, and rolls out keeping every pod until its replacement is Ready.
func TestCharts_defaultTheOptionalPlatformParameters(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		deployment := only(t, render(t, chart, "biz"), "Deployment")
		container := deployment.at("spec", "template", "spec", "containers").list()[0]
		assert.Equal(t, "ghcr.io/netcracker/qubership-"+chart+":"+imageTag, container.at("image").str2(), chart)
		assert.Equal(t, "", deployment.at("metadata", "labels", "app.kubernetes.io/version").v, chart)
		assert.Equal(t, "Helm", deployment.at("metadata", "labels", "app.kubernetes.io/managed-by").str2(), chart)
		assert.Equal(t, "RollingUpdate", deployment.at("spec", "strategy", "type").str2(), chart)
		assert.EqualValues(t, 1, deployment.at("spec", "strategy", "rollingUpdate", "maxSurge").v, chart)
		assert.EqualValues(t, 0, deployment.at("spec", "strategy", "rollingUpdate", "maxUnavailable").v, chart)
	}
}

// NAMESPACE, the platform parameter, places every object of both charts,
// and the namespace-scoped references inside them follow it: the instance
// label, the scrape, the rules, and the satellite guard.
func TestCharts_placeEveryObjectInThePlatformsNamespace(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		objects := render(t, chart, "release-ns", "--set", "NAMESPACE=biz", "--set", "MONITORING_ENABLED=true",
			"--set", "management.enabled=true")
		for _, o := range objects {
			if o.kind() == "CustomResourceDefinition" {
				continue
			}
			assert.Equal(t, "biz", o.at("metadata", "namespace").str2(), "%s %s %s", chart, o.kind(), o.name())
		}
		deployment := only(t, objects, "Deployment")
		assert.Equal(t, "biz", strings.TrimPrefix(
			deployment.at("metadata", "labels", "app.kubernetes.io/instance").str2(), chart+"-"), chart)
		assert.Equal(t, []string{"biz"},
			strs(only(t, objects, "PodMonitor").at("spec", "namespaceSelector", "matchNames")), chart)
		rules, err := json.Marshal(only(t, objects, "PrometheusRule"))
		require.NoError(t, err)
		assert.NotContains(t, string(rules), "release-ns", "%s scopes a rule to the release namespace", chart)

		out, err := renderErr(chart, "release-ns", "--set", "NAMESPACE=biz", "--set", "BASELINE_ORIGIN=biz")
		require.Error(t, err, "%s rendered NAMESPACE as a satellite of itself", chart)
		assert.Contains(t, string(out), "is this release's own namespace", chart)
	}
}

// The service chart renders the autoscaler the platform's other services
// render: disabled in both directions without HPA_ENABLED, so REPLICAS alone
// sizes the Deployment, and between HPA_MIN_REPLICAS and HPA_MAX_REPLICAS
// with it, at a CPU target that is a share of the limit. The operator has
// none: its replicas beyond the Lease holder add no capacity.
func TestServiceChart_scalesWithTheAutoscalerParameters(t *testing.T) {
	hpa := only(t, render(t, serviceChart, "biz"), "HorizontalPodAutoscaler")
	assert.Equal(t, serviceChart, hpa.at("spec", "scaleTargetRef", "name").str2())
	assert.Equal(t, "Disabled", hpa.at("spec", "behavior", "scaleUp", "selectPolicy").str2())
	assert.Equal(t, "Disabled", hpa.at("spec", "behavior", "scaleDown", "selectPolicy").str2())

	hpa = only(t, render(t, serviceChart, "biz", "--set", "HPA_ENABLED=true", "--set", "HPA_MIN_REPLICAS=2",
		"--set", "HPA_MAX_REPLICAS=4", "--set", "CPU_REQUEST=100m", "--set", "CPU_LIMIT=1"), "HorizontalPodAutoscaler")
	assert.EqualValues(t, 2, hpa.at("spec", "minReplicas").v)
	assert.EqualValues(t, 4, hpa.at("spec", "maxReplicas").v)
	assert.Equal(t, "Max", hpa.at("spec", "behavior", "scaleUp", "selectPolicy").str2())
	metric := hpa.at("spec", "metrics").list()[0]
	assert.EqualValues(t, 750, metric.at("resource", "target", "averageUtilization").v,
		"75% of a 1-CPU limit is 750% of a 100m request")

	assert.NotContains(t, kinds(render(t, operatorChart, "biz")), "HorizontalPodAutoscaler")
	assert.NotContains(t, kinds(render(t, serviceChart, "biz", "--set", "BASELINE_ORIGIN=base")),
		"HorizontalPodAutoscaler")
}

// The operator reads REPLICAS like the service: the HA profiles run a
// standby beside the Lease holder, the others run the holder alone.
func TestOperatorChart_readsReplicasFromTheProfile(t *testing.T) {
	for profile, replicas := range map[string]int{"dev": 1, "dev-ha": 2, "prod-nonha": 1, "prod": 2} {
		dir := filepath.Join("..", "..", "helm-templates", operatorChart, "resource-profiles", profile+".yaml")
		deployment := only(t, render(t, operatorChart, "biz", "-f", dir), "Deployment")
		assert.EqualValues(t, replicas, deployment.at("spec", "replicas").v, profile)
	}
}

// SERVICE_NAME names every object and every reference to one, not only the
// Deployment: a flag that differs from the claim's classifier leaves the
// service without its database, an autoscaler aimed at another name scales
// nothing, and an operator started with another --deployment owns nothing.
func TestCharts_nameEveryReferenceAfterServiceName(t *testing.T) {
	objects := render(t, serviceChart, "biz", "-f",
		filepath.Join("..", "..", "helm-templates", serviceChart, "resource-profiles", "prod.yaml"),
		"--set", "SERVICE_NAME=rl", "--set", "management.enabled=true")
	deployment := only(t, objects, "Deployment")
	pod := deployment.at("spec", "template", "spec")
	assert.Equal(t, "rl", only(t, objects, "ServiceAccount").name())
	assert.Equal(t, "rl", pod.at("serviceAccountName").str2())
	assert.Contains(t, argsOf(pod.at("containers").list()[0]), "--redis-dbaas-microservice=rl")
	for _, kind := range []string{"InternalDatabase", "DatabaseSecretClaim"} {
		claim := only(t, objects, kind)
		assert.Equal(t, "rl-redis", claim.name(), kind)
		assert.Equal(t, "rl", claim.at("spec", "classifier", "microserviceName").str2(), kind)
	}
	assert.Equal(t, "rl-redis", only(t, objects, "DatabaseSecretClaim").at("spec", "secretName").str2())
	var mounted []string
	for _, volume := range pod.at("volumes").list() {
		if name := volume.at("secret", "secretName").str2(); name != "" {
			mounted = append(mounted, name)
		}
	}
	assert.Equal(t, []string{"rl-redis"}, mounted, "the Deployment mounts a Secret the claim does not name")
	hpa := only(t, objects, "HorizontalPodAutoscaler")
	assert.Equal(t, "rl", hpa.name())
	assert.Equal(t, "rl", hpa.at("spec", "scaleTargetRef", "name").str2(), "the autoscaler targets another Deployment")

	objects = render(t, operatorChart, "biz", "--set", "SERVICE_NAME=rl")
	deployment = only(t, objects, "Deployment")
	pod = deployment.at("spec", "template", "spec")
	assert.Equal(t, "rl", only(t, objects, "ServiceAccount").name())
	assert.Equal(t, "rl", pod.at("serviceAccountName").str2())
	assert.Contains(t, argsOf(pod.at("containers").list()[0]), "--deployment=rl")
	assert.Equal(t, "rl", only(t, objects, "Role").name())
	binding := only(t, objects, "RoleBinding")
	assert.Equal(t, "rl", binding.name())
	assert.Equal(t, "rl", binding.at("roleRef", "name").str2())
	assert.Equal(t, "rl", binding.at("subjects").list()[0].at("name").str2())
	var owner []string
	for _, rule := range only(t, objects, "Role").at("rules").list() {
		if slices.Contains(strs(rule.at("resources")), "deployments") {
			owner = strs(rule.at("resourceNames"))
		}
	}
	assert.Equal(t, []string{"rl"}, owner, "the operator may not read the Deployment it is told to adopt")

	// The instance label is the name and the namespace, cut to a label's 63.
	long := strings.Repeat("n", 50)
	labels := only(t, render(t, serviceChart, strings.Repeat("s", 40), "--set", "SERVICE_NAME="+long),
		"Deployment").at("metadata", "labels")
	instance := labels.at("app.kubernetes.io/instance").str2()
	assert.Len(t, instance, 63)
	assert.True(t, strings.HasPrefix(instance, long+"-"))
}

// DEPLOYMENT_STRATEGY_TYPE is read the way the platform's other services read
// it, with this chart's own rollout when it is unset.
func TestCharts_rollOutByTheStrategyType(t *testing.T) {
	type rollout struct{ kind, surge, unavailable string }
	cases := map[string]struct {
		args []string
		want rollout
	}{
		"unset":                          {nil, rollout{"RollingUpdate", "1", "0"}},
		"ramped_slow_rollout":            {nil, rollout{"RollingUpdate", "1", "0"}},
		"recreate":                       {nil, rollout{"Recreate", "", ""}},
		"best_effort_controlled_rollout": {nil, rollout{"RollingUpdate", "0", "80%"}},
		"custom_rollout": {[]string{"--set", "DEPLOYMENT_STRATEGY_MAXSURGE=2",
			"--set-string", "DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=50%"}, rollout{"RollingUpdate", "2", "50%"}},
	}
	for _, chart := range []string{operatorChart, serviceChart} {
		for name, c := range cases {
			args := c.args
			if name != "unset" {
				args = append([]string{"--set", "DEPLOYMENT_STRATEGY_TYPE=" + name}, args...)
			}
			strategy := only(t, render(t, chart, "biz", args...), "Deployment").at("spec", "strategy")
			got := rollout{
				strategy.at("type").str2(),
				fmt.Sprint(strategy.at("rollingUpdate", "maxSurge").v),
				fmt.Sprint(strategy.at("rollingUpdate", "maxUnavailable").v),
			}
			if got.surge == "<nil>" {
				got.surge, got.unavailable = "", ""
			}
			assert.Equal(t, c.want, got, "%s: %s", chart, name)
		}
		strategy := only(t, render(t, chart, "biz", "--set", "DEPLOYMENT_STRATEGY_TYPE=custom_rollout"),
			"Deployment").at("spec", "strategy", "rollingUpdate")
		assert.Equal(t, "25%", strategy.at("maxSurge").str2(), chart)
		assert.Equal(t, "25%", strategy.at("maxUnavailable").str2(), chart)
	}
}

// The container's own platform parameters: a writable root filesystem when
// READONLY_CONTAINER_FILE_SYSTEM_ENABLED is off, and the liveness delay.
func TestCharts_readTheContainerParameters(t *testing.T) {
	for _, chart := range []string{operatorChart, serviceChart} {
		container := only(t, render(t, chart, "biz", "--set", "READONLY_CONTAINER_FILE_SYSTEM_ENABLED=false",
			"--set", "LIVENESS_PROBE_INITIAL_DELAY_SECONDS=42"), "Deployment").
			at("spec", "template", "spec", "containers").list()[0]
		assert.Equal(t, false, container.at("securityContext", "readOnlyRootFilesystem").v, chart)
		assert.EqualValues(t, 42, container.at("livenessProbe", "initialDelaySeconds").v, chart)
	}
}

// Each service profile sizes the autoscaler, and the Deployment leaves the
// count to it whenever it is on: a rendered count would conflict with the
// autoscaler's under server-side apply, or undo its scaling on an upgrade.
func TestServiceChart_profilesSizeTheAutoscaler(t *testing.T) {
	type sizing struct {
		enabled          bool
		replicas         any
		minimum, maximum float64
	}
	for profile, want := range map[string]sizing{
		"dev":        {false, float64(1), 1, 9999},
		"dev-ha":     {true, nil, 2, 5},
		"prod-nonha": {true, nil, 1, 5},
		"prod":       {true, nil, 2, 5},
	} {
		objects := render(t, serviceChart, "biz", "-f",
			filepath.Join("..", "..", "helm-templates", serviceChart, "resource-profiles", profile+".yaml"))
		assert.Equal(t, want.replicas, only(t, objects, "Deployment").at("spec", "replicas").v, profile)
		spec := only(t, objects, "HorizontalPodAutoscaler").at("spec")
		assert.Equal(t, want.minimum, spec.at("minReplicas").v, profile)
		assert.Equal(t, want.maximum, spec.at("maxReplicas").v, profile)
		policy := "Disabled"
		if want.enabled {
			policy = "Max"
		}
		assert.Equal(t, policy, spec.at("behavior", "scaleUp", "selectPolicy").str2(), profile)
		assert.EqualValues(t, 60, spec.at("behavior", "scaleUp", "stabilizationWindowSeconds").v, profile)
		assert.EqualValues(t, 300, spec.at("behavior", "scaleDown", "stabilizationWindowSeconds").v, profile)
		for _, direction := range []string{"scaleUp", "scaleDown"} {
			assert.Equal(t, []any{map[string]any{"type": "Pods", "value": float64(1), "periodSeconds": float64(60)}},
				spec.at("behavior", direction, "policies").v, "%s %s", profile, direction)
		}
	}

	spec := only(t, render(t, serviceChart, "biz", "--set", "HPA_ENABLED=true", "--set", "HPA_MAX_REPLICAS=3",
		"--set", "HPA_AVG_CPU_UTILIZATION_TARGET_PERCENT=50", "--set", "HPA_SCALING_UP_PERCENT_VALUE=100",
		"--set", "HPA_SCALING_UP_PERCENT_PERIOD_SECONDS=30"), "HorizontalPodAutoscaler").at("spec")
	assert.EqualValues(t, 2500, spec.at("metrics").list()[0].at("resource", "target", "averageUtilization").v,
		"50% of the dev profile's 500m limit is 2500% of its 10m request")
	assert.Contains(t, spec.at("behavior", "scaleUp", "policies").v,
		map[string]any{"type": "Percent", "value": float64(100), "periodSeconds": float64(30)})
}

// Every object of both charts reads NAMESPACE and SERVICE_NAME, and the
// platform's labels, from the platform parameters; no place keeps the release
// namespace or the chart's own name. A reference that drifted would leave an
// installation that does not work once a parameter differs from its default:
// a classifier in another namespace, a policy principal or a RoleBinding
// subject that matches nothing, a selector that selects no pod. The two
// places that keep the chart's name by design are skipped: the binary's path
// in the container's arguments, and the alert rules' text.
func TestCharts_readTheParametersInEveryObject(t *testing.T) {
	topologies := []string{"--set", "CLOUD_TOPOLOGIES[0].topologyKey=topology.kubernetes.io/zone"}
	for _, chart := range []string{operatorChart, serviceChart} {
		args := append([]string{"-f", filepath.Join("..", "..", "helm-templates", chart, "resource-profiles", "prod.yaml"),
			"--set", "NAMESPACE=biz", "--set", "SERVICE_NAME=rl", "--set", "IMAGE_REPOSITORY=registry.example/rl",
			"--set", "MANAGED_BY=platform", "--set", "DEPLOYMENT_SESSION_ID=session",
			"--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true"}, topologies...)
		objects := render(t, chart, "release-ns", args...)
		require.NotEmpty(t, objects, chart)
		for _, o := range objects {
			if o.kind() == "CustomResourceDefinition" {
				continue
			}
			what := chart + " " + o.kind() + " " + o.name()
			labels := o.at("metadata", "labels")
			assert.Equal(t, "platform", labels.at("app.kubernetes.io/managed-by").str2(), what)
			assert.Equal(t, "session", labels.at("deployment.netcracker.com/sessionId").str2(), what)
			assert.Equal(t, "rl", labels.at("app.kubernetes.io/name").str2(), what)

			if o.kind() == "PrometheusRule" {
				continue
			}
			for _, container := range o.at("spec", "template", "spec", "containers").list() {
				kept := []any{}
				for _, arg := range container.at("args").list() {
					if !strings.HasPrefix(arg.str2(), "/app/") {
						kept = append(kept, arg.v)
					}
				}
				container.v.(map[string]any)["args"] = kept
			}
			raw, err := json.Marshal(o)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "release-ns", "%s reads the release namespace", what)
			assert.NotContains(t, string(raw), chart, "%s keeps the chart's own name", what)
		}

		deployment := only(t, objects, "Deployment")
		assert.Equal(t, "rl", deployment.at("spec", "template", "metadata", "labels", "name").str2(),
			"%s: the pods do not carry the label the selector reads", chart)
	}
}

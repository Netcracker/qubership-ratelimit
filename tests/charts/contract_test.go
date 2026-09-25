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
// extra arguments, and parses every document it produced.
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

// The Service of the service chart: the name and the two ports the operator
// chart's filters and the operator binary address it by.
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

// The operator chart's filters address the Service by the contract's name
// and port, in the release namespace or in the baseline's.
func TestOperatorChart_filtersAddressTheServiceOfTheContract(t *testing.T) {
	authority := func(namespace string) string {
		return fmt.Sprintf("%s.%s.svc.cluster.local", contract.ServiceName, namespace)
	}
	cluster := func(namespace string) string {
		return fmt.Sprintf("outbound|%d||%s", contract.GRPCPort, authority(namespace))
	}
	check := func(t *testing.T, objects []object, namespace string) {
		t.Helper()
		var filters int
		for _, o := range objects {
			if o.kind() != "EnvoyFilter" {
				continue
			}
			filters++
			raw, err := yaml.Marshal(o)
			require.NoError(t, err)
			assert.Contains(t, string(raw), "authority: "+authority(namespace))
			assert.Contains(t, string(raw), "cluster_name: "+cluster(namespace))
		}
		assert.Equal(t, 2, filters, "one filter per enabled gateway")
	}

	t.Run("baseline", func(t *testing.T) {
		objects := render(t, operatorChart, "biz")
		check(t, objects, "biz")
		// The operator adopts its own Deployment by the name the chart gives it.
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
	})
	t.Run("satellite", func(t *testing.T) {
		objects := render(t, operatorChart, "sat", "--set", "BASELINE_ORIGIN=base", "--set", "MONITORING_ENABLED=true")
		assert.Equal(t, []string{"EnvoyFilter"}, kinds(objects), "a satellite gets the filters and nothing else")
		check(t, objects, "base")
	})
}

// The service chart renders nothing in a satellite, whatever the values say.
func TestServiceChart_rendersNothingInASatellite(t *testing.T) {
	objects := render(t, serviceChart, "sat", "--set", "BASELINE_ORIGIN=base",
		"--set", "MONITORING_ENABLED=true", "--set", "management.enabled=true")
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

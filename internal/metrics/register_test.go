package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// gatheredNames lists the family names a registry reports.
func gatheredNames(t *testing.T, registry *prometheus.Registry) []string {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.GetName())
	}
	return names
}

// gatheredBuildInfo reads the labels and the value of the one
// ratelimit_build_info series.
func gatheredBuildInfo(t *testing.T, registry *prometheus.Registry) (labels map[string]string, value float64) {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "ratelimit_build_info" {
			continue
		}
		require.Len(t, family.GetMetric(), 1, "series of ratelimit_build_info")
		labels = map[string]string{}
		for _, pair := range family.GetMetric()[0].GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}
		return labels, family.GetMetric()[0].GetGauge().GetValue()
	}
	t.Fatal("ratelimit_build_info is not on the registry")
	return nil, 0
}

// withSeriesOfBothPlanes gives every vector the registration tests name a
// series, since a vector without one is absent from a scrape whether it is
// registered or not.
func withSeriesOfBothPlanes(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { DropFleet("register.test") })
	Checks.WithLabelValues("register.test", VerdictOK).Add(0)
	ConfigWriteErrors.WithLabelValues("other").Add(0)
	PublishFleet("register.test", FleetSample{Applied: 1, Total: 1, Reason: "Progressing"})
}

// A second call is what a test that builds a process twice does; it is not
// the panic prometheus raises for a duplicate collector.
func TestRegisterService_toleratesASecondCallOnTheSameRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	RegisterService(registry, "1.2.3")

	assert.NotPanics(t, func() { RegisterService(registry, "1.2.3") })
}

// The service's scrape carries the data plane, and no series of the
// operator's.
func TestRegisterService_registersOnlyTheDataPlaneSeries(t *testing.T) {
	withSeriesOfBothPlanes(t)
	registry := prometheus.NewRegistry()

	RegisterService(registry, "1.2.3")

	names := gatheredNames(t, registry)
	for _, want := range []string{"ratelimit_checks_total", "ratelimit_snapshot_timestamp_seconds", "ratelimit_build_info"} {
		assert.Contains(t, names, want, "a series of the data plane")
	}
	for _, unwanted := range []string{"ratelimit_leader", "ratelimit_policy_replicas", "ratelimit_config_write_errors_total"} {
		assert.NotContains(t, names, unwanted, "a series of the operator")
	}
}

func TestRegisterService_labelsTheBuildInfoWithTheServiceAndItsVersion(t *testing.T) {
	registry := prometheus.NewRegistry()

	RegisterService(registry, "1.2.3")

	labels, value := gatheredBuildInfo(t, registry)
	assert.Equal(t, map[string]string{"component": ComponentService, "version": "1.2.3"}, labels)
	assert.Equal(t, 1.0, value)
}

// RegisterOperator tolerates a second call on one registry, as RegisterService
// does.
func TestRegisterOperator_toleratesASecondCallOnTheSameRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	RegisterOperator(registry, "4.5.6")

	assert.NotPanics(t, func() { RegisterOperator(registry, "4.5.6") })
}

// The operator's scrape carries the control plane, and no series of the data
// plane sits at zero there for a query to exclude.
func TestRegisterOperator_registersOnlyTheControlPlaneSeries(t *testing.T) {
	withSeriesOfBothPlanes(t)
	registry := prometheus.NewRegistry()

	RegisterOperator(registry, "4.5.6")

	names := gatheredNames(t, registry)
	for _, want := range []string{"ratelimit_leader", "ratelimit_config_write_errors_total", "ratelimit_build_info"} {
		assert.Contains(t, names, want, "a series of the control plane")
	}
	for _, unwanted := range []string{"ratelimit_checks_total", "ratelimit_snapshot_timestamp_seconds"} {
		assert.NotContains(t, names, unwanted, "a series of the data plane")
	}
}

func TestRegisterOperator_labelsTheBuildInfoWithTheOperatorAndItsVersion(t *testing.T) {
	registry := prometheus.NewRegistry()

	RegisterOperator(registry, "4.5.6")

	labels, value := gatheredBuildInfo(t, registry)
	assert.Equal(t, map[string]string{"component": ComponentOperator, "version": "4.5.6"}, labels)
	assert.Equal(t, 1.0, value)
}

// compiledSnapshots compiles one domain, gateway.public, that maps the key
// tenant and holds the rule api/total.
func compiledSnapshots(t *testing.T) map[string]*compile.Snapshot {
	t.Helper()
	snapshot, problems := compile.Compile("biz", "gateway.public", &model.Policy{
		Domain:   "gateway.public",
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org_id"}},
		Blocks: []model.Block{{Name: "api", Rules: []model.Rule{{
			Name: "total", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}}}}},
	})
	require.Empty(t, problems)
	return map[string]*compile.Snapshot{"gateway.public": snapshot}
}

// The keys of a domain are its effective keys: the built-in method, path, and
// sub, and the mapped tenant.
func TestActiveSetOf_listsTheLabelValuesTheSnapshotsCanProduce(t *testing.T) {
	active := ActiveSetOf(compiledSnapshots(t))

	assert.Equal(t, &ActiveSet{
		Domains: map[string]struct{}{"gateway.public": {}},
		Rules:   map[string]struct{}{"api/total": {}},
		Keys: map[string]map[string]struct{}{
			"gateway.public": {"method": {}, "path": {}, "sub": {}, "tenant": {}},
		},
	}, active)
}

// path and method are resolved from the request, not extracted from a token,
// and stay out.
func TestExtractionKeysOf_listsTheBuiltInSubAndTheMappedKeys(t *testing.T) {
	keys := ExtractionKeysOf(compiledSnapshots(t))

	assert.ElementsMatch(t, []string{model.KeySub, "tenant"}, keys["gateway.public"])
}

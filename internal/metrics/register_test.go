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

func TestRegisterService_putsTheDataPlaneOnTheRegistryOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	RegisterService(registry, "1.2.3")
	// A second call is what a test that builds a process twice does; it is
	// not the duplicate-collector panic.
	require.NotPanics(t, func() { RegisterService(registry, "1.2.3") })

	Checks.WithLabelValues("register.test", VerdictOK).Inc()
	names := gathered(t, registry)
	for _, want := range []string{"ratelimit_checks_total", "ratelimit_snapshot_timestamp_seconds", "ratelimit_build_info"} {
		assert.True(t, names[want], "%s is not on the registry", want)
	}
	for _, unwanted := range []string{"ratelimit_leader", "ratelimit_policy_replicas", "ratelimit_config_write_errors_total"} {
		assert.False(t, names[unwanted], "%s is the operator's and must not be on the service's scrape", unwanted)
	}
	assert.Equal(t, map[string]string{"component": ComponentService, "version": "1.2.3"}, buildInfoLabels(t, registry))

	// A registry of its own is a registry of its own: the collectors are
	// shared values, the registrations are not.
	other := prometheus.NewRegistry()
	families, err := other.Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
}

func TestRegisterOperator_putsTheControlPlaneOnTheRegistryOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	RegisterOperator(registry, "4.5.6")
	require.NotPanics(t, func() { RegisterOperator(registry, "4.5.6") })

	ConfigWriteErrors.WithLabelValues("other").Add(0)
	names := gathered(t, registry)
	for _, want := range []string{"ratelimit_leader", "ratelimit_config_write_errors_total", "ratelimit_build_info"} {
		assert.True(t, names[want], "%s is not on the registry", want)
	}
	for _, unwanted := range []string{"ratelimit_checks_total", "ratelimit_snapshot_timestamp_seconds"} {
		assert.False(t, names[unwanted], "%s is the service's and must not sit at zero on the operator's scrape", unwanted)
	}
	assert.Equal(t, map[string]string{"component": ComponentOperator, "version": "4.5.6"}, buildInfoLabels(t, registry))
}

// gathered lists the family names a registry reports.
func gathered(t *testing.T, registry *prometheus.Registry) map[string]bool {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	names := make(map[string]bool, len(families))
	for _, family := range families {
		names[family.GetName()] = true
	}
	return names
}

// buildInfoLabels reads the labels of the one ratelimit_build_info series.
func buildInfoLabels(t *testing.T, registry *prometheus.Registry) map[string]string {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != "ratelimit_build_info" {
			continue
		}
		require.Len(t, family.GetMetric(), 1)
		assert.Equal(t, 1.0, family.GetMetric()[0].GetGauge().GetValue())
		labels := map[string]string{}
		for _, pair := range family.GetMetric()[0].GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}
		return labels
	}
	t.Fatal("ratelimit_build_info is not on the registry")
	return nil
}

func TestActiveSetOf_listsWhatTheSnapshotsCanLabel(t *testing.T) {
	snapshot, problems := compile.Compile("biz", "gateway.public", &model.Policy{
		Domain:   "gateway.public",
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org_id"}},
		Blocks: []model.Block{{Name: "api", Rules: []model.Rule{{
			Name: "total", Rates: []model.Rate{{Requests: 1, Period: time.Minute}}}}}},
	})
	require.Empty(t, problems)
	snapshots := map[string]*compile.Snapshot{"gateway.public": snapshot}

	active := ActiveSetOf(snapshots)
	assert.Contains(t, active.Domains, "gateway.public")
	assert.Contains(t, active.Rules, RuleID("api", "total"))
	assert.Contains(t, active.Keys["gateway.public"], "tenant")
	assert.ElementsMatch(t, []string{model.KeyClient, "tenant"}, ExtractionKeysOf(snapshots)["gateway.public"])
}

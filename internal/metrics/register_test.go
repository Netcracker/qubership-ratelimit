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

func TestRegister_putsEverySeriesOnTheRegistryOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	Register(registry)
	// A second call is what a test that builds a process twice does; it is
	// not the duplicate-collector panic.
	require.NotPanics(t, func() { Register(registry) })

	Checks.WithLabelValues("register.test", VerdictOK).Inc()
	families, err := registry.Gather()
	require.NoError(t, err)
	names := make(map[string]bool, len(families))
	for _, family := range families {
		names[family.GetName()] = true
	}
	for _, want := range []string{"ratelimit_checks_total", "ratelimit_snapshot_timestamp_seconds"} {
		assert.True(t, names[want], "%s is not on the registry", want)
	}

	// A registry of its own is a registry of its own: the collectors are
	// shared values, the registrations are not.
	other := prometheus.NewRegistry()
	families, err = other.Gather()
	require.NoError(t, err)
	assert.Empty(t, families)
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
	assert.ElementsMatch(t, []string{model.KeyClient, "tenant"}, ExtractionKeysOf(snapshots))
}

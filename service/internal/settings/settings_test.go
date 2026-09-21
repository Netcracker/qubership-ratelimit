package settings

import (
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/service/internal/management"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
)

// Without redis.addresses the process counts in its own memory, which is a
// permitted configuration: management.enabled does not require Redis. The
// records have to follow the counters there. Leaving them nil starts the
// management API with a nil store, and every mutation panics into an RLS-0500
// while the reads keep working, so nothing short of a reset reveals it.
func TestCounterStore_theInProcessBackendCarriesARecordsStore(t *testing.T) {
	backend := CounterStore(t.Errorf)

	require.NotNil(t, backend.Store, "the in-process branch must still count somewhere")
	require.NotNil(t, backend.Records,
		"a nil records store panics on the first DELETE /counters")
	require.False(t, backend.Shared, "in-process counting is per replica, and says so")
	require.Nil(t, backend.Closer, "nothing was dialed, so there is nothing to close")
}

// The values a property can carry wrong, and what each one is replaced by.
func TestSettings_replaceABadValueWithTheDefaultAndSaySo(t *testing.T) {
	var warned []string
	warn := func(format string, args ...any) { warned = append(warned, format) }

	t.Setenv("METRICS_NEAR_LIMIT_RATIO", "1.5")
	t.Setenv("REDIS_DB", "two")
	t.Setenv("MANAGEMENT_ROLES_VIEWER", "ro, , auditor,")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})

	assert.Equal(t, rls.DefaultNearLimitRatio, NearLimitRatio(warn))
	assert.Equal(t, 0, redisDatabase(warn))
	assert.Len(t, warned, 2)

	assert.Equal(t, []string{"ro", "auditor"}, ManagementRoles().Viewer)
	assert.Equal(t, []string{management.RoleOperator}, ManagementRoles().Operator)
	assert.Equal(t, management.DefaultClaimNames, ManagementClaims())

	t.Setenv("METRICS_NEAR_LIMIT_RATIO", "0.5")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	assert.Equal(t, 0.5, NearLimitRatio(warn))
}

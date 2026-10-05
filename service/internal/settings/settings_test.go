package settings

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3/model/rest"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/service/internal/management"
	"github.com/netcracker/qubership-ratelimit/service/internal/redisconn"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
)

// Without a DBaaS connection the process counts in its own memory, the
// developer loop's store: management.enabled does not require Redis. The
// records have to follow the counters there. Leaving them nil starts the
// management API with a nil store, and every mutation panics into an RLS-0500
// while the reads keep working, so nothing short of a reset reveals it.
func TestCounterStore_theInProcessBackendCarriesARecordsStore(t *testing.T) {
	backend := CounterStore(nil)

	require.NotNil(t, backend.Store, "the in-process branch must still count somewhere")
	require.NotNil(t, backend.Records,
		"a nil records store panics on the first DELETE /counters")
	require.False(t, backend.Shared, "in-process counting is per replica, and says so")
	require.Nil(t, backend.Closer, "nothing was dialed, so there is nothing to close")
	require.Nil(t, backend.CheckEviction, "the in-process store never evicts")
}

// With a DBaaS connection the store is Redis at the address the Secret
// names, shared by every replica, with a client the caller closes.
func TestCounterStore_countsInTheDatabaseTheSecretNames(t *testing.T) {
	source, err := redisconn.Open(context.Background(), fixedResolver{
		"host": "ratelimit-redis.core", "port": float64(6379), "password": "p", "role": "admin",
	}, redisconn.Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)

	backend := CounterStore(source)
	t.Cleanup(func() { _ = backend.Closer.Close() })
	assert.True(t, backend.Shared)
	assert.NotNil(t, backend.Records)
	assert.Contains(t, backend.Description, "ratelimit-redis.core:6379")
	assert.NotNil(t, backend.CheckEviction)
}

// The store's eviction policy is read at startup: noeviction passes, any
// other policy and a policy that cannot be read are errors that name it.
func TestCheckEviction_namesAPolicyThatEvicts(t *testing.T) {
	require.NoError(t, CheckEviction(context.Background(), policyReader{"maxmemory-policy": "noeviction"}))

	err := CheckEviction(context.Background(), policyReader{"maxmemory-policy": "allkeys-lru"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"allkeys-lru"`)
	assert.Contains(t, err.Error(), "maxmemory-policy: noeviction")

	err = CheckEviction(context.Background(), policyReader(nil))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ERR unknown command")
}

// policyReader answers CONFIG GET with its map, or with an error when nil.
type policyReader map[string]string

func (p policyReader) ConfigGet(ctx context.Context, _ string) *goredis.MapStringStringCmd {
	if p == nil {
		return goredis.NewMapStringStringResult(nil, errors.New("ERR unknown command 'CONFIG'"))
	}
	return goredis.NewMapStringStringResult(p, nil)
}

// The values a property can carry wrong, and what each one is replaced by.
func TestSettings_replaceABadValueWithTheDefaultAndSaySo(t *testing.T) {
	var warned []string
	warn := func(format string, args ...any) { warned = append(warned, format) }

	t.Setenv("METRICS_NEAR_LIMIT_RATIO", "1.5")
	t.Setenv("MANAGEMENT_ROLES_VIEWER", "ro, , auditor,")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})

	assert.Equal(t, rls.DefaultNearLimitRatio, NearLimitRatio(warn))
	assert.Len(t, warned, 1)

	assert.Equal(t, []string{"ro", "auditor"}, ManagementRoles().Viewer)
	assert.Equal(t, []string{management.RoleOperator}, ManagementRoles().Operator)
	assert.Equal(t, management.DefaultClaimNames, ManagementClaims())

	t.Setenv("METRICS_NEAR_LIMIT_RATIO", "0.5")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	assert.Equal(t, 0.5, NearLimitRatio(warn))
}

// fixedResolver answers every lookup with one set of connection properties.
type fixedResolver map[string]any

func (f fixedResolver) GetConnection(context.Context, string, map[string]any,
	rest.BaseDbParams) (map[string]any, error) {
	return f, nil
}

// MANAGEMENT_GATEWAY_DOMAINS is a comma-separated list, read with the blanks
// around an entry and the empty entries dropped.
func TestManagementGatewayDomains_readsACommaSeparatedList(t *testing.T) {
	t.Setenv("MANAGEMENT_GATEWAY_DOMAINS", "gateway.private, gateway.internal,")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})

	assert.Equal(t, []string{"gateway.private", "gateway.internal"}, ManagementGatewayDomains())
}

func TestManagementGatewayDomains_unsetIsNoDomain(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})

	assert.Empty(t, ManagementGatewayDomains())
}

// An installation that leaves the operator list empty is read-only. The chart
// renders the empty list as an empty variable, and reading it back as the
// default "operator" would grant every mutation to a token carrying that role.
func TestManagementRoles_anEmptyListGrantsNothing(t *testing.T) {
	t.Setenv("MANAGEMENT_ROLES_VIEWER", "rl-viewer")
	t.Setenv("MANAGEMENT_ROLES_OPERATOR", "")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})

	roles := ManagementRoles()
	assert.Empty(t, roles.Operator)
	assert.Equal(t, []string{"rl-viewer"}, roles.Viewer)

	t.Setenv("MANAGEMENT_ROLES_VIEWER", "")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	roles = ManagementRoles()
	assert.Empty(t, roles.Viewer)
	assert.Empty(t, roles.Operator)
}

// An unset list is the canonical name, which is what a deployment that issues
// viewer and operator verbatim relies on.
func TestManagementRoles_unsetIsTheCanonicalName(t *testing.T) {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	roles := ManagementRoles()
	assert.Equal(t, []string{management.RoleViewer}, roles.Viewer)
	assert.Equal(t, []string{management.RoleOperator}, roles.Operator)
}

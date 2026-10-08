package settings

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3/model/rest"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/service/internal/redisconn"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
)

// readEnvironment points configloader at the environment alone, where the
// tests set the properties.
func readEnvironment() {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
}

// warnings collects the warnings a function here logs about a value it
// replaced.
type warnings []string

func (w *warnings) warn(format string, args ...any) { *w = append(*w, fmt.Sprintf(format, args...)) }

// Without a DBaaS connection the process counts in its own memory, the
// developer loop's store: management.enabled does not require Redis. The
// records have to follow the counters there. Leaving them nil starts the
// management API with a nil store, and every mutation panics into an RLS-0500
// while the reads keep working, so nothing short of a reset reveals it.
func TestCounterStore_theInProcessBackendCarriesARecordsStore(t *testing.T) {
	backend := CounterStore(nil)

	assert.NotNil(t, backend.Store, "the in-process branch must still count somewhere")
	assert.NotNil(t, backend.Records, "a nil records store panics on the first DELETE /counters")
	assert.False(t, backend.Shared, "an in-process store counts per replica")
	assert.Nil(t, backend.Closer, "nothing was dialed, so there is nothing to close")
	assert.Nil(t, backend.CheckEviction, "the in-process store never evicts")
}

// With a DBaaS connection the store is Redis at the address the Secret
// names, shared by every replica, with a client the caller closes.
func TestCounterStore_countsInTheDatabaseTheSecretNames(t *testing.T) {
	source, err := redisconn.Open(context.Background(), fixedResolver{
		"host": "ratelimit-redis.core", "port": float64(6379), "password": "p", "role": "admin",
	}, redisconn.Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)

	backend := CounterStore(source)

	require.NotNil(t, backend.Closer, "the client the caller closes")
	t.Cleanup(func() { _ = backend.Closer.Close() })
	assert.True(t, backend.Shared)
	assert.NotNil(t, backend.Records)
	assert.Contains(t, backend.Description, "ratelimit-redis.core:6379")
	assert.NotNil(t, backend.CheckEviction)
}

// policyReader returns its map for CONFIG GET, or errUnknownCommand when it is
// nil.
type policyReader map[string]string

var errUnknownCommand = errors.New("ERR unknown command 'CONFIG'")

func (p policyReader) ConfigGet(context.Context, string) *goredis.MapStringStringCmd {
	if p == nil {
		return goredis.NewMapStringStringResult(nil, errUnknownCommand)
	}
	return goredis.NewMapStringStringResult(p, nil)
}

// The store's eviction policy is read at startup: noeviction passes, and any
// other policy, or a policy that cannot be read, is an error that names it.
func TestCheckEviction_acceptsNoeviction(t *testing.T) {
	assert.NoError(t, CheckEviction(context.Background(), policyReader{"maxmemory-policy": "noeviction"}))
}

func TestCheckEviction_refusesAnEvictingPolicyByName(t *testing.T) {
	err := CheckEviction(context.Background(), policyReader{"maxmemory-policy": "allkeys-lru"})

	assert.ErrorContains(t, err, `"allkeys-lru"`)
	assert.ErrorContains(t, err, "maxmemory-policy: noeviction", "the remedy names the policy to install")
}

func TestCheckEviction_reportsAPolicyItCannotRead(t *testing.T) {
	err := CheckEviction(context.Background(), policyReader(nil))

	assert.ErrorIs(t, err, errUnknownCommand)
}

// fixedResolver returns one set of connection properties for every lookup.
type fixedResolver map[string]any

func (f fixedResolver) GetConnection(context.Context, string, map[string]any,
	rest.BaseDbParams) (map[string]any, error) {
	return f, nil
}

// A value that does not parse or lies outside the open interval (0, 1) is
// reported once and replaced by the default; the interval's own ends are
// outside it. NaN used to be returned as the ratio with no warning, because
// NaN compares false with both bounds.
func TestNearLimitRatio_replacesAValueOutsideTheIntervalWithTheDefault(t *testing.T) {
	for _, tt := range []struct{ name, raw string }{
		{"a ratio above one", "1.5"},
		{"zero", "0"},
		{"one", "1"},
		{"a negative ratio", "-0.5"},
		{"NaN", "NaN"},
		{"a word", "ninety"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var warned warnings
			t.Setenv("METRICS_NEAR_LIMIT_RATIO", tt.raw)
			readEnvironment()

			ratio := NearLimitRatio(warned.warn)

			assert.Equal(t, rls.DefaultNearLimitRatio, ratio, "NearLimitRatio with %q", tt.raw)
			assert.Len(t, warned, 1, "warnings for %q", tt.raw)
		})
	}
}

// An empty value reads as an unset one: the default, with no warning.
func TestNearLimitRatio_readsAnEmptyValueAsTheDefaultWithoutAWarning(t *testing.T) {
	var warned warnings
	t.Setenv("METRICS_NEAR_LIMIT_RATIO", "")
	readEnvironment()

	ratio := NearLimitRatio(warned.warn)

	assert.Equal(t, rls.DefaultNearLimitRatio, ratio)
	assert.Empty(t, warned)
}

// A ratio inside (0, 1) is read as it is, without a warning. This is the
// control of TestNearLimitRatio_replacesAValueOutsideTheIntervalWithTheDefault.
func TestNearLimitRatio_readsARatioInsideTheInterval(t *testing.T) {
	var warned warnings
	t.Setenv("METRICS_NEAR_LIMIT_RATIO", "0.5")
	readEnvironment()

	ratio := NearLimitRatio(warned.warn)

	assert.Equal(t, 0.5, ratio)
	assert.Empty(t, warned)
}

// MANAGEMENT_GATEWAY_DOMAINS is a comma-separated list, read with the blanks
// around an entry and the empty entries dropped.
func TestManagementGatewayDomains_readsACommaSeparatedList(t *testing.T) {
	t.Setenv("MANAGEMENT_GATEWAY_DOMAINS", "gateway.private, gateway.internal,")
	readEnvironment()

	assert.Equal(t, []string{"gateway.private", "gateway.internal"}, ManagementGatewayDomains())
}

func TestManagementGatewayDomains_unsetIsNoDomain(t *testing.T) {
	readEnvironment()

	assert.Empty(t, ManagementGatewayDomains())
}

// MANAGEMENT_CALLERS names ServiceAccounts as <name> in the release's
// namespace or <namespace>/<name> elsewhere, and each comes back as the sub
// claim of its tokens. An entry of another shape is reported and left out
// rather than granting operator to a name nobody can hold.
func TestManagementCallers_readsBothFormsAsTokenSubjects(t *testing.T) {
	var warned []string
	warn := func(format string, args ...any) { warned = append(warned, fmt.Sprintf(format, args...)) }
	t.Setenv("MANAGEMENT_CALLERS", "ui-backend, platform/ops-backend,, Bad/Name, a/b/c")
	readEnvironment()

	assert.Equal(t, []string{
		"system:serviceaccount:biz:ui-backend",
		"system:serviceaccount:platform:ops-backend",
	}, ManagementCallers("biz", warn))
	assert.Len(t, warned, 2, "the entries of another shape are not both reported")
}

func TestManagementCallers_unsetIsNoCaller(t *testing.T) {
	readEnvironment()

	assert.Empty(t, ManagementCallers("biz", func(string, ...any) {}))
}

// The audience defaults to the platform's machine-to-machine convention.
func TestManagementAudience_unsetIsThePlatformConvention(t *testing.T) {
	readEnvironment()

	assert.Equal(t, "netcracker", ManagementAudience())
}

func TestManagementAudience_readsTheConfiguredAudience(t *testing.T) {
	t.Setenv("MANAGEMENT_M2M_AUDIENCE", "ratelimit-e2e")
	readEnvironment()

	assert.Equal(t, "ratelimit-e2e", ManagementAudience())
}

// RESPONSE_HEADERS_IETF turns the ratelimit-policy and ratelimit fields off
// only when it reads as false: empty is on, and a value that is not a boolean
// is reported and read as on, so a typo does not change what clients receive.
func TestIETFHeaders_isOnUnlessSetToFalse(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		want     bool
		warnings int
	}{
		{"an empty value is on", "", true, 0},
		{"false is off", "false", false, 0},
		{"true is on", "true", true, 0},
		{"a value that is not a boolean reads as on with a warning", "off", true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var warned warnings
			t.Setenv("RESPONSE_HEADERS_IETF", c.value)
			readEnvironment()

			assert.Equal(t, c.want, IETFHeaders(warned.warn), "RESPONSE_HEADERS_IETF=%q", c.value)
			assert.Len(t, warned, c.warnings, "warnings about RESPONSE_HEADERS_IETF=%q", c.value)
		})
	}
}

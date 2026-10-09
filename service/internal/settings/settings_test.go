package settings

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

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
// claim of its tokens. An entry of another shape, such as a namespace longer
// than the 63 bytes of a DNS label, is reported and left out rather than
// granting operator to a name nobody can hold.
func TestManagementCallers_readsBothFormsAsTokenSubjects(t *testing.T) {
	var warned warnings
	callers := "ui-backend, platform/ops-backend,, Bad/Name, a/b/c, " + strings.Repeat("n", 64) + "/ops-backend"
	t.Setenv("MANAGEMENT_CALLERS", callers)
	readEnvironment()

	assert.Equal(t, []string{
		"system:serviceaccount:biz:ui-backend",
		"system:serviceaccount:platform:ops-backend",
	}, ManagementCallers("biz", warned.warn), "ManagementCallers with MANAGEMENT_CALLERS=%q", callers)
	assert.Len(t, warned, 3, "warnings for MANAGEMENT_CALLERS=%q", callers)
}

func TestManagementCallers_unsetIsNoCaller(t *testing.T) {
	var warned warnings
	readEnvironment()

	assert.Empty(t, ManagementCallers("biz", warned.warn))
	assert.Empty(t, warned, "warnings with MANAGEMENT_CALLERS unset")
}

// The audience defaults to the platform's machine-to-machine convention.
func TestManagementAudience_unsetIsThePlatformConvention(t *testing.T) {
	var warned warnings
	readEnvironment()

	assert.Equal(t, "netcracker", ManagementAudience(warned.warn))
	assert.Empty(t, warned)
}

func TestManagementAudience_readsTheConfiguredAudience(t *testing.T) {
	var warned warnings
	t.Setenv("MANAGEMENT_M2M_AUDIENCE", " ratelimit-e2e ")
	readEnvironment()

	assert.Equal(t, "ratelimit-e2e", ManagementAudience(warned.warn), "the audience with its spaces trimmed")
	assert.Empty(t, warned)
}

// An empty audience is unset, as it is for the other properties here, and
// reads as the default without a warning.
func TestManagementAudience_readsAnEmptyValueAsTheDefault(t *testing.T) {
	var warned warnings
	t.Setenv("MANAGEMENT_M2M_AUDIENCE", "")
	readEnvironment()

	assert.Equal(t, "netcracker", ManagementAudience(warned.warn))
	assert.Empty(t, warned)
}

// An audience of spaces alone matches no token. It is reported and replaced by
// the default; it used to be verified as given, and every caller got 401.
func TestManagementAudience_replacesAnAudienceOfSpacesByTheDefault(t *testing.T) {
	var warned warnings
	t.Setenv("MANAGEMENT_M2M_AUDIENCE", "   ")
	readEnvironment()

	assert.Equal(t, "netcracker", ManagementAudience(warned.warn))
	assert.Len(t, warned, 1, "warnings about an audience of spaces")
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

// RESPONSE_HEADERS_IETF is read by strconv.ParseBool: each of the spellings
// it accepts turns the fields off or on without a warning. The spellings
// false and true are in TestIETFHeaders_isOnUnlessSetToFalse, and the rows
// here are the other ten.
func TestIETFHeaders_readsTheOtherSpellingsOfABoolean(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"0 is off", "0", false},
		{"f is off", "f", false},
		{"F is off", "F", false},
		{"FALSE is off", "FALSE", false},
		{"False is off", "False", false},
		{"1 is on", "1", true},
		{"t is on", "t", true},
		{"T is on", "T", true},
		{"TRUE is on", "TRUE", true},
		{"True is on", "True", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var warned warnings
			t.Setenv("RESPONSE_HEADERS_IETF", c.value)
			readEnvironment()

			assert.Equal(t, c.want, IETFHeaders(warned.warn), "RESPONSE_HEADERS_IETF=%q", c.value)
			assert.Empty(t, warned, "warnings about RESPONSE_HEADERS_IETF=%q", c.value)
		})
	}
}

// A namespace is a DNS label of at most 63 bytes: an entry in a namespace of
// 63 bytes names a caller, and one in a namespace of 64 is reported and left
// out.
func TestManagementCallers_boundsTheNamespaceAtTheLengthOfADNSLabel(t *testing.T) {
	var warned warnings
	longest, over := strings.Repeat("n", 63), strings.Repeat("n", 64)
	callers := longest + "/ops-backend, " + over + "/ops-backend"
	t.Setenv("MANAGEMENT_CALLERS", callers)
	readEnvironment()

	assert.Equal(t, []string{"system:serviceaccount:" + longest + ":ops-backend"},
		ManagementCallers("biz", warned.warn), "ManagementCallers with a 63-byte and a 64-byte namespace")
	assert.Len(t, warned, 1, "warnings for a 63-byte and a 64-byte namespace")
}

// A ServiceAccount name is a DNS subdomain of at most 253 bytes: an entry
// naming 253 bytes names a caller, and one naming 254 is reported and left
// out.
func TestManagementCallers_boundsTheNameAtTheLengthOfADNSSubdomain(t *testing.T) {
	var warned warnings
	longest, over := strings.Repeat("s", 253), strings.Repeat("s", 254)
	t.Setenv("MANAGEMENT_CALLERS", "platform/"+longest+", platform/"+over)
	readEnvironment()

	assert.Equal(t, []string{"system:serviceaccount:platform:" + longest},
		ManagementCallers("biz", warned.warn), "ManagementCallers with a 253-byte and a 254-byte name")
	assert.Len(t, warned, 1, "warnings for a 253-byte and a 254-byte name")
}

// A ServiceAccount name is a DNS subdomain, so it may carry dots; an
// underscore is in neither a label nor a subdomain, so the same name with one
// is reported and left out.
func TestManagementCallers_acceptsADottedName(t *testing.T) {
	var warned warnings
	callers := "platform/ops.backend, platform/ops_backend"
	t.Setenv("MANAGEMENT_CALLERS", callers)
	readEnvironment()

	assert.Equal(t, []string{"system:serviceaccount:platform:ops.backend"},
		ManagementCallers("biz", warned.warn), "ManagementCallers with MANAGEMENT_CALLERS=%q", callers)
	assert.Len(t, warned, 1, "warnings for MANAGEMENT_CALLERS=%q", callers)
}

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// A store that refuses the connection fails a decision within the check's
// deadline, with the dial error. The library defaults used to retry the dial
// and the command until the deadline passed, and the failure was counted as a
// timeout.
func TestDecisionOptions_failAtOnceOnARefusedConnection(t *testing.T) {
	client := goredis.NewUniversalClient(DecisionOptions(closedAddr(t), nil))
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Ping(ctx).Err()

	require.Error(t, err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	var opErr *net.OpError
	assert.ErrorAs(t, err, &opErr, "the dial error")
	assert.Less(t, time.Since(start), 50*time.Millisecond)
}

// A decision without a deadline of its own is bounded by the client.
func TestDecisionOptions_boundADecisionWithoutADeadline(t *testing.T) {
	client := goredis.NewUniversalClient(DecisionOptions(silentServer(t), nil))
	t.Cleanup(func() { _ = client.Close() })

	start := time.Now()
	err := client.Ping(context.Background()).Err()

	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*decisionTimeout)
}

// A decision ends at the check's own deadline, well inside the client's
// timeouts: the gateway gives up at the filter timeout, and a check it no
// longer waits for must not hold the store. Without ContextTimeoutEnabled the
// call ran to the 250 ms read timeout.
func TestDecisionOptions_endADecisionAtTheChecksDeadline(t *testing.T) {
	client := goredis.NewUniversalClient(DecisionOptions(silentServer(t), nil))
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Ping(ctx).Err()

	require.Error(t, err)
	assert.Less(t, time.Since(start), 150*time.Millisecond)
}

// A management call ends at its request's deadline, inside the client's 3 s
// timeouts.
func TestManagementOptions_endACallAtItsDeadline(t *testing.T) {
	client := goredis.NewUniversalClient(ManagementOptions(silentServer(t), nil))
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := client.Ping(ctx).Err()

	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}

// silentServer is the address of a server that accepts connections and never
// answers; closing its listener when the test ends stops it, and the
// connections it accepted close with the test.
func silentServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 16)
	t.Cleanup(func() {
		for {
			select {
			case conn := <-accepted:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- conn:
			default:
				_ = conn.Close()
			}
		}
	}()
	return listener.Addr().String()
}

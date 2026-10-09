// Package settings reads the properties of the data plane: where the
// counters live, the near-limit margin of the metrics, and the callers and
// the token audience the management API authenticates against. The counter store comes from
// the connection the DBaaS Secret carries; the rest read configloader and
// return a value the wiring uses, where a bad value is logged and replaced by
// the default, never fatal, because none of these is worth a pod that does
// not start.
package settings

import (
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security/token"
	goredis "github.com/redis/go-redis/v9"

	enginestore "github.com/netcracker/qubership-ratelimit/engine/store"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
	"github.com/netcracker/qubership-ratelimit/service/internal/redisconn"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
)

// Warn is what a function here says about a value it replaced. The platform
// logger's Errorf has this shape.
type Warn func(format string, args ...any)

// CounterBackend is the chosen counter store and what the rest of the process
// needs to know about it: the clients whose lifecycle the caller owns, a
// description for the startup line.
type CounterBackend struct {
	// Store decides the traffic's checks.
	Store enginestore.Store

	// Management reads and resets the same counters for the management API,
	// and Records keeps that API's commands. Over Redis both go through a
	// client of their own, which waits and retries longer than the decision
	// path may.
	Management enginestore.Store
	Records    records.Store

	Closer      io.Closer
	Description string

	// CheckEviction reads whether the store may evict keys; nil when the
	// store cannot.
	CheckEviction func(ctx context.Context) error
}

// RequiredEvictionPolicy is the maxmemory-policy the counter store must run
// with. Counters and management records are correctness state: an evicted
// record lets a retry repeat a destructive sweep, so memory pressure has to
// surface as a failed write rather than as a key that quietly disappears.
const RequiredEvictionPolicy = "noeviction"

// configReader is the one command CheckEviction sends.
type configReader interface {
	ConfigGet(ctx context.Context, parameter string) *goredis.MapStringStringCmd
}

// CheckEviction returns an error that names the store's maxmemory-policy
// when it is not RequiredEvictionPolicy, or when it cannot be read. The
// DBaaS Redis adapter sets the policy of every database it creates from its
// own installation, and nothing in the service chart can change it, so the
// service says so in its log rather than refusing to start.
func CheckEviction(ctx context.Context, client configReader) error {
	values, err := client.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		return fmt.Errorf("read the counter store's maxmemory-policy, which must be %s: %w",
			RequiredEvictionPolicy, err)
	}
	policy := values["maxmemory-policy"]
	if policy != RequiredEvictionPolicy {
		return fmt.Errorf("the counter store runs with maxmemory-policy %q, not %s: under memory pressure "+
			"it drops counters and management records without an error; install the DBaaS Redis adapter "+
			"with redis.conf maxmemory-policy: %s and recreate the database",
			policy, RequiredEvictionPolicy, RequiredEvictionPolicy)
	}
	return nil
}

// CounterStore builds the counter store over the Redis that source resolves,
// and returns the clients whose lifecycle the caller owns; the store never
// closes them.
//
// Redis is what makes a limit a limit of the domain rather than of each
// replica: with N replicas counting in their own memory, a limit of 100
// admits 100*N, so the service counts in Redis alone and source is required.
// In a pod the database is the one DBaaS provisioned for the release,
// resolved through the platform's DBaaS client from the mounted Secret of its
// DatabaseSecretClaim.
//
// Over Redis the decisions and the management API have a client each,
// configured by [DecisionOptions] and [ManagementOptions]. The clients are
// UniversalClients because that is what the engine takes; the DBaaS Redis
// adapter provisions a standalone server, one address. The password is asked
// of the source on every new connection, so a changed password the source
// picks up reaches the pool without a restart.
func CounterStore(source *redisconn.Source) CounterBackend {
	addr := source.Connection().Addr()
	decisions := goredis.NewUniversalClient(DecisionOptions(addr, source.Credentials))
	management := goredis.NewUniversalClient(ManagementOptions(addr, source.Credentials))
	return CounterBackend{
		Store:       redisstore.New(decisions),
		Management:  redisstore.New(management),
		Records:     records.NewRedis(management),
		Closer:      closers{decisions, management},
		Description: "redis at " + addr,
		CheckEviction: func(ctx context.Context) error {
			return CheckEviction(ctx, management)
		},
	}
}

// decisionTimeout bounds each step of a decision that arrives without a
// deadline of its own: the dial, the wait for a pooled connection, the write,
// and the read. A check from a gateway carries the filter's deadline, which
// the client honors before this bound.
const decisionTimeout = 250 * time.Millisecond

// DecisionOptions configures the client that decides the traffic's checks.
//
// A decision is never retried and its dial is attempted once: the gateway
// waits on the check for the filter's timeout, tens of milliseconds, and a
// replayed script would charge the same request twice. A store that refuses
// the connection fails the check at once, with the dial error, rather than
// after the deadline as a timeout. A pooled connection that the store closed,
// on a restart for example, fails one check the same way; the gateway's
// failure mode decides that check.
func DecisionOptions(addr string, credentials func() (string, string)) *goredis.UniversalOptions {
	return &goredis.UniversalOptions{
		Addrs:                 []string{addr},
		CredentialsProvider:   credentials,
		ContextTimeoutEnabled: true,
		DialTimeout:           decisionTimeout,
		DialerRetries:         1,
		PoolTimeout:           decisionTimeout,
		ReadTimeout:           decisionTimeout,
		WriteTimeout:          decisionTimeout,
		MaxRetries:            -1,
	}
}

// managementTimeout bounds each step of a management API call to the store:
// the dial, the wait for a pooled connection, the write, and the read.
const managementTimeout = 3 * time.Second

// ManagementOptions configures the client of the management API and its
// command records. It keeps the client's retries: a replayed acceptance finds
// the record the same call wrote, and the API reads that as its own.
func ManagementOptions(addr string, credentials func() (string, string)) *goredis.UniversalOptions {
	return &goredis.UniversalOptions{
		Addrs:                 []string{addr},
		CredentialsProvider:   credentials,
		ContextTimeoutEnabled: true,
		DialTimeout:           managementTimeout,
		PoolTimeout:           managementTimeout,
		ReadTimeout:           managementTimeout,
		WriteTimeout:          managementTimeout,
	}
}

// closers closes every client it holds and returns the first error.
type closers []io.Closer

// Close implements [io.Closer].
func (c closers) Close() error {
	var first error
	for _, closer := range c {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// NearLimitRatio reads the near-limit margin for the metrics. Unset or empty,
// it is [rls.DefaultNearLimitRatio]; any other value that does not parse or
// lies outside (0, 1), NaN included, is reported through warn and replaced by
// that default.
// The property key spells every hump as its own segment because the
// configloader turns each underscore of METRICS_NEAR_LIMIT_RATIO into a dot; a
// camelCase key would never see the variable.
func NearLimitRatio(warn Warn) float64 {
	raw := configloader.GetOrDefaultString("metrics.near.limit.ratio", "")
	if raw == "" {
		return rls.DefaultNearLimitRatio
	}
	ratio, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(ratio) || ratio <= 0 || ratio >= 1 {
		warn("METRICS_NEAR_LIMIT_RATIO=%q is not a ratio in (0, 1), using %v",
			raw, rls.DefaultNearLimitRatio)
		return rls.DefaultNearLimitRatio
	}
	return ratio
}

// IETFHeaders reads whether responses carry the ratelimit-policy and
// ratelimit fields beside x-ratelimit-*, from RESPONSE_HEADERS_IETF. Unset is
// on; a value strconv.ParseBool cannot read is reported and read as on, the
// default, so a typo does not change what clients receive.
func IETFHeaders(warn Warn) bool {
	raw := configloader.GetOrDefaultString("response.headers.ietf", "")
	if raw == "" {
		return true
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		warn("RESPONSE_HEADERS_IETF=%q is not a boolean, using true", raw)
		return true
	}
	return enabled
}

// DefaultManagementAudience is the audience a caller's token is issued for
// when MANAGEMENT_M2M_AUDIENCE is unset: the platform's machine-to-machine
// convention.
const DefaultManagementAudience = "netcracker"

// ManagementAudience reads the audience the management API verifies a token
// against, from MANAGEMENT_M2M_AUDIENCE, with the surrounding spaces trimmed.
// Unset or empty, it is DefaultManagementAudience. A value of spaces alone
// would match no token and refuse every caller, so it is reported through
// warn and replaced by DefaultManagementAudience.
func ManagementAudience(warn Warn) string {
	raw := configloader.GetOrDefaultString("management.m2m.audience", DefaultManagementAudience)
	audience := strings.TrimSpace(raw)
	if audience == "" {
		warn("MANAGEMENT_M2M_AUDIENCE %q holds spaces alone, which match no token; using %s",
			raw, DefaultManagementAudience)
		return DefaultManagementAudience
	}
	return audience
}

// ManagementCallers reads the ServiceAccounts that may call the management API
// from MANAGEMENT_CALLERS, a comma-separated list: <name> for a ServiceAccount
// in namespace, <namespace>/<name> for one in another namespace. It returns
// each as the sub claim of the ServiceAccount's tokens,
// system:serviceaccount:<namespace>:<name>. An entry of another shape is
// reported through warn and left out; unset or empty is no caller.
func ManagementCallers(namespace string, warn Warn) []string {
	var out []string
	for _, entry := range csv(configloader.GetOrDefaultString("management.callers", "")) {
		ns, name, qualified := strings.Cut(entry, "/")
		if !qualified {
			ns, name = namespace, entry
		}
		if !namespaceName.MatchString(ns) || !serviceAccountName.MatchString(name) {
			warn("MANAGEMENT_CALLERS entry %q is not <name> or <namespace>/<name> of a ServiceAccount, leaving it out",
				entry)
			continue
		}
		out = append(out, token.GetKubernetesSubject(ns, name))
	}
	return out
}

// namespaceName and serviceAccountName are the Kubernetes rules for the two
// halves of a callers entry: a namespace is a DNS label, a ServiceAccount
// name a DNS subdomain.
var (
	namespaceName      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	serviceAccountName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
)

// ManagementGatewayDomains lists the rate limit domains of the gateways that
// route to the management API, a comma-separated property. The chart sets it
// from management.gatewayDomains; unset or empty is no domain.
func ManagementGatewayDomains() []string {
	return csv(configloader.GetOrDefaultString("management.gateway.domains", ""))
}

// csv splits a comma-separated property, dropping the empty entries a trailing
// comma or a blank value leaves behind.
func csv(value string) []string {
	var out []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

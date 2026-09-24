// Package settings reads the properties of the data plane: where the
// counters live, the near-limit margin of the metrics, and the claims and
// roles the management API authorizes against. The counter store comes from
// the connection the DBaaS Secret carries; the rest read configloader and
// return a value the wiring uses, where a bad value is logged and replaced by
// the default, never fatal, because none of these is worth a pod that does
// not start.
package settings

import (
	"io"
	"strconv"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	goredis "github.com/redis/go-redis/v9"

	enginestore "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	redisstore "github.com/netcracker/qubership-ratelimit/engine/store/redis"
	"github.com/netcracker/qubership-ratelimit/service/internal/management"
	"github.com/netcracker/qubership-ratelimit/service/internal/records"
	"github.com/netcracker/qubership-ratelimit/service/internal/redisconn"
	"github.com/netcracker/qubership-ratelimit/service/internal/rls"
)

// Warn is what a function here says about a value it replaced. The platform
// logger's Errorf has this shape.
type Warn func(format string, args ...any)

// CounterBackend is the chosen counter store and what the rest of the process
// needs to know about it: the client whose lifecycle the caller owns, a
// description for the startup line.
type CounterBackend struct {
	Store       enginestore.Store
	Records     records.Store
	Closer      io.Closer
	Description string

	// Shared marks a store every replica counts in. Without one a limit of N
	// admits N per replica, and the management API's records are per replica
	// too.
	Shared bool
}

// CounterStore picks where the counters live, and returns the client whose
// lifecycle the caller owns; the store never closes it.
//
// Redis is what makes a limit a limit of the domain rather than of each
// replica: with N replicas counting in their own memory, a limit of 100
// admits 100*N. In a pod the database is the one DBaaS provisioned for the
// release, resolved through the platform's DBaaS client from the mounted
// Secret of its DatabaseSecretClaim; the chart always sets it up, so a
// replica never falls back to counting on its own. A nil source is the
// in-process store, correct at one replica and for tests and the local
// developer loop, and nothing a chart renders.
//
// The client is a UniversalClient because that is what the engine takes; the
// DBaaS Redis adapter provisions a standalone server, one address. The
// password is asked of the source on every new connection, so a rotation the
// source picks up reaches the pool without a restart.
func CounterStore(source *redisconn.Source) CounterBackend {
	if source == nil {
		// The records live where the counters do. Leaving them nil would start
		// the management API with a nil store, and every mutation would panic
		// into an RLS-0500 while the reads kept working. In-process counting is
		// correct at one replica, and so are in-process records.
		counters := memory.New()
		return CounterBackend{
			Store:       counters,
			Records:     records.NewMemory(counters),
			Description: "in-process, counted per replica",
		}
	}

	addr := source.Connection().Addr()
	shared := goredis.NewUniversalClient(&goredis.UniversalOptions{
		Addrs:               []string{addr},
		CredentialsProvider: source.Credentials,
	})
	return CounterBackend{
		Store:       redisstore.New(shared),
		Records:     records.NewRedis(shared),
		Closer:      shared,
		Description: "redis at " + addr + ", provisioned by DBaaS",
		Shared:      true,
	}
}

// NearLimitRatio reads the near-limit margin for the metrics. The property
// key spells every hump as its own segment because the configloader turns
// each underscore of METRICS_NEAR_LIMIT_RATIO into a dot; a camelCase key
// would never see the variable.
func NearLimitRatio(warn Warn) float64 {
	raw := configloader.GetOrDefaultString("metrics.near.limit.ratio", "")
	if raw == "" {
		return rls.DefaultNearLimitRatio
	}
	ratio, err := strconv.ParseFloat(raw, 64)
	if err != nil || ratio <= 0 || ratio >= 1 {
		warn("METRICS_NEAR_LIMIT_RATIO=%q is not a ratio in (0, 1), using %v",
			raw, rls.DefaultNearLimitRatio)
		return rls.DefaultNearLimitRatio
	}
	return ratio
}

// ManagementClaims names the claims the subject and its roles are read from.
// Both accept a dotted path, because an IdP often nests the roles: Keycloak
// issues them under realm_access.roles.
func ManagementClaims() management.ClaimNames {
	return management.ClaimNames{
		Subject: configloader.GetOrDefaultString("management.claims.subject",
			management.DefaultClaimNames.Subject),
		Roles: configloader.GetOrDefaultString("management.claims.roles",
			management.DefaultClaimNames.Roles),
	}
}

// ManagementRoles maps the role names the IdP issues onto the two this API
// authorizes against. Both properties are comma-separated lists, and both
// default to the canonical name, which is what a deployment issuing "viewer"
// and "operator" already has.
func ManagementRoles() management.RoleMapping {
	return management.RoleMapping{
		Viewer:   csv(configloader.GetOrDefaultString("management.roles.viewer", management.RoleViewer)),
		Operator: csv(configloader.GetOrDefaultString("management.roles.operator", management.RoleOperator)),
	}
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

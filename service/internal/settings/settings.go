// Package settings reads the properties of the data plane: where the
// counters live, the near-limit margin of the metrics, and the claims and
// roles the management API authorizes against. Each function reads
// configloader and returns a value the wiring uses; a bad value is logged
// and replaced by the default, never fatal, because none of these is worth a
// pod that does not start.
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
// admits 100*N. The in-process store is correct at one replica and for tests,
// and is what an empty address list selects.
//
// The topology is the caller's business, which is why the engine takes a
// UniversalClient: one address is a standalone server, several are a cluster,
// and a master name selects Sentinel. The domain hash tag in the counter keys
// keeps each decision on one Cluster slot, so the script is valid on all
// three.
func CounterStore(warn Warn) CounterBackend {
	addresses := configloader.GetOrDefaultString("redis.addresses", "")
	if addresses == "" {
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

	shared := goredis.NewUniversalClient(&goredis.UniversalOptions{
		Addrs:      strings.Split(addresses, ","),
		Username:   configloader.GetOrDefaultString("redis.username", ""),
		Password:   configloader.GetOrDefaultString("redis.password", ""),
		DB:         redisDatabase(warn),
		MasterName: configloader.GetOrDefaultString("redis.masterName", ""),
	})
	return CounterBackend{
		Store:       redisstore.New(shared),
		Records:     records.NewRedis(shared),
		Closer:      shared,
		Description: "redis at " + addresses,
		Shared:      true,
	}
}

// redisDatabase reads the database index.
func redisDatabase(warn Warn) int {
	raw := configloader.GetOrDefaultString("redis.db", "0")
	database, err := strconv.Atoi(raw)
	if err != nil {
		warn("REDIS_DB=%q is not a number, using database 0", raw)
		return 0
	}
	return database
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

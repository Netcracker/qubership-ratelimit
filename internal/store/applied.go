package store

import (
	"encoding/json"
	"maps"
	"net/http"
	"sync/atomic"
	"time"
)

// AppliedPath is where a replica publishes what it enforces. It sits under the
// /debug/ prefix of the metrics port: read-only diagnostics inside the cluster,
// with no mutations, no authentication, and no compatibility promise. It is not
// part of any management API.
const AppliedPath = "/debug/applied"

// Applied is one replica's answer for one domain: the generation it enforces,
// and the object that generation came from.
//
// The UID travels with the generation because a generation number alone is
// ambiguous across a delete and recreate: a fresh object starts at generation 1
// too, and a leader comparing numbers would call a replica up to date when it
// is enforcing rules from an object that no longer exists.
type Applied struct {
	Generation int64     `json:"generation"`
	UID        string    `json:"uid"`
	AppliedAt  time.Time `json:"appliedAt"`
}

// applied is what this replica currently enforces, keyed by domain. It is
// published by the updater after each rebuild and read by the leader's probe.
type appliedState struct {
	current atomic.Pointer[map[string]Applied]
}

// publish records what this replica enforces. The map is cloned, so a later
// rebuild cannot mutate a map a probe is already reading.
func (a *appliedState) publish(domains map[string]Applied) {
	cloned := maps.Clone(domains)
	if cloned == nil {
		cloned = map[string]Applied{}
	}
	a.current.Store(&cloned)
}

// snapshot returns what this replica enforces, read-only.
func (a *appliedState) snapshot() map[string]Applied {
	if current := a.current.Load(); current != nil {
		return *current
	}
	return map[string]Applied{}
}

// Applied reports what this replica enforces, by domain. It is empty until the
// first rebuild, which is the honest answer for a replica that is not ready
// either.
func (u *Updater) Applied() map[string]Applied { return u.applied.snapshot() }

// AppliedHandler serves the enforced generations of one replica as JSON. The
// leader polls every ready endpoint of the Service through it and writes the
// result into status.replicas, which is what makes Ready a statement about the
// fleet rather than about the leader alone.
func AppliedHandler(u *Updater) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(w).Encode(u.Applied()); err != nil {
			// The status is already written by then, so there is nothing to
			// report to the caller; the leader treats a truncated body as an
			// unreachable replica.
			u.Log.V(1).Info("failed to write the applied generations", "error", err)
		}
	})
}

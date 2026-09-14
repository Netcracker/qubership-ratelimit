package management

import (
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
)

// StatusView is one replica's serving state.
//
// The custom resource's status shows the consensus. Replicas can diverge,
// briefly during a rollout and durably when their last-good histories differ,
// and this is the endpoint that makes the divergence visible. Comparing it
// across pods is the intended use, which is why it names the replica first.
type StatusView struct {
	Replica string `json:"replica"`

	// SnapshotSwappedAt is when the serving rule set last changed here. Absent
	// until the first snapshot lands.
	SnapshotSwappedAt *time.Time `json:"snapshotSwappedAt,omitempty"`

	// RuleSetVersions is what GET /rules reports for each domain. Compare them
	// across replicas to see rollout skew.
	RuleSetVersions map[string]string `json:"ruleSetVersions,omitempty"`

	CounterStore CounterStoreView `json:"counterStore"`
}

// CounterStoreView says where the counters live.
type CounterStoreView struct {
	// Backend is the description the startup line prints, so a support
	// conversation about "which store is this pod using" ends in one call.
	Backend string `json:"backend"`
}

// handleStatus reports what this replica is serving right now.
func (a *API) handleStatus(c *fiber.Ctx) error {
	ruleSet := a.Rules.Load()

	view := StatusView{
		Replica:      a.replica(),
		CounterStore: CounterStoreView{Backend: a.CounterBackend},
	}
	if swapped := a.Rules.SwappedAt(); !swapped.IsZero() {
		view.SnapshotSwappedAt = &swapped
	}
	if domains := ruleSet.Domains(); len(domains) > 0 {
		view.RuleSetVersions = make(map[string]string, len(domains))
		for _, domain := range domains {
			view.RuleSetVersions[domain] = ruleSet.Version(domain)
		}
	}
	return writeJSON(c, view)
}

// replica names this pod. The downward API supplies it in a deployment; the
// hostname is the same value there and a usable one anywhere else.
func (a *API) replica() string {
	if a.Replica != "" {
		return a.Replica
	}
	if name := os.Getenv("POD_NAME"); name != "" {
		return name
	}
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

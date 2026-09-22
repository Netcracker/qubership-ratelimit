// Package debug serves the read-only diagnostics of one replica on its
// metrics port: what it enforces, rendered in full. It sits next to the
// applied report the operator reads and shares its terms: inside the
// cluster, no authentication, no compatibility promise. Where the management
// API answers "what does the fleet enforce" through the Service and lifts
// limits, this answers "what does this pod enforce" and changes nothing.
//
// It renders the store's snapshot the way the management API renders it,
// through ruleview, so the two never disagree on a rule; what it adds is the
// generation the domain was applied from and the identity keys with the
// claim paths behind them, which is the half of a "why is nobody limited"
// question the management API does not carry.
//
// Every document is built from one load of the rule set: the rules, the
// version, the generation and UID they were applied from, and the swap time
// all ride on the set, so a request that lands inside an apply describes one
// configuration whole. The refusal is the one fact read beside it, since a
// refused reading leaves the set as it is.
package debug

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

// Summary is the body of a GET on contract.SnapshotPath: one row per domain
// this replica enforces, with the facts the domain gauges carry.
type Summary struct {
	// Replica is the pod, so that a report saved from a port-forward says
	// where it came from.
	Replica string `json:"replica,omitempty"`

	// SwappedAt is when this replica last swapped its rule set; the
	// management API reports the same value per replica.
	SwappedAt time.Time `json:"swappedAt"`

	// Refusal is the applied report's: set while the replica keeps its
	// snapshot because the last manifest could not be read.
	Refusal *applied.Refusal `json:"refusal,omitempty"`

	Domains []DomainSummary `json:"domains"`
}

// DomainSummary is one row of the summary.
type DomainSummary struct {
	Domain string `json:"domain"`

	// Generation and UID are the policy object this domain was applied
	// from, as the applied report has them; AppliedAt is when.
	Generation int64     `json:"generation"`
	UID        string    `json:"uid,omitempty"`
	AppliedAt  time.Time `json:"appliedAt"`

	// RuleSetVersion is the enforced-set identity the management API
	// reports, so a row here and a row there compare by it.
	RuleSetVersion string `json:"ruleSetVersion"`

	Blocks          int `json:"blocks"`
	Rules           int `json:"rules"`
	DecisionBuckets int `json:"decisionBuckets"`

	EffectiveKeys  []string `json:"effectiveKeys"`
	ListValuedKeys []string `json:"listValuedKeys,omitempty"`
}

// DomainSnapshot is the body of a GET on contract.SnapshotPath/{domain}: the
// compiled domain in full. Groups are resolved into the value sets of the
// rules that name them, so a rule's client list is what the engine tests,
// however long it is.
type DomainSnapshot struct {
	Domain string `json:"domain"`

	Generation int64     `json:"generation"`
	UID        string    `json:"uid,omitempty"`
	AppliedAt  time.Time `json:"appliedAt"`

	RuleSetVersion  string `json:"ruleSetVersion"`
	DecisionBuckets int    `json:"decisionBuckets"`

	EffectiveKeys  []string `json:"effectiveKeys"`
	ListValuedKeys []string `json:"listValuedKeys,omitempty"`

	// Keys are the identity extractions in the order the engine runs them:
	// the built-in client first unless a mapping overrides it, then the
	// mapped keys as authored.
	Keys []KeyView `json:"keys"`

	Blocks []ruleview.BlockView `json:"blocks"`
}

// KeyView is one identity extraction: where in the token the key's value
// comes from, and what is done to it on the way.
type KeyView struct {
	Key string `json:"key"`

	// Claim is the path into the token's claims, dotted; Fallbacks are the
	// paths tried when it is absent, in order.
	Claim     string   `json:"claim"`
	Fallbacks []string `json:"fallbacks,omitempty"`

	Type          string `json:"type"`
	Normalization string `json:"normalization,omitempty"`
}

// Reporter is the applied report's source: the applier, for the refusal it
// holds beside the rule set.
type Reporter interface {
	Report() applied.Report
}

// Handler answers GET on contract.SnapshotPath and on
// contract.SnapshotPath/{domain}, as JSON, or as YAML when the query says
// format=yaml or the Accept header names it. Every other method is 405: the
// endpoint reads the store and nothing else.
func Handler(rules *store.Store, reporter Reporter, replica string) http.Handler {
	h := &handler{rules: rules, reporter: reporter, replica: replica}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+contract.SnapshotPath, h.summary)
	mux.HandleFunc("GET "+contract.SnapshotPath+"/{domain}", h.domain)
	return mux
}

type handler struct {
	rules    *store.Store
	reporter Reporter
	replica  string
}

func (h *handler) summary(w http.ResponseWriter, r *http.Request) {
	set := h.rules.Load()
	write(w, r, Summarize(set, h.replica, h.reporter.Report().Refusal))
}

// Summarize builds the summary of one rule set. It is a function of the set
// alone, which is what makes the pairing of rules and generations hold by
// construction: there is no second source to read them from.
func Summarize(set *store.RuleSet, replica string, refusal *applied.Refusal) Summary {
	summary := Summary{
		Replica:   replica,
		SwappedAt: set.SwappedAt(),
		Refusal:   refusal,
		Domains:   make([]DomainSummary, 0, set.Len()),
	}
	for _, domain := range set.Domains() {
		d, _ := set.Domain(domain)
		counts := ruleview.Summary(d.Snapshot, d.Version)
		summary.Domains = append(summary.Domains, DomainSummary{
			Domain:          domain,
			Generation:      d.Generation,
			UID:             d.UID,
			AppliedAt:       d.AppliedAt,
			RuleSetVersion:  counts.RuleSetVersion,
			Blocks:          counts.Blocks,
			Rules:           counts.Rules,
			DecisionBuckets: d.Snapshot.DecisionBuckets,
			EffectiveKeys:   counts.EffectiveKeys,
			ListValuedKeys:  counts.ListValuedKeys,
		})
	}
	return summary
}

func (h *handler) domain(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	d, ok := h.rules.Load().Domain(domain)
	if !ok {
		http.Error(w, "no configuration is applied for domain "+domain, http.StatusNotFound)
		return
	}
	write(w, r, Render(d))
}

// Render builds the full document of one bound domain, from that domain
// alone.
func Render(d store.Domain) DomainSnapshot {
	view := ruleview.Render(d.Snapshot)
	return DomainSnapshot{
		Domain:          d.Snapshot.Domain,
		Generation:      d.Generation,
		UID:             d.UID,
		AppliedAt:       d.AppliedAt,
		RuleSetVersion:  d.Version,
		DecisionBuckets: d.Snapshot.DecisionBuckets,
		EffectiveKeys:   view.EffectiveKeys,
		ListValuedKeys:  view.ListValuedKeys,
		Keys:            keys(d.Snapshot),
		Blocks:          view.Blocks,
	}
}

// keys renders the extraction plan of a snapshot.
func keys(snapshot *compile.Snapshot) []KeyView {
	out := make([]KeyView, 0, len(snapshot.Extraction))
	for i := range snapshot.Extraction {
		extraction := &snapshot.Extraction[i]
		view := KeyView{
			Key:           extraction.Key,
			Claim:         strings.Join(extraction.Path, "."),
			Type:          string(extraction.Type),
			Normalization: string(extraction.Normalization),
		}
		for _, fallback := range extraction.Fallbacks {
			view.Fallbacks = append(view.Fallbacks, strings.Join(fallback, "."))
		}
		out = append(out, view)
	}
	return out
}

// write encodes the document in the format the request asked for. YAML is
// produced from the JSON encoding, so the two carry the same fields under
// the same names and a reader can switch between them without a mapping.
func write(w http.ResponseWriter, r *http.Request, document any) {
	w.Header().Set("Cache-Control", "no-store")
	if wantsYAML(r) {
		body, err := yaml.Marshal(document)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	// The status is already written by then; a truncated body is the
	// reader's to notice, the same as on the applied report.
	_ = encoder.Encode(document)
}

func wantsYAML(r *http.Request) bool {
	if format := r.URL.Query().Get("format"); format != "" {
		return strings.EqualFold(format, "yaml")
	}
	return strings.Contains(r.Header.Get("Accept"), "yaml")
}

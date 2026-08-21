package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
)

// heartbeatInterval keeps an idle stream alive. A selected rule can be quiet
// for minutes, and the proxies between a browser and this process drop a
// connection that says nothing — the comment line costs nothing and is
// discarded by every SSE client.
const heartbeatInterval = 15 * time.Second

// AuditView reports the decision audit selection and where to watch it.
type AuditView struct {
	Rules []auditstream.RuleRef `json:"rules"`

	// MaxRules is the ceiling a client should enforce in its own UI before
	// sending a selection that would be rejected.
	MaxRules int `json:"maxRules"`

	// StreamPath is where the live records are served, so a client does not
	// have to build the URL from a version it might guess wrong.
	StreamPath string `json:"streamPath"`

	// Replica names the pod that answered. The stream carries this replica's
	// decisions only, and a client showing records to a person should say
	// whose they are.
	Replica string `json:"replica,omitempty"`
}

// auditView renders the current selection.
func (a *API) auditView() AuditView {
	return AuditView{
		Rules:      a.Switchboard.Selection().Rules,
		MaxRules:   auditstream.MaxSelectedRules,
		StreamPath: BasePath + "/audit/stream",
		Replica:    a.Replica,
	}
}

// getAudit reports which rules are being streamed.
func (a *API) getAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, a.auditView())
}

// putAudit replaces the selection.
//
// The whole set is replaced rather than added to, so two people debugging at
// once cannot leave a rule streaming that neither of them remembers turning
// on. Turning everything off is an empty rules array, which is also the state
// the operator ships in.
func (a *API) putAudit(w http.ResponseWriter, r *http.Request) {
	var selection auditstream.Selection
	if !decodeJSON(w, r, &selection) {
		return
	}

	if len(selection.Rules) > auditstream.MaxSelectedRules {
		badRequest(w, r, fmt.Sprintf(
			"At most %d rules may stream at once; the request names %d. "+
				"The stream carries one record per matching request, so select the rules being investigated.",
			auditstream.MaxSelectedRules, len(selection.Rules)), "rules")
		return
	}
	if err := a.validateSelection(selection); err != nil {
		a.audit(r, AuditEvent{
			Action: ActionSetAudit, Outcome: OutcomeRejected, Reason: err.Error(),
		})
		badRequest(w, r, err.Error(), "rules")
		return
	}

	// The stored copy comes first. Every replica reads it, so a write that
	// failed after this replica had already switched itself on would leave one
	// pod streaming rules the rest know nothing about.
	if err := a.Selection.Save(r.Context(), selection); err != nil {
		a.Log.Error(err, "failed to store the decision audit selection", "requestId", requestIDOf(r))
		a.audit(r, AuditEvent{
			Action: ActionSetAudit, Outcome: OutcomeFailed, Reason: err.Error(),
		})
		internalError(w, r, "store the audit selection")
		return
	}
	// The other replicas pick this up on their next refresh; applying it here
	// means the caller's own next request already sees what it asked for.
	a.Switchboard.Set(selection)

	a.audit(r, AuditEvent{
		Action: ActionSetAudit, Outcome: OutcomeSucceeded, Keys: len(selection.Rules),
		Reason: describeSelection(selection),
	})

	writeJSON(w, r, a.auditView())
}

// validateSelection rejects a rule this operator is not enforcing, which is
// almost always a typo: a client picks rules from the listing, so anything
// else was typed by hand.
func (a *API) validateSelection(selection auditstream.Selection) error {
	ruleSet := a.Rules.Load()
	for _, ref := range selection.Rules {
		snapshot := ruleSet.Snapshot(ref.Domain)
		if snapshot == nil {
			return fmt.Errorf("no rate limit policy is bound to domain %q", ref.Domain)
		}
		policy, block, rule, ok := splitRuleID(ref.RuleID)
		if !ok {
			return fmt.Errorf("the ruleId %q must be \"policy/block/rule\"", ref.RuleID)
		}
		if _, err := resolveTarget(snapshot, policy, block, rule, nil); err != nil {
			return err
		}
	}
	return nil
}

// describeSelection renders a selection for an audit record.
func describeSelection(selection auditstream.Selection) string {
	if len(selection.Rules) == 0 {
		return "the decision audit stream is off"
	}
	var out strings.Builder
	out.WriteString("streaming")
	for i, ref := range selection.Rules {
		if i > 0 {
			out.WriteString(",")
		}
		out.WriteString(" " + ref.Domain + " " + ref.RuleID)
	}
	return out.String()
}

// streamAudit serves the live decision records as Server-Sent Events.
//
// SSE rather than a WebSocket because the traffic is one-way and a browser
// reconnects on its own; rather than polling because the records are events,
// and a poll would either miss them or need this process to buffer a history
// it has no reason to keep.
//
// What a reader sees is this replica's decisions. The operator runs several
// and each decides its own share of the traffic, so a rule doing steady work
// looks slower here than it is, and a client showing this to a person should
// name the replica the records came from.
func (a *API) streamAudit(w http.ResponseWriter, r *http.Request) {
	filter := streamFilter{
		domain: r.URL.Query().Get("domain"),
		ruleID: r.URL.Query().Get("ruleId"),
	}

	controller := http.NewResponseController(w)
	// The listener has a write timeout so a stalled client cannot hold a
	// connection forever. A stream is the one case where that is wrong: it is
	// supposed to stay open and idle, so its deadline is cleared here rather
	// than the timeout being dropped for every other endpoint.
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		a.Log.Error(err, "failed to clear the write deadline for an audit stream",
			"requestId", requestIDOf(r))
		internalError(w, r, "open the stream")
		return
	}

	subscription, unsubscribe := a.Hub.Subscribe()
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Some proxies buffer a response until it ends, which for a stream is
	// forever. This is the header that turns that off where it is honored.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		return
	}

	// An opening comment gets the headers to a client that is waiting for
	// bytes before it reports the connection as open.
	if _, err := fmt.Fprintf(w, ": streaming decisions from %s\n\n", a.Replica); err != nil {
		return
	}
	_ = controller.Flush()

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	reported := uint64(0)
	for {
		select {
		case <-r.Context().Done():
			return

		case record := <-subscription.Records():
			if !filter.matches(record) {
				continue
			}
			if !writeRecord(w, record) {
				return
			}
			// A reader that fell behind is told so rather than left to believe
			// it saw everything: a gap in an audit stream that looks complete
			// is worse than no stream.
			if dropped := subscription.Dropped(); dropped != reported {
				reported = dropped
				if !writeDropped(w, dropped) {
					return
				}
			}
			if err := controller.Flush(); err != nil {
				return
			}

		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
	}
}

// streamFilter narrows a stream to one domain or one rule, so a client
// watching a single rule does not have to discard the rest in the browser.
type streamFilter struct {
	domain string
	ruleID string
}

func (f streamFilter) matches(record auditstream.Record) bool {
	if f.domain != "" && record.Domain != f.domain {
		return false
	}
	if f.ruleID != "" && record.RuleID != f.ruleID {
		return false
	}
	return true
}

// writeRecord sends one record as an SSE event, reporting whether the
// connection is still usable.
func writeRecord(w http.ResponseWriter, record auditstream.Record) bool {
	encoded, err := json.Marshal(record)
	if err != nil {
		// The record is this process's own struct; a failure here is a bug,
		// and dropping one record beats tearing down the stream.
		return true
	}
	_, err = fmt.Fprintf(w, "event: decision\ndata: %s\n\n", encoded)
	return err == nil
}

// writeDropped tells the reader how many records it has missed.
func writeDropped(w http.ResponseWriter, dropped uint64) bool {
	_, err := fmt.Fprintf(w, "event: dropped\ndata: {\"dropped\":%s}\n\n",
		strconv.FormatUint(dropped, 10))
	return err == nil
}

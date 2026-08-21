package management

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-logr/logr"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// BasePath prefixes every endpoint. It is also what a cluster administrator
// writes in the nonResourceURLs of a role, so it changes only with the API
// version.
//
// It deliberately does not start with /api. Kubernetes ships a ClusterRole
// named system:discovery that grants get on /api/* to the group
// system:authenticated, and it is bound by default — so an API served under
// /api/v1/... is readable by every identity the cluster recognizes, no matter
// what this chart's roles say. Authorization here is a SubjectAccessReview
// against these very paths, which means the prefix is a security boundary and
// not a matter of taste.
const BasePath = "/ratelimit/v1"

// maxReportedKeys bounds how many counter keys a reset response echoes. The
// count is always exact; the list is a sample, because resetting a rule of a
// busy domain can drop tens of thousands of keys and no client benefits from
// being handed all of them.
const maxReportedKeys = 100

// API serves the management endpoints.
type API struct {
	// Rules is the enforced rule set, the same value the decision path reads.
	Rules *store.Store

	// Counters is the store the engines count in.
	Counters counters.Store

	// Scope says whether Counters is shared between replicas, which decides
	// how far a reset reaches.
	Scope CounterScope

	// Auditor records every mutation.
	Auditor Auditor

	// Switchboard and Selection hold the decision audit selection: the first
	// is what this replica enforces, the second is where it is stored for all
	// of them.
	Switchboard *auditstream.Switchboard
	Selection   *auditstream.Store

	// Hub is the live decision stream this replica publishes.
	Hub *auditstream.Hub

	// Replica names this pod. It appears on the audit stream, where a reader
	// is seeing one replica's share of the traffic and has to know it.
	Replica string

	Log logr.Logger
}

// Handler builds the routed, authenticated handler.
//
// The middleware order is the order the concerns have to happen in: a request
// id first so everything after it can be correlated, recovery next so a panic
// in any later layer is still answered, then CORS — which must answer a
// preflight before authentication, since a browser sends preflight without
// credentials by design — and authentication last, immediately in front of the
// handlers, so nothing routed can be reached without it.
func (a *API) Handler(authn Authenticator, authz Authorizer, corsOrigins []string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+BasePath+"/domains", a.listDomains)
	mux.HandleFunc("GET "+BasePath+"/domains/{domain}/rules", a.getRules)
	mux.HandleFunc("GET "+BasePath+"/domains/{domain}/counters", a.listCounters)
	mux.HandleFunc("POST "+BasePath+"/domains/{domain}/counters/reset", a.resetCounters)
	mux.HandleFunc("GET "+BasePath+"/audit", a.getAudit)
	mux.HandleFunc("PUT "+BasePath+"/audit", a.putAudit)
	mux.HandleFunc("GET "+BasePath+"/audit/stream", a.streamAudit)

	// A route this API does not serve gets its own answer rather than the
	// stdlib's plain-text 404, so a client only ever has to parse one error
	// shape.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r, "No endpoint serves "+r.Method+" on this path.")
	})

	var handler http.Handler = mux
	handler = withAuth(authn, authz, a.Log, handler)
	handler = withCORS(corsOrigins, handler)
	handler = withRecovery(a.Log, handler)
	handler = withRequestID(handler)
	return handler
}

// listDomains reports every domain a policy is bound to.
func (a *API) listDomains(w http.ResponseWriter, r *http.Request) {
	ruleSet := a.Rules.Load()
	summaries := make([]DomainSummary, 0, ruleSet.Len())
	for _, domain := range ruleSet.Domains() {
		if snapshot := ruleSet.Snapshot(domain); snapshot != nil {
			summaries = append(summaries, domainSummary(snapshot))
		}
	}
	writeJSON(w, r, newList(summaries))
}

// getRules reports the rule set the domain's engine is deciding with.
func (a *API) getRules(w http.ResponseWriter, r *http.Request) {
	snapshot, ok := a.snapshot(w, r)
	if !ok {
		return
	}
	writeJSON(w, r, ruleSetView(snapshot))
}

// listCounters reports the live counters of a domain.
func (a *API) listCounters(w http.ResponseWriter, r *http.Request) {
	snapshot, ok := a.snapshot(w, r)
	if !ok {
		return
	}
	query, ok := a.parseCounterQuery(w, r)
	if !ok {
		return
	}

	result, err := queryCounters(r.Context(), snapshot, a.Counters, query)
	if errors.Is(err, errNotInspectable) {
		writeProblem(w, r, http.StatusNotImplemented, CodeUnsupported,
			"The configured counter store cannot enumerate keys, so counters cannot be listed.")
		return
	}
	if err != nil {
		a.Log.Error(err, "failed to list counters",
			"domain", snapshot.Domain, "requestId", requestIDOf(r))
		internalError(w, r, "read the counters")
		return
	}
	writeJSON(w, r, result)
}

// parseCounterQuery reads the filters and paging of a listing request.
func (a *API) parseCounterQuery(w http.ResponseWriter, r *http.Request) (counterQuery, bool) {
	values := r.URL.Query()
	query := counterQuery{
		policy:      values.Get("policy"),
		block:       values.Get("block"),
		rule:        values.Get("rule"),
		limitedOnly: values.Get("limited") == "true",
		cursor:      values.Get("cursor"),
		pageSize:    defaultPageSize,
	}

	// A rule id is the shorthand a client already has from the rule listing.
	if id := values.Get("ruleId"); id != "" {
		policy, block, rule, ok := splitRuleID(id)
		if !ok {
			badRequest(w, r, `The ruleId must be "policy/block/rule".`, "ruleId")
			return counterQuery{}, false
		}
		query.policy, query.block, query.rule = policy, block, rule
	}

	if raw := values.Get("limit"); raw != "" {
		size, err := strconv.Atoi(raw)
		if err != nil || size < 1 {
			badRequest(w, r, "The limit must be a positive whole number.", "limit")
			return counterQuery{}, false
		}
		if size > maxPageSize {
			size = maxPageSize
		}
		query.pageSize = size
	}
	return query, true
}

// ResetRequest selects the counters to drop.
//
// The rule is named either by its id, which is what the rule and counter
// listings report, or by its three parts, which is what someone writing the
// call by hand has. Axes narrow the reset to one client; without them the
// whole rule is reset, for every client it counts.
type ResetRequest struct {
	RuleID string `json:"ruleId,omitempty"`

	Policy string `json:"policy,omitempty"`
	Block  string `json:"block,omitempty"`
	Rule   string `json:"rule,omitempty"`

	// Axes are the identity values to reset, by axis name. They must name a
	// leading run of the rule's axes, in the order the rule declares — the
	// rule listing reports that order.
	Axes map[string]string `json:"axes,omitempty"`
}

// ResetResponse reports what the reset actually dropped.
type ResetResponse struct {
	Domain string            `json:"domain"`
	RuleID string            `json:"ruleId"`
	Axes   map[string]string `json:"axes,omitempty"`

	// Scope says how far this reset reached: every replica, or only the one
	// that served the call.
	Scope CounterScope `json:"scope"`

	// ResetCount is exact. Keys is a sample of at most maxReportedKeys.
	ResetCount int      `json:"resetCount"`
	Keys       []string `json:"keys"`
	Truncated  bool     `json:"truncated,omitempty"`
}

// resetCounters drops counter state on demand — the endpoint that lifts a
// limit from a client without waiting for the window to pass.
func (a *API) resetCounters(w http.ResponseWriter, r *http.Request) {
	snapshot, ok := a.snapshot(w, r)
	if !ok {
		return
	}

	var request ResetRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	policy, block, rule, ok := request.rule()
	if !ok {
		badRequest(w, r,
			`Name the rule either as "ruleId": "policy/block/rule" or as separate policy, block and rule fields.`,
			"ruleId", "policy", "block", "rule")
		return
	}

	id := ruleID(policy, block, rule)
	target, err := resolveTarget(snapshot, policy, block, rule, request.Axes)
	if err != nil {
		// A rejected reset is audited too: someone tried to lift a limit and
		// the attempt is as much a management event as a success.
		a.audit(r, AuditEvent{
			Action: ActionResetCounters, Outcome: OutcomeRejected,
			Domain: snapshot.Domain, RuleID: id, Axes: request.Axes, Reason: err.Error(),
		})
		badRequest(w, r, err.Error(), "ruleId", "axes")
		return
	}

	keys, err := dropCounters(r.Context(), snapshot, a.Counters, target)
	if errors.Is(err, errNotInspectable) {
		writeProblem(w, r, http.StatusNotImplemented, CodeUnsupported,
			"The configured counter store cannot enumerate keys, so only a reset naming every axis of the rule is possible.")
		return
	}
	if err != nil {
		a.Log.Error(err, "failed to reset counters",
			"domain", snapshot.Domain, "rule", id, "requestId", requestIDOf(r))
		a.audit(r, AuditEvent{
			Action: ActionResetCounters, Outcome: OutcomeFailed,
			Domain: snapshot.Domain, RuleID: id, Axes: target.named, Reason: err.Error(),
		})
		internalError(w, r, "reset the counters")
		return
	}

	a.audit(r, AuditEvent{
		Action: ActionResetCounters, Outcome: OutcomeSucceeded,
		Domain: snapshot.Domain, RuleID: id, Axes: target.named, Keys: len(keys),
	})

	response := ResetResponse{
		Domain:     snapshot.Domain,
		RuleID:     id,
		Axes:       target.named,
		Scope:      a.scope(),
		ResetCount: len(keys),
		Keys:       keys,
	}
	if len(keys) > maxReportedKeys {
		response.Keys = keys[:maxReportedKeys]
		response.Truncated = true
	}
	if response.Keys == nil {
		response.Keys = []string{}
	}
	writeJSON(w, r, response)
}

// rule resolves the two ways a request may name a rule into one.
func (req ResetRequest) rule() (policy, block, rule string, ok bool) {
	named := req.Policy != "" || req.Block != "" || req.Rule != ""
	switch {
	case req.RuleID != "" && named:
		// Both forms, which can disagree. Guessing which one the caller meant
		// is how a reset lands on the wrong rule.
		return "", "", "", false
	case req.RuleID != "":
		return splitRuleID(req.RuleID)
	case req.Policy != "" && req.Block != "" && req.Rule != "":
		return req.Policy, req.Block, req.Rule, true
	default:
		return "", "", "", false
	}
}

// snapshot resolves the domain of the request against the enforced rule set.
func (a *API) snapshot(w http.ResponseWriter, r *http.Request) (*compile.Snapshot, bool) {
	domain := r.PathValue("domain")
	if domain == "" {
		badRequest(w, r, "The path must name a domain.", "domain")
		return nil, false
	}
	snapshot := a.Rules.Load().Snapshot(domain)
	if snapshot == nil {
		notFound(w, r,
			"No rate limit policy is bound to domain "+strconv.Quote(domain)+
				". List the bound domains at "+BasePath+"/domains.")
		return nil, false
	}
	return snapshot, true
}

// scope reports how far a counter operation reaches, defaulting to the
// narrower of the two answers: claiming a reset was domain-wide when it was
// not is the mistake worth avoiding.
func (a *API) scope() CounterScope {
	if a.Scope == "" {
		return ScopeReplica
	}
	return a.Scope
}

// audit records a mutation, filling in what every record shares.
func (a *API) audit(r *http.Request, event AuditEvent) {
	if a.Auditor == nil {
		return
	}
	event.Subject = subjectOf(r)
	event.RequestID = requestIDOf(r)
	event.Time = time.Now()
	a.Auditor.Record(r.Context(), event)
}

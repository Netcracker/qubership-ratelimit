package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
)

// Simulation is the non-charging request debugger: what would the gateway have
// been told about this request, and which rule said so.
//
// It runs the decision pipeline through Peek, so nothing is reserved and no
// counter moves. The verdict is best-effort as of the instant it was taken,
// since live traffic can change it before the next request arrives. That is the
// honest thing a debugger can offer, and the reason evaluatedAt is reported.

// maxSimulationToken bounds the raw token descriptor. It is the write-only
// field of this API: never echoed, never logged, never quoted in an error.
const maxSimulationToken = 8192

// Identity sources. merge mirrors the gateway, extracting from the token with
// explicit keys overlaid per key, while the pure forms admit exactly their own
// source, so what was judged is never ambiguous.
const (
	identityMerge = "merge"
	identityToken = "token"
	identityKeys  = "keys"
)

// SimulationRequest is one request to judge.
type SimulationRequest struct {
	Domain string `json:"domain"`

	// Path and Method are required: a gateway request always carries them, and
	// route matching is undefined without them.
	Path   string `json:"path"`
	Method string `json:"method"`

	// IdentitySource names the form; absent means merge.
	IdentitySource string `json:"identitySource,omitempty"`

	// Token is the raw token descriptor value. Write-only.
	Token string `json:"token,omitempty"`

	// Keys are pre-extracted identity values, the direct-consumer form.
	Keys map[string][]string `json:"keys,omitempty"`

	// Cost judges every window at this cost; the simulation charges nothing.
	// Absent is 1.
	Cost int64 `json:"cost,omitempty"`

	// carried holds the optional fields the body named, with their raw
	// values, so that an explicit empty or null value is told from an absent
	// one.
	carried map[string]json.RawMessage
}

// UnmarshalJSON decodes the request with no unknown field allowed, as every
// body of this API, and records which of cost, token, and keys it carried.
func (s *SimulationRequest) UnmarshalJSON(data []byte) error {
	type fields SimulationRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode((*fields)(s)); err != nil {
		return err
	}
	var named map[string]json.RawMessage
	if err := json.Unmarshal(data, &named); err != nil {
		return err
	}
	s.carried = map[string]json.RawMessage{}
	for _, name := range []string{"cost", "token", "keys"} {
		if raw, ok := named[name]; ok {
			s.carried[name] = raw
		}
	}
	return nil
}

// carriedEmpty reports whether the body named the field with null or with a
// value that leaves it at its zero value.
func (s *SimulationRequest) carriedEmpty(name string, zero bool) bool {
	raw, ok := s.carried[name]
	return ok && (zero || bytes.Equal(bytes.TrimSpace(raw), []byte("null")))
}

// SimulationResponse is the decision the gateway would have received, plus the
// per-rule breakdown the gateway never sees.
type SimulationResponse struct {
	Allowed bool `json:"allowed"`

	EvaluatedAt time.Time `json:"evaluatedAt"`

	// RefusalReason is present only on a refusal: the reason of the binding
	// enforcing window. Shadow rules never set it; their reasons live in their
	// own outcomes.
	RefusalReason string `json:"refusalReason,omitempty"`

	Headers *HeadersView `json:"headers,omitempty"`

	// Rules is every applied rule with its own verdict, shadow rules included,
	// reporting what they would have done.
	Rules []RuleOutcomeView `json:"rules"`

	// Skips are identity-extraction anomalies; they never carry claim values.
	Skips []SkipView `json:"skips,omitempty"`

	// ExtractedKeys names the declared identity keys the request carried, never
	// the values.
	ExtractedKeys []string `json:"extractedKeys,omitempty"`
}

// HeadersView is what the rate limit response headers would have carried: the
// binding window across every applied enforcing rule.
type HeadersView struct {
	// Block and Rule name the rule the numbers came from, the name the
	// ratelimit-policy and ratelimit fields carry as block/rule.
	Block string `json:"block"`
	Rule  string `json:"rule"`

	Algorithm     string `json:"algorithm"`
	PeriodSeconds int64  `json:"periodSeconds"`

	Limit     int64 `json:"limit"`
	Remaining int64 `json:"remaining"`

	// RetryAfterSeconds is present exactly on refusals that waiting cures.
	RetryAfterSeconds *float64 `json:"retryAfterSeconds,omitempty"`
	ResetAfterSeconds *float64 `json:"resetAfterSeconds,omitempty"`

	// EffectiveWindowSeconds is the t of the ratelimit response field: the
	// seconds until the window admits one request more than Remaining. It is
	// absent where the window holds its whole capacity, which, since the
	// simulation charges nothing, includes a window the request would be the
	// first to touch. The real answer, after its own charge, carries one
	// emission interval there under GCRA and the time to the boundary under
	// a fixed window.
	EffectiveWindowSeconds *float64 `json:"effectiveWindowSeconds,omitempty"`
}

// RuleOutcomeView is one applied rule's own verdict. A rule may carry several
// windows; the numbers come from the binding one among its own.
type RuleOutcomeView struct {
	ID   string `json:"id"`
	Mode string `json:"mode"`

	Allowed bool `json:"allowed"`

	Algorithm     string `json:"algorithm"`
	PeriodSeconds int64  `json:"periodSeconds"`

	Limit     int64 `json:"limit"`
	Remaining int64 `json:"remaining"`

	// RefusalReason is mandatory on a refusal, and RetryAfterSeconds is present
	// exactly when it is rate_limited: no waiting cures capacity_exceeded, so
	// no hint can be offered for it.
	RefusalReason     string   `json:"refusalReason,omitempty"`
	RetryAfterSeconds *float64 `json:"retryAfterSeconds,omitempty"`
}

// SkipView is one identity-extraction anomaly.
type SkipView struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// Refusal reasons. rate_limited is a window doing its job; capacity_exceeded is
// a request no waiting can cure, because its cost is larger than the window can
// ever hold.
const (
	ReasonRateLimited      = "rate_limited"
	ReasonCapacityExceeded = "capacity_exceeded"
)

// validate checks the structural form of a simulation request.
func (s *SimulationRequest) validate() *apiError {
	if s.Domain == "" {
		return invalid("the simulation needs a domain", "domain")
	}
	if s.Path == "" {
		return invalid("the simulation needs a request path", "path")
	}
	if s.Method == "" {
		return invalid("the simulation needs an HTTP method", "method")
	}
	// The schema of the specification bounds each optional field, and the
	// runtime holds the same bounds: a field that is present is a value, never
	// an absent one in disguise.
	if s.Cost < 0 || s.carriedEmpty("cost", s.Cost == 0) {
		return invalid("the cost must be at least 1; omit it for a cost of 1", "cost")
	}
	if s.carriedEmpty("token", s.Token == "") {
		return invalid("the token is empty; omit the field instead", "token")
	}
	if s.carriedEmpty("keys", len(s.Keys) == 0) {
		return invalid("keys names no identity key; omit the field instead", "keys")
	}
	if len(s.Token) > maxSimulationToken {
		return invalid("the token is longer than the 8 KiB this endpoint accepts", "token")
	}
	for name, values := range s.Keys {
		if len(values) == 0 {
			return invalid("identity key "+logSafe(name)+" carries no values; omit it instead", "keys")
		}
	}

	switch s.IdentitySource {
	case "", identityMerge:
		// Both sources are optional here, and with neither the simulation is
		// anonymous. That is a legitimate question: what do the unconditional
		// rules say.
		return nil
	case identityToken:
		if s.Token == "" {
			return invalid("the token form needs a token", "token")
		}
		if s.Keys != nil {
			return invalid("the token form takes identity from extraction alone, so it admits no keys field", "keys")
		}
		return nil
	case identityKeys:
		if len(s.Keys) == 0 {
			return invalid("the keys form needs at least one identity key", "keys")
		}
		if s.Token != "" {
			return invalid("the keys form takes identity from explicit values alone, so it admits no token field", "token")
		}
		return nil
	default:
		return invalid("identitySource is merge, token, or keys", "identitySource")
	}
}

// simulate judges one request without charging anything.
func (a *API) simulate(ctx context.Context, request SimulationRequest) (SimulationResponse, *apiError) {
	rules := a.Rules.Load()
	domainEngine := rules.Engine(request.Domain)
	if domainEngine == nil {
		return SimulationResponse{}, notFound("domain " + logSafe(request.Domain) +
			" is not in the enforced rule set")
	}
	// A simulation's keys are identity values, never a path segment: a capture
	// takes its value from the simulated path, so no key is skipped here.
	if apiErr := unnormalized(rules.Snapshot(request.Domain), request.Keys, nil,
		func(string) string { return "keys" }); apiErr != nil {
		return SimulationResponse{}, apiErr
	}

	decision, err := domainEngine.Peek(ctx, engine.Request{
		Path:   request.Path,
		Method: request.Method,
		Token:  request.Token,
		Keys:   request.Keys,
		Cost:   request.Cost,
	})
	if errors.Is(err, engine.ErrTooManyBuckets) {
		// Not a store incident: the request matched more buckets than a
		// decision may carry, which the enforcing path refuses too.
		return SimulationResponse{}, errorf(CodeInternal,
			"this request matches more counters than one decision may carry, "+
				"so the enforcing path refuses it as well")
	}
	if err != nil {
		a.Log.ErrorC(ctx, "failed to simulate a request domain=%v error=%v", request.Domain, err)
		return SimulationResponse{}, storeDown("the counter store did not answer the simulation")
	}
	return simulationResponse(decision, a.now().UTC()), nil
}

func simulationResponse(decision engine.Decision, at time.Time) SimulationResponse {
	response := SimulationResponse{
		Allowed:       decision.Allowed,
		EvaluatedAt:   at,
		Rules:         make([]RuleOutcomeView, 0, len(decision.Rules)),
		ExtractedKeys: decision.ExtractedKeys,
	}
	if !decision.Allowed {
		response.RefusalReason = refusalReason(decision.CostExceedsCapacity)
	}
	if decision.Headers != nil {
		response.Headers = headersView(decision.Headers, decision.Allowed, decision.CostExceedsCapacity)
	}
	for _, outcome := range decision.Rules {
		response.Rules = append(response.Rules, ruleOutcomeView(outcome))
	}
	for _, skip := range decision.Skips {
		response.Skips = append(response.Skips, SkipView{Key: skip.Key, Reason: string(skip.Reason)})
	}
	return response
}

func headersView(headers *engine.Headers, allowed, costExceeds bool) *HeadersView {
	view := &HeadersView{
		Block:         headers.Block,
		Rule:          headers.Rule,
		Algorithm:     headers.Algorithm,
		PeriodSeconds: headers.PeriodSeconds,
		Limit:         headers.Limit,
		Remaining:     headers.Remaining,
	}
	if !allowed && !costExceeds && headers.RetryAfter > 0 {
		view.RetryAfterSeconds = seconds(headers.RetryAfter)
	}
	if headers.ResetAfter > 0 {
		view.ResetAfterSeconds = seconds(headers.ResetAfter)
	}
	if headers.EffectiveWindow >= 0 {
		view.EffectiveWindowSeconds = seconds(headers.EffectiveWindow)
	}
	return view
}

func ruleOutcomeView(outcome engine.RuleOutcome) RuleOutcomeView {
	mode := ruleview.ModeEnforce
	if outcome.Shadow {
		mode = ruleview.ModeShadow
	}
	view := RuleOutcomeView{
		ID:            ruleID(outcome.Block, outcome.Rule),
		Mode:          mode,
		Allowed:       outcome.Allowed,
		Algorithm:     outcome.Algorithm,
		PeriodSeconds: outcome.PeriodSeconds,
		Limit:         outcome.Limit,
		Remaining:     outcome.Remaining,
	}
	if outcome.Allowed {
		return view
	}
	view.RefusalReason = refusalReason(outcome.CostExceedsCapacity)
	if !outcome.CostExceedsCapacity && outcome.RetryAfter > 0 {
		view.RetryAfterSeconds = seconds(outcome.RetryAfter)
	}
	return view
}

func refusalReason(costExceeds bool) string {
	if costExceeds {
		return ReasonCapacityExceeded
	}
	return ReasonRateLimited
}

func seconds(d time.Duration) *float64 {
	value := d.Seconds()
	return &value
}

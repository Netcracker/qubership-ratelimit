// Package rls implements the Envoy rate limit service (RLS) protocol.
package rls

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	engine "github.com/netcracker/qubership-ratelimit/engine"
	auditstream "github.com/netcracker/qubership-ratelimit/internal/audit"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// Logger is the part of the platform logger the server needs.
type Logger interface {
	DebugC(ctx context.Context, format string, args ...any)
	InfoC(ctx context.Context, format string, args ...any)
	ErrorC(ctx context.Context, format string, args ...any)
}

const (
	// descriptorKeyPath is the descriptor entry carrying the :path pseudo-header.
	descriptorKeyPath = "path"

	// descriptorKeyMethod carries the :method pseudo-header.
	descriptorKeyMethod = "method"

	// descriptorKeyToken carries the authorization header; the engine's
	// identity layer extracts claims from it and never lets the raw value out.
	descriptorKeyToken = "token"

	// descriptorKeyRequestID carries x-request-id, which the gateway sends so a
	// check can be correlated with the gateway access log for the same request.
	// It is log correlation only, never an identity key.
	descriptorKeyRequestID = "request_id"

	// queryRedacted replaces the query string of a logged path. Envoy's :path
	// carries the query, and query strings routinely hold credentials —
	// ?access_token=, ?api_key=, session ids.
	queryRedacted = "?[redacted]"

	// maxDescriptorsPerCheck bounds how many descriptors one check may carry:
	// every descriptor is its own engine decision and its own store trip, and
	// the gateway form sends exactly one. Sixteen leaves room for legitimate
	// direct consumers without letting one call become an unbounded store scan.
	maxDescriptorsPerCheck = 16

	// maxLoggedValueLength bounds a logged descriptor value. The value is chosen
	// by the caller, not by us, so an unbounded copy is an unbounded log record.
	maxLoggedValueLength = 256
	valueTruncated       = "[truncated]"
)

// Server answers Envoy rate limit checks by deciding through the domain's
// engine from the rule store.
type Server struct {
	envoyratelimit.UnimplementedRateLimitServiceServer

	store *store.Store
	log   Logger

	// audit and hub carry the decision audit stream. Both are nil unless the
	// process runs the management API, and the stream stays silent until an
	// operator selects a rule through it.
	audit   *auditstream.Switchboard
	hub     *auditstream.Hub
	replica string
}

// Option adjusts a Server at construction.
type Option func(*Server)

// WithDecisionAudit attaches the decision audit stream. The switchboard says
// which rules are streamed and the hub fans the records out; replica names
// this pod, so a reader watching one connection can tell whose decisions they
// are seeing.
func WithDecisionAudit(switchboard *auditstream.Switchboard, hub *auditstream.Hub, replica string) Option {
	return func(s *Server) {
		s.audit = switchboard
		s.hub = hub
		s.replica = replica
	}
}

// NewServer returns a Server reading its rule set from the given store.
func NewServer(s *store.Store, log Logger, opts ...Option) *Server {
	server := &Server{store: s, log: log}
	for _, apply := range opts {
		apply(server)
	}
	return server
}

// ShouldRateLimit decides whether the request may pass.
func (s *Server) ShouldRateLimit(
	ctx context.Context,
	req *envoyratelimit.RateLimitRequest,
) (*envoyratelimit.RateLimitResponse, error) {
	domain := req.GetDomain()

	path, requestID := loggableEntries(req)
	ctx = ctxmanager.InitContext(ctx, map[string]any{
		xrequestid.X_REQUEST_ID_HEADER_NAME: requestID,
	})

	eng := s.store.Engine(domain)
	if eng == nil {
		// A domain no policy claims means the gateway's filter config and the
		// CRs have drifted apart; nothing else detects it. No policy also
		// means no limit to enforce, so the traffic passes.
		s.log.InfoC(ctx, "unknown rate limit domain: no RateLimitPolicy is bound to it domain=%v path=%v",
			domain, path)
		return &envoyratelimit.RateLimitResponse{OverallCode: envoyratelimit.RateLimitResponse_OK}, nil
	}

	requests := engineRequests(req)
	if len(requests) > maxDescriptorsPerCheck {
		// A check carrying more descriptors than any sanctioned caller sends
		// is a protocol violation, not unavailability: refusing keeps it off
		// the fail-open path an abuser could otherwise ride through.
		s.log.ErrorC(ctx, "rate limit check carries %v descriptors, over the limit of %v domain=%v path=%v",
			len(requests), maxDescriptorsPerCheck, domain, path)
		return &envoyratelimit.RateLimitResponse{
			OverallCode: envoyratelimit.RateLimitResponse_OVER_LIMIT,
		}, nil
	}
	decisions := make([]engine.Decision, 0, len(requests))
	allowed := true
	for _, er := range requests {
		decision, err := eng.Decide(ctx, er)
		if err != nil {
			if errors.Is(err, engine.ErrTooManyBuckets) {
				// The bucket-budget backstop reports a configuration
				// violation, not unavailability: it denies regardless of the
				// fallback policy, or an oversized policy set would turn the
				// widest paths into unlimited ones.
				s.log.ErrorC(ctx, "rate limit decision over the bucket budget domain=%v path=%v error=%v",
					domain, path, err)
				return &envoyratelimit.RateLimitResponse{
					OverallCode: envoyratelimit.RateLimitResponse_OVER_LIMIT,
				}, nil
			}
			if !allowed {
				// An earlier descriptor already refused: the answer is known,
				// and a store error on a later one must not launder that
				// refusal into the fail-open path.
				s.log.ErrorC(ctx, "rate limit store error after a refusal domain=%v path=%v error=%v",
					domain, path, err)
				return &envoyratelimit.RateLimitResponse{
					OverallCode:          envoyratelimit.RateLimitResponse_OVER_LIMIT,
					ResponseHeadersToAdd: responseHeaders(strictestDecision(decisions, false)),
				}, nil
			}
			// A store error becomes a gRPC error, so Envoy's failure_mode_deny
			// stays the one switch deciding fail-open versus fail-closed.
			s.log.ErrorC(ctx, "rate limit store error domain=%v path=%v error=%v", domain, path, err)
			return nil, status.Error(codes.Unavailable, "rate limit store unavailable")
		}
		allowed = allowed && decision.Allowed
		decisions = append(decisions, decision)
	}

	code := envoyratelimit.RateLimitResponse_OK
	if !allowed {
		code = envoyratelimit.RateLimitResponse_OVER_LIMIT
	}
	rules := 0
	for _, d := range decisions {
		rules += len(d.Rules)
	}
	s.log.DebugC(ctx, "rate limit check domain=%v path=%v allowed=%v rules=%v", domain, path, allowed, rules)
	// The method comes from a descriptor, so it is caller-controlled and gets
	// the same treatment as the path before it reaches a log line or a record.
	s.publishDecisionAudit(ctx, domain, path, sanitizeValue(methodOf(requests)), requestID, decisions)

	return &envoyratelimit.RateLimitResponse{
		OverallCode:          code,
		ResponseHeadersToAdd: responseHeaders(strictestDecision(decisions, allowed)),
	}, nil
}

// engineRequests folds each descriptor into its own engine request — the
// Envoy semantics: descriptors are decided independently, every one of them
// charges its own counters per its own verdict, and the overall answer
// refuses when any one of them does. A request without descriptors still
// makes one empty-request decision, so whole-domain limits see direct
// consumers too.
//
// Within a descriptor, path, method, and token feed the built-in keys,
// request_id stays a log correlation field, and any other entry arrives as a
// pre-extracted identity key — the direct-consumer form of the protocol. An
// empty value means absence, mirroring the identity layer. hits_addend is
// the cost of every decision; zero means the protocol default of one.
func engineRequests(req *envoyratelimit.RateLimitRequest) []engine.Request {
	cost := int64(req.GetHitsAddend())
	descriptors := req.GetDescriptors()
	if len(descriptors) == 0 {
		return []engine.Request{{Cost: cost}}
	}
	out := make([]engine.Request, 0, len(descriptors))
	for _, descriptor := range descriptors {
		er := engine.Request{Cost: cost}
		for _, entry := range descriptor.GetEntries() {
			value := entry.GetValue()
			if value == "" {
				continue
			}
			switch entry.GetKey() {
			case descriptorKeyPath:
				er.Path = value
			case descriptorKeyMethod:
				er.Method = value
			case descriptorKeyToken:
				er.Token = value
			case descriptorKeyRequestID:
			default:
				if er.Keys == nil {
					er.Keys = map[string][]string{}
				}
				er.Keys[entry.GetKey()] = append(er.Keys[entry.GetKey()], value)
			}
		}
		out = append(out, er)
	}
	return out
}

// publishDecisionAudit emits one record per applied rule an operator has
// selected for the decision audit stream.
//
// The guards in front are the feature's whole cost model. Nothing selected
// means one atomic load per check, which is what lets this sit on a path that
// runs at gateway speed; a selected rule then costs a record per matching
// request, which is the firehose the operator asked for deliberately.
//
// A record names the rule and what it decided, never the identity behind the
// counter: the axis values are inside the engine's bucket keys, and a
// RuleOutcome does not carry them. Someone tracing one client's refusals reads
// the counter listing for the values and this stream for the timing.
func (s *Server) publishDecisionAudit(
	ctx context.Context,
	domain, path, method, requestID string,
	decisions []engine.Decision,
) {
	if s.audit == nil || !s.audit.Any() {
		return
	}

	// One timestamp for the whole check: every rule below decided the same
	// request, so stamping them individually would suggest an ordering that
	// does not exist.
	checked := auditedRequest{
		time: time.Now(), domain: domain, path: path, method: method, requestID: requestID,
	}
	for _, decision := range decisions {
		for _, rule := range decision.Rules {
			if !s.audit.Enabled(domain, rule.Policy, rule.Block, rule.Rule) {
				continue
			}
			s.emitDecisionRecord(ctx, s.auditRecord(checked, rule))
		}
	}
}

// auditedRequest is the request-level context every record of one check shares.
type auditedRequest struct {
	time      time.Time
	domain    string
	path      string
	method    string
	requestID string
}

// auditRecord renders one applied rule's decision.
func (s *Server) auditRecord(checked auditedRequest, rule engine.RuleOutcome) auditstream.Record {
	record := auditstream.Record{
		Time:      checked.time,
		Domain:    checked.domain,
		RuleID:    rule.Policy + "/" + rule.Block + "/" + rule.Rule,
		Verdict:   auditstream.VerdictAllowed,
		Shadow:    rule.Shadow,
		Limit:     rule.Limit,
		Remaining: rule.Remaining,
		Path:      checked.path,
		Method:    checked.method,
		RequestID: checked.requestID,
		Replica:   s.replica,
	}
	if !rule.Allowed {
		record.Verdict = auditstream.VerdictRefused
		if rule.RetryAfter > 0 {
			record.RetryAfterSeconds = rule.RetryAfter.Seconds()
		}
	}
	return record
}

// emitDecisionRecord sends one record to whoever is watching, and to the log.
//
// The log carries the stream too, so a selection made while nobody is watching
// still leaves a trace to read afterwards.
func (s *Server) emitDecisionRecord(ctx context.Context, record auditstream.Record) {
	if s.hub != nil {
		s.hub.Publish(record)
	}
	s.log.InfoC(ctx,
		"rate limit decision audit domain=%v rule=%v verdict=%v shadow=%v limit=%v remaining=%v path=%v method=%v",
		record.Domain, record.RuleID, record.Verdict, record.Shadow,
		record.Limit, record.Remaining, record.Path, record.Method)
}

// methodOf returns the method the check reported, for the audit record. Every
// descriptor of one check describes the same HTTP request, so the first one
// that carries a method speaks for all of them.
func methodOf(requests []engine.Request) string {
	for _, request := range requests {
		if request.Method != "" {
			return request.Method
		}
	}
	return ""
}

// strictestDecision picks the decision whose numbers the response carries:
// among refusals, the longest wait; among admitted ones, the least remaining.
// Decisions without matched counting rules carry no headers and lose every
// comparison; when none carries headers, the response carries none either.
func strictestDecision(decisions []engine.Decision, allowed bool) engine.Decision {
	var best engine.Decision
	for _, d := range decisions {
		if d.Headers == nil || d.Allowed != allowed {
			continue
		}
		if best.Headers == nil {
			best = d
			continue
		}
		if allowed {
			if d.Headers.Remaining < best.Headers.Remaining {
				best = d
			}
		} else if d.Headers.RetryAfter > best.Headers.RetryAfter {
			best = d
		}
	}
	if best.Headers == nil {
		best.Allowed = allowed
	}
	return best
}

// responseHeaders turns the strictest-rule numbers into the x-ratelimit-*
// response headers; a refusal that waiting can cure also carries retry-after.
// A decision without matched counting rules carries no headers at all, and a
// refusal no waiting cures carries no retry hint — the engine marks it with a
// negative RetryAfter.
func responseHeaders(decision engine.Decision) []*corev3.HeaderValue {
	h := decision.Headers
	if h == nil {
		return nil
	}
	out := []*corev3.HeaderValue{
		{Key: "x-ratelimit-limit", Value: strconv.FormatInt(h.Limit, 10)},
		{Key: "x-ratelimit-remaining", Value: strconv.FormatInt(h.Remaining, 10)},
		{Key: "x-ratelimit-reset", Value: strconv.FormatInt(ceilSeconds(h.ResetAfter), 10)},
	}
	if !decision.Allowed && h.RetryAfter >= 0 {
		out = append(out, &corev3.HeaderValue{
			Key: "retry-after", Value: strconv.FormatInt(ceilSeconds(h.RetryAfter), 10)})
	}
	return out
}

// ceilSeconds rounds a duration up to whole seconds — the resolution HTTP
// rate limit headers speak.
func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// loggableEntries returns the two descriptor values that are safe to log.
func loggableEntries(req *envoyratelimit.RateLimitRequest) (path, requestID string) {
	for _, descriptor := range req.GetDescriptors() {
		for _, entry := range descriptor.GetEntries() {
			switch entry.GetKey() {
			case descriptorKeyPath:
				path = sanitizePath(entry.GetValue())
			case descriptorKeyRequestID:
				requestID = sanitizeValue(entry.GetValue())
			}
		}
	}
	return path, requestID
}

// sanitizePath makes a caller-controlled :path safe to put in a log line.
//
// Three things are wrong with logging it raw: the query string can carry
// credentials; control characters let a caller forge log records by injecting
// newlines; and the length is bounded only by what the gateway accepts.
func sanitizePath(path string) string {
	query := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], queryRedacted
	}
	return sanitizeValue(path) + query
}

// sanitizeValue strips what a caller could use to forge or flood a log record:
// control characters let them inject newlines, and the length is bounded only by
// what the gateway accepts.
func sanitizeValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)

	if len(value) > maxLoggedValueLength {
		// Cut on a rune boundary: slicing bytes can split a multi-byte rune and
		// leave an invalid sequence in the log.
		value = strings.ToValidUTF8(value[:maxLoggedValueLength], "") + valueTruncated
	}
	return value
}

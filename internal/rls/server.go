// Package rls implements the Envoy rate limit service (RLS) protocol.
package rls

import (
	"context"
	"strings"

	envoyratelimit "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"

	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// Logger is the part of the platform logger the server needs.
type Logger interface {
	InfoC(ctx context.Context, format string, args ...any)
}

const (
	// descriptorKeyPath is the descriptor entry carrying the :path pseudo-header.
	descriptorKeyPath = "path"

	// descriptorKeyRequestID carries x-request-id, which the gateway sends so a
	// check can be correlated with the gateway access log for the same request.
	descriptorKeyRequestID = "request_id"

	// queryRedacted replaces the query string of a logged path. Envoy's :path
	// carries the query, and query strings routinely hold credentials —
	// ?access_token=, ?api_key=, session ids.
	queryRedacted = "?[redacted]"

	// maxLoggedValueLength bounds a logged descriptor value. The value is chosen
	// by the caller, not by us, so an unbounded copy is an unbounded log record.
	maxLoggedValueLength = 256
	valueTruncated       = "[truncated]"
)

// Server answers Envoy rate limit checks.
type Server struct {
	envoyratelimit.UnimplementedRateLimitServiceServer

	store   *store.Store
	limiter *fixedWindow
	log     Logger
}

// NewServer returns a Server reading its rule set from the given store.
func NewServer(s *store.Store, log Logger) *Server {
	return &Server{
		store:   s,
		limiter: newFixedWindow(defaultLimit, defaultWindow),
		log:     log,
	}
}

// ShouldRateLimit decides whether the request may pass.
func (s *Server) ShouldRateLimit(
	ctx context.Context,
	req *envoyratelimit.RateLimitRequest,
) (*envoyratelimit.RateLimitResponse, error) {
	domain := req.GetDomain()
	known := s.store.HasDomain(domain)

	allowed, current := true, 0
	if known {
		allowed, current = s.limiter.allow(domain)
	}

	path, requestID := loggableEntries(req)
	ctx = ctxmanager.InitContext(ctx, map[string]any{
		xrequestid.X_REQUEST_ID_HEADER_NAME: requestID,
	})

	s.log.InfoC(ctx, "rate limit check domain=%v path=%v knownDomain=%v allowed=%v count=%v",
		domain, path, known, allowed, current)
	if !known {
		s.log.InfoC(ctx, "unknown rate limit domain: no RateLimitPolicy is bound to it domain=%v", domain)
	}

	code := envoyratelimit.RateLimitResponse_OK
	if !allowed {
		code = envoyratelimit.RateLimitResponse_OVER_LIMIT
	}
	return &envoyratelimit.RateLimitResponse{OverallCode: code}, nil
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

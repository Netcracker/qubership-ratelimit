package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
)

// RequestIDHeader carries the correlation id. A caller that sets it gets it
// back on the response and in every log line and audit record of the call,
// which is what makes a reset traceable from a UI click to the operator log.
const RequestIDHeader = "X-Request-Id"

// maxRequestBody bounds a request body. Every body this API accepts is a small
// object, so the limit exists to stop an authenticated client from making the
// operator read an endless stream into memory.
const maxRequestBody = 1 << 20 // 1 MiB

type contextKey int

const (
	contextKeyRequestID contextKey = iota
	contextKeyUser
)

// List is the envelope of every collection response. A bare JSON array is
// harder to extend: adding a total or a cursor later would change the type of
// the whole body, and a client that expects an array breaks. Items is never
// null — an empty collection is an empty array, so a client can iterate
// without a nil check.
type List[T any] struct {
	Items []T `json:"items"`

	// NextCursor is the value to pass back as ?cursor= for the next page. It
	// is empty on the last page, which is how a caller knows to stop.
	NextCursor string `json:"nextCursor,omitempty"`

	// Truncated marks a page cut short by a limit rather than by the end of
	// the collection. It repeats what a non-empty NextCursor implies, in the
	// form a progress indicator wants to read.
	Truncated bool `json:"truncated,omitempty"`
}

// newList wraps items, normalizing a nil slice into an empty one.
func newList[T any](items []T) List[T] {
	if items == nil {
		items = []T{}
	}
	return List[T]{Items: items}
}

// writeJSON sends a success body. Every endpoint here answers 200 on success —
// nothing is created and nothing is accepted for later — so the status is not a
// parameter that could be got wrong.
func writeJSON(w http.ResponseWriter, r *http.Request, body any) {
	buf, err := json.Marshal(body)
	if err != nil {
		// Encoding this package's own types cannot fail on valid data, so this
		// is a bug. Reporting it as a 500 beats sending a half-written body
		// with a 200 already on the wire.
		internalError(w, r, "encode the response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

// decodeJSON reads a request body into v, rejecting the shapes a client should
// hear about rather than have silently ignored: a wrong content type, an
// unknown field (usually a typo or a version mismatch), and trailing data.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		if media, _, _ := strings.Cut(contentType, ";"); strings.TrimSpace(media) != "application/json" {
			writeProblem(w, r, http.StatusUnsupportedMediaType, CodeInvalidRequest,
				"The request body must be application/json.")
			return false
		}
	}

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		badRequest(w, r, "The request body is not valid JSON for this endpoint: "+err.Error())
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		badRequest(w, r, "The request body carries more than one JSON value.")
		return false
	}
	return true
}

// withRequestID gives every request a correlation id, reusing the caller's
// when it sent one.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitizeHeader(r.Header.Get(RequestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKeyRequestID, id)))
	})
}

// withRecovery turns a handler panic into a 500 instead of dropping the
// connection and taking the listener's goroutine with it.
func withRecovery(log logr.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Error(nil, "management request panicked",
					"panic", recovered, "path", r.URL.Path, "requestId", requestIDOf(r))
				internalError(w, r, "serve the request")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withCORS answers browser preflight and marks the responses a configured
// origin may read. The allowed origins are an explicit list: a UI is served
// from somewhere the operator does not know, and a wildcard on an API that
// lifts rate limits is not a default anyone should inherit.
//
// Credentials are never allowed, so a browser cannot be tricked into spending
// an ambient cookie here — a UI authenticates by sending a bearer token it
// holds deliberately.
func withCORS(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	allowed := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		allowed[strings.TrimSpace(origin)] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := allowed[origin]; ok && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, "+RequestIDHeader)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", RequestIDHeader)
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		// Vary is set whether or not this origin matched: the response differs
		// by Origin, and a cache that missed that would hand one origin's
		// headers to another.
		w.Header().Add("Vary", "Origin")

		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestIDOf returns the correlation id of the request, or an empty string
// outside the middleware.
func requestIDOf(r *http.Request) string {
	if r == nil {
		return ""
	}
	id, _ := r.Context().Value(contextKeyRequestID).(string)
	return id
}

// newRequestID returns a random correlation id.
func newRequestID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand does not fail on any platform this runs on, and a
		// correlation id is not worth failing a request over.
		return "unknown"
	}
	return hex.EncodeToString(buf[:])
}

// sanitizeHeader strips what must never reach a log line or a response header
// from a caller-supplied value: control characters forge log records and
// response headers, and an unbounded value is an unbounded log record.
func sanitizeHeader(v string) string {
	const maxLength = 128
	var b strings.Builder
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len() >= maxLength {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

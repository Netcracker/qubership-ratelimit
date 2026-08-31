package management

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
)

// RequestIDHeader carries the correlation id.
//
// It is a global contract of this API: optional on the request, mandatory on
// every response, and the same value runs through the operator log, the audit
// journal, and meta.requestId of every error body. It is what a person quotes
// when asking what happened.
//
// The platform owns all of that. Its context propagation reads the header or
// generates a value, puts it on every response, and prints it beside every log
// line. This package therefore neither generates ids nor writes the header on a
// normal request. What is left here is the one rule the propagation does not
// have: a value outside the log-safe pattern is refused rather than passed
// through (see withRequestID).
const RequestIDHeader = xrequestid.X_REQUEST_ID_HEADER_NAME

// requestIDPattern is the log-safe shape a caller-supplied id has to have. The
// value is written to logs and to the audit journal verbatim, so anything that
// could forge a record is refused rather than sanitized. Silently rewriting a
// correlation id would break the correlation it exists for.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// maxRequestBody bounds a request body. Every body this API accepts is a small
// object, so the limit exists to stop an authenticated client from making the
// service read an endless stream into memory.
const maxRequestBody = 1 << 20 // 1 MiB

// localSubject is where the identity middleware keeps the caller.
const localSubject = "ratelimit.subject"

// withRequestID refuses a correlation id this service would not want to write
// down.
//
// The id reaches logs, the audit journal, and error bodies verbatim, so a value
// carrying control characters could forge whole records. Rewriting it quietly
// would break the correlation the header exists for, which leaves refusing as
// the only option, and it is the one the API documents.
//
// Everything else about the header belongs to the platform: propagation put a
// value in the context before this ran and will put one on the response. Only
// the refusal path touches either, and it replaces both, so the caller's value
// never reaches a log line or a response header.
func withRequestID(c *fiber.Ctx) error {
	if id := c.Get(RequestIDHeader); id != "" && !requestIDPattern.MatchString(id) {
		replaceRequestID(c)
		return invalid("the "+RequestIDHeader+" header does not match "+requestIDPattern.String(),
			RequestIDHeader)
	}
	return c.Next()
}

// replaceRequestID swaps a refused id for a fresh one, in the context the
// platform logger reads and in the response header it already wrote.
func replaceRequestID(c *fiber.Ctx) {
	provider := xrequestid.XRequestIdProvider{}
	// An empty value asks the platform to generate one.
	ctx, err := provider.Set(c.UserContext(), xrequestid.NewXRequestIdContextObject(""))
	if err == nil {
		c.SetUserContext(ctx)
	}
	c.Set(RequestIDHeader, requestIDOf(c))
}

// writeJSON sends a success body. Every endpoint here answers 200 on success,
// so the status is not a parameter that could be got wrong.
func writeJSON(c *fiber.Ctx, body any) error {
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	return c.Status(fiber.StatusOK).JSON(body)
}

// decodeJSON reads a request body, rejecting the shapes a client should hear
// about rather than have silently ignored: a wrong content type, an unknown
// field (usually a typo or a version mismatch), and trailing data.
func decodeJSON(c *fiber.Ctx, v any) *apiError {
	if contentType := c.Get(fiber.HeaderContentType); contentType != "" {
		if media, _, _ := strings.Cut(contentType, ";"); strings.TrimSpace(media) != fiber.MIMEApplicationJSON {
			return invalid("the request body must be application/json; send it with that Content-Type",
				fiber.HeaderContentType)
		}
	}

	body := c.Body()
	if len(body) > maxRequestBody {
		return invalid("the request body is larger than the 1 MiB this endpoint accepts")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return invalid("the request body is not valid JSON for this endpoint: " + err.Error())
	}
	if err := decoder.Decode(&struct{}{}); err == nil {
		return invalid("the request body carries more than one JSON value")
	}
	return nil
}

// queryValues collects the query string with every repetition kept.
//
// The selection grammar repeats parameters: one axis name ORs its values, and
// ruleId is repeatable. The last-one-wins map a router hands out would quietly
// narrow a listing and, worse, quietly widen a reset.
func queryValues(c *fiber.Ctx) url.Values {
	values := url.Values{}
	for key, value := range c.Request().URI().QueryArgs().All() {
		values.Add(string(key), string(value))
	}
	return values
}

// requestIDOf returns the correlation id the platform resolved for this
// request: the same value its logger prints and its propagation returns.
func requestIDOf(c *fiber.Ctx) string {
	if c == nil {
		return ""
	}
	id, err := xrequestid.Of(c.UserContext())
	if err != nil {
		return ""
	}
	return id.GetRequestId()
}

// maxLoggedValueLength bounds a caller-supplied value once it is recorded.
const maxLoggedValueLength = 256

// logSafe makes a caller-controlled string safe to record.
//
// Control characters let a caller forge whole records by injecting newlines, and
// an audit trail the audited party can write is worth nothing. The length is
// bounded here too; otherwise it is whatever the client chose to send.
func logSafe(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len() >= maxLoggedValueLength {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

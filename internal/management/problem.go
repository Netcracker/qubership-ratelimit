package management

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ProblemContentType is the media type of every error body, per RFC 9457.
const ProblemContentType = "application/problem+json"

// Error codes. A client branches on these, never on the prose: the message is
// written for a person reading a console and is free to change, the code is
// the contract.
const (
	CodeUnauthorized   = "unauthorized"
	CodeForbidden      = "forbidden"
	CodeNotFound       = "not-found"
	CodeInvalidRequest = "invalid-request"
	CodeUnsupported    = "unsupported"
	CodeInternal       = "internal"
)

// Problem is the error body. It follows RFC 9457 and adds two extensions a
// caller actually needs: code, the stable identifier to branch on, and
// requestId, the value to quote when asking why a call failed.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`

	Code      string `json:"code"`
	RequestID string `json:"requestId,omitempty"`

	// Fields names the request fields the problem is about, so a form can
	// mark them rather than showing one message over the whole dialog.
	Fields []string `json:"fields,omitempty"`
}

// problemTitles gives each code the short human title RFC 9457 asks for.
var problemTitles = map[string]string{
	CodeUnauthorized:   "Authentication required",
	CodeForbidden:      "Not authorized",
	CodeNotFound:       "Not found",
	CodeInvalidRequest: "Invalid request",
	CodeUnsupported:    "Not supported by this deployment",
	CodeInternal:       "Internal error",
}

// writeProblem sends an error body. It never reflects the request back into
// the response beyond the fields the caller named: a detail string is built
// here from values this package controls, so an attacker-supplied path cannot
// ride into a browser through an error message.
func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string, fields ...string) {
	title, ok := problemTitles[code]
	if !ok {
		title = http.StatusText(status)
	}
	body := Problem{
		Type:      "/ratelimit/v1/errors/" + code,
		Title:     title,
		Status:    status,
		Detail:    detail,
		Code:      code,
		RequestID: requestIDOf(r),
		Fields:    fields,
	}

	w.Header().Set("Content-Type", ProblemContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The body is this package's own struct, so a marshal error here would be
	// a bug rather than input. There is nothing left to say to the client
	// after the status is written, so it is dropped deliberately.
	_ = json.NewEncoder(w).Encode(body)
}

// badRequest reports a malformed or contradictory request, naming the fields
// at fault so a form can mark them.
func badRequest(w http.ResponseWriter, r *http.Request, detail string, fields ...string) {
	writeProblem(w, r, http.StatusBadRequest, CodeInvalidRequest, detail, fields...)
}

// notFound reports a domain or rule the current rule set does not carry. It
// names what was looked for, because the usual cause is a rule that exists in
// a policy the operator rejected — the object is there, the enforced rule set
// is not.
func notFound(w http.ResponseWriter, r *http.Request, what string) {
	writeProblem(w, r, http.StatusNotFound, CodeNotFound, what)
}

// internalError reports a failure of this process or its counter store. The
// cause goes to the log, never to the client: it names hosts, addresses, and
// store internals.
func internalError(w http.ResponseWriter, r *http.Request, action string) {
	writeProblem(w, r, http.StatusInternalServerError, CodeInternal,
		fmt.Sprintf("Failed to %s. Check the operator log for the cause, quoting the request id.", action))
}

package management

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	errs "github.com/netcracker/qubership-core-lib-go-error-handling/v3/errors"
	"github.com/netcracker/qubership-core-lib-go-error-handling/v3/tmf"
)

// The error catalog. A client branches on the code and never on the prose:
// reason is the code's title and constant per code, message is the detail of
// one instance and free to change.
var (
	CodeInvalidRequest = errs.ErrorCode{Code: "RLS-0400", Title: "Invalid request"}
	CodeUnauthorized   = errs.ErrorCode{Code: "RLS-0401", Title: "Authentication required"}
	CodeForbidden      = errs.ErrorCode{Code: "RLS-0403", Title: "Access denied"}
	CodeNotFound       = errs.ErrorCode{Code: "RLS-0404", Title: "Unknown resource"}
	CodeConflict       = errs.ErrorCode{Code: "RLS-0409", Title: "Conflict"}
	CodeGone           = errs.ErrorCode{Code: "RLS-0410", Title: "Confirmation token gone"}

	// CodeWorkLimit reports a sweep that ran into the server's deadline. It is
	// 422 rather than 413 because what was too large is the selection inside the
	// store, not the request body, and its recovery differs from a plain
	// failure: narrowing helps, repeating the same width does not.
	CodeWorkLimit = errs.ErrorCode{Code: "RLS-0422", Title: "Selection exceeds the synchronous work limit"}

	CodeInternal = errs.ErrorCode{Code: "RLS-0500", Title: "Internal error"}

	// CodeInterrupted is any unforeseen error that cut a command after
	// acceptance: recorded by the walker that caught it, or by the first retry
	// to find the record with a dead lease. It shares 500 with CodeInternal and
	// is told apart by the code, which is also what makes the partial
	// disclosure mandatory on this branch and impossible on the other.
	CodeInterrupted = errs.ErrorCode{Code: "RLS-0501", Title: "Command interrupted after acceptance"}

	CodeStoreDown = errs.ErrorCode{Code: "RLS-0503", Title: "Counter store unavailable"}
)

// statuses map each code to the HTTP status it is answered with. The status
// travels in the body too, so a client reading the body alone knows the class.
var statuses = map[string]int{
	CodeInvalidRequest.Code: http.StatusBadRequest,
	CodeUnauthorized.Code:   http.StatusUnauthorized,
	CodeForbidden.Code:      http.StatusForbidden,
	CodeNotFound.Code:       http.StatusNotFound,
	CodeConflict.Code:       http.StatusConflict,
	CodeGone.Code:           http.StatusGone,
	CodeWorkLimit.Code:      http.StatusUnprocessableEntity,
	CodeInternal.Code:       http.StatusInternalServerError,
	CodeInterrupted.Code:    http.StatusInternalServerError,
	CodeStoreDown.Code:      http.StatusServiceUnavailable,
}

// Conflict kinds. Every 409 carries one, so a generated client can branch on
// the recovery instead of parsing prose: each names a different next move.
const (
	// ConflictCommandMismatch: the key is bound to another command. Use a new
	// key for a new command.
	ConflictCommandMismatch = "command_mismatch"

	// ConflictStaleConfirmation: the token no longer matches this selection,
	// domain, or subject. Preview what you mean to run.
	ConflictStaleConfirmation = "stale_confirmation"

	// ConflictStaleRuleSet: the enforced set moved under the command. Re-read
	// and repeat.
	ConflictStaleRuleSet = "stale_rule_set"

	// ConflictSweepInFlight: the domain already runs a sweep. Wait out
	// Retry-After.
	ConflictSweepInFlight = "sweep_in_flight"

	// ConflictStaleIfMatch: the validator is out of date. Re-read and repeat.
	ConflictStaleIfMatch = "stale_if_match"
)

// apiError is one failure on its way to the client.
//
// It is an error a handler returns rather than a response a handler writes,
// which keeps the status, the request id, and the challenge header in one
// place. The platform's error handler calls Handle on any error that offers it,
// so this is also how the catalog's codes reach the wire in the TMF envelope
// every service of the platform answers with.
type apiError struct {
	*errs.ErrCodeError

	// fields names the request fields a validation error is about, so a form
	// can mark them instead of showing one message over the whole dialog.
	fields []string

	// conflictType names the recovery of a 409. It is mandatory there, which is
	// why nothing but a conflict may carry it.
	conflictType string

	// partialReset is the disclosure a bulk command owes when it failed after
	// acceptance: what it managed to do before it stopped. Mandatory on the
	// deadline and interrupted branches, impossible on a failure that never
	// bound anything, because that one has nothing to disclose.
	partialReset *PartialReset

	// retryAfter is the wait a conflicting sweep imposes.
	retryAfter time.Duration
}

// errorf builds an error of the given code.
func errorf(code errs.ErrorCode, message string, fields ...string) *apiError {
	return &apiError{ErrCodeError: errs.NewError(code, message, nil), fields: fields}
}

// invalid reports a request the caller got wrong, naming the fields at fault.
func invalid(message string, fields ...string) *apiError {
	return errorf(CodeInvalidRequest, message, fields...)
}

// notFound reports a domain, rule, or window the enforced set does not carry.
func notFound(message string) *apiError {
	return errorf(CodeNotFound, message)
}

// conflict reports a state the caller has to reconcile, naming which one.
func conflict(kind, message string) *apiError {
	return &apiError{
		ErrCodeError: errs.NewError(CodeConflict, message, nil),
		conflictType: kind,
	}
}

// storeDown reports a counter store that did not answer. It is never read as
// "the record is not there": unavailability and absence are different answers,
// and conflating them would let a retry repeat a destructive command.
func storeDown(message string) *apiError {
	return errorf(CodeStoreDown, message)
}

// interrupted reports a command an unforeseen error cut after acceptance, with
// what it managed to do.
func interrupted(message string, partial *PartialReset) *apiError {
	failure := errorf(CodeInterrupted, message)
	failure.partialReset = partial
	return failure
}

// workLimit reports a sweep that hit the deadline, with what it managed to do.
func workLimit(message string, partial *PartialReset) *apiError {
	failure := errorf(CodeWorkLimit, message)
	failure.partialReset = partial
	return failure
}

// withRetryAfter attaches the wait a caller should observe.
func (e *apiError) withRetryAfter(wait time.Duration) *apiError {
	e.retryAfter = wait
	return e
}

// replayOf rebuilds a recorded failure for a retry, keeping its id and its
// disclosure and taking only the request id from the current call.
func replayOf(code errs.ErrorCode, id, message string, partial *PartialReset) *apiError {
	failure := errorf(code, message)
	failure.Id = id
	failure.partialReset = partial
	return failure
}

// tmfResponse renders this error as the body it is answered with.
//
// A replay comes through here too: replayOf rebuilt the error from what the
// record kept, id included, so the failing call and every replay of it produce
// the same body apart from the request id.
func (e *apiError) tmfResponse(requestID string) *tmf.Response {
	return tmf.NewResponseBuilder(e).Status(e.status()).Meta(*e.meta(requestID)).Build()
}

// meta carries the request id of the current call, the fields a validation
// error is about, the recovery of a conflict, and the partial disclosure of a
// command that failed after acceptance.
func (e *apiError) meta(requestID string) *map[string]any {
	meta := map[string]any{"requestId": requestID}
	if len(e.fields) > 0 {
		meta["fields"] = e.fields
	}
	if e.conflictType != "" {
		meta["conflictType"] = e.conflictType
	}
	if e.partialReset != nil {
		meta["partialReset"] = e.partialReset
	}
	return &meta
}

// status is the HTTP status this error is answered with.
func (e *apiError) status() int {
	if status, known := statuses[e.GetErrorCode().Code]; known {
		return status
	}
	return http.StatusInternalServerError
}

// Handle writes the TMF envelope for this error.
//
// Every non-2xx body this service forms has this shape, so a client parses one
// thing. The request id goes into meta and into the header, so the value a
// person quotes is the value in the log. Returning nil tells the platform's
// error handler the error is answered, which also keeps it from logging a
// detail that came from the caller.
func (e *apiError) Handle(c *fiber.Ctx) error {
	status := e.status()
	if e.GetErrorCode() == CodeUnauthorized {
		// The challenge tells a client what credential to present, which is the
		// difference between a UI showing a sign-in prompt and one showing an
		// opaque failure.
		c.Set(fiber.HeaderWWWAuthenticate, "Bearer")
	}
	if e.retryAfter > 0 {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(e.retryAfter.Seconds()))))
	}
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")

	return c.Status(status).JSON(e.tmfResponse(requestIDOf(c)))
}

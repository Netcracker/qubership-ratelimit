package management

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// endpointResets scopes an Idempotency-Key used against the bulk action, so one
// key spent here and on the addressed DELETE is two bindings.
const endpointResets = "counter-resets"

// handleBulkReset runs a bulk reset: a preview that mints a confirmation token,
// or the execution that token authorizes.
//
// The order of the checks is the contract. The record is consulted first, so a
// retry of a finished execution answers what it did rather than a refusal for
// the token it consumed itself. Everything that can still refuse runs next,
// while nothing is bound. Acceptance comes last, as one write, and after it the
// command has an outcome no matter how it ends.
func (a *API) handleBulkReset(c *fiber.Ctx) error {
	snapshot, version, apiErr := a.snapshot(c)
	if apiErr != nil {
		return apiErr
	}
	idempotencyKey, apiErr := idempotencyKeyOf(c)
	if apiErr != nil {
		return apiErr
	}

	var request BulkResetRequest
	if apiErr := decodeJSON(c, &request); apiErr != nil {
		return apiErr
	}
	command, apiErr := parseBulk(snapshot.Domain, request)
	if apiErr != nil {
		return apiErr
	}

	ctx := c.UserContext()
	subject := subjectOf(c)
	keys := commandKeys(snapshot.Domain,
		recordKey(snapshot.Domain, endpointResets, subject.Name, idempotencyKey), command)

	record, err := a.Records.Lookup(ctx, keys)
	if err != nil {
		a.Log.ErrorC(ctx, "failed to read a command record error=%v", err)
		// Fail closed: an unreachable store is never read as "no record", or a
		// retry would run a destructive command a second time.
		return storeDown("the command record store did not answer; the command was not accepted")
	}
	if record.Found {
		return a.standing(c, keys, record, command)
	}

	if !command.DryRun {
		// Validated before it is consumed, so a token that names another
		// selection is refused without spending anything.
		if apiErr := a.checkToken(ctx, snapshot, version, subject, command); apiErr != nil {
			return apiErr
		}
	}
	return a.accept(c, snapshot, version, subject, command, keys, idempotencyKey)
}

// checkToken reads the confirmation token and checks what it was bound to.
//
// The binding is the whole point of the two-step: a token is permission to
// delete one selection, in one domain, as one subject, over one enforced rule
// set. A token that no longer matches means the operator confirmed something
// other than what they are now asking for.
func (a *API) checkToken(
	ctx context.Context,
	snapshot *compile.Snapshot,
	version string,
	subject Subject,
	command bulkCommand,
) *apiError {
	raw, found, err := a.Records.Get(ctx, tokenKey(snapshot.Domain, command.ConfirmationToken))
	if err != nil {
		a.Log.ErrorC(ctx, "failed to read a confirmation token error=%v", err)
		return storeDown("the command record store did not answer; the command was not accepted")
	}
	if !found {
		return errorf(CodeGone, "the confirmation token expired or was already used; run a new preview")
	}

	var token tokenDocument
	if err := json.Unmarshal(raw, &token); err != nil {
		return errorf(CodeInternal, "the confirmation token could not be read")
	}
	switch {
	case token.Domain != snapshot.Domain || token.Subject != subject.Name:
		return conflict(ConflictStaleConfirmation,
			"this confirmation token belongs to another domain or another subject")
	case token.Selection != command.selection():
		return conflict(ConflictStaleConfirmation,
			"this confirmation token was minted for a different selection; preview the one you mean to run")
	case token.RuleSetVersion != version:
		return conflict(ConflictStaleRuleSet,
			"the enforced rule set changed since the preview; run a new preview")
	}
	return nil
}

// accept binds the command and runs it.
func (a *API) accept(
	c *fiber.Ctx,
	snapshot *compile.Snapshot,
	version string,
	subject Subject,
	command bulkCommand,
	keys records.Keys,
	idempotencyKey string,
) error {
	ctx := c.UserContext()
	fencing := newFencing()

	// Acceptance is the point of no return, and one write: it consumes the
	// token, binds the key, and claims the domain's sweep lease. Anything after
	// it ends as a recorded outcome, because releasing the record would let the
	// same key run a second sweep and leave the consumed token ambiguous.
	accepted, err := a.Records.Accept(ctx, records.Acceptance{
		Keys:     keys,
		Command:  command.command(snapshot.Domain),
		Fencing:  fencing,
		LeaseTTL: leaseTTL,
	})
	if err != nil {
		a.Log.ErrorC(ctx, "failed to accept a bulk reset error=%v", err)
		// The write may or may not have landed. The client resolves it by
		// retrying the SAME key: the retry either finds the record and proceeds
		// as a retry, or finds nothing and executes first.
		return storeDown("the command record store did not answer; " +
			"retry the same Idempotency-Key, never a new one")
	}

	switch {
	case accepted.SweepBusy:
		return conflict(ConflictSweepInFlight,
			"another sweep is already running in domain "+logSafe(snapshot.Domain)+
				"; nothing was accepted, so retry after the wait").
			withRetryAfter(accepted.LeaseTTL)
	case accepted.TokenMissing:
		return errorf(CodeGone, "the confirmation token expired or was already used; run a new preview")
	case !accepted.OK:
		return a.standing(c, keys, accepted.Existing, command)
	}

	a.auditBulk(c, subject, idempotencyKey, snapshot.Domain, command)
	return a.sweep(c, snapshot, version, subject, command, keys, fencing)
}

// sweep walks the selection to its end and records what it did.
func (a *API) sweep(
	c *fiber.Ctx,
	snapshot *compile.Snapshot,
	version string,
	subject Subject,
	command bulkCommand,
	keys records.Keys,
	fencing string,
) error {
	// The walk outlives the request on purpose: a client that disconnects
	// changes nothing for an accepted command, which runs to its recorded
	// outcome either way.
	ctx, cancel := context.WithTimeout(a.backgroundContext(), leaseTTL)
	defer cancel()

	walker := a.newSweeper(snapshot, command, keys, fencing)
	deadline := a.now().Add(sweepDeadline)

	if err := walker.run(ctx, deadline); err != nil {
		return a.recordFailure(ctx, c, keys, fencing, walker, command, err)
	}

	result := walker.result(snapshot.Domain)
	outcome := records.Outcome{Progress: walker.snapshotProgress()}

	if command.DryRun {
		token, expires, apiErr := a.mintToken(ctx, snapshot.Domain, version, subject, command)
		if apiErr != nil {
			return a.recordFailure(ctx, c, keys, fencing, walker, command, apiErr)
		}
		result.ConfirmationToken, result.ConfirmationExpiresAt = token, &expires
		outcome.Token, outcome.TokenExpiresAt = token, expires
	}

	if err := a.Records.Commit(ctx, records.Commit{
		Keys: keys, Fencing: fencing, Outcome: outcome,
	}); err != nil {
		if errors.Is(err, records.ErrLeaseLost) {
			// Another hand finalized this command while the walk ran. What it
			// recorded is the truth; this call reports that rather than its own.
			return a.replayFrom(c, keys, command)
		}
		a.Log.ErrorC(ctx, "failed to record the outcome of a bulk reset error=%v", err)
		// The record stays accepted, and recovery runs on the lease: a retry
		// polls while it lives and finalizes once it expires.
		return storeDown("the counter store did not answer while recording the outcome")
	}
	return writeJSON(c, result)
}

// recordFailure writes the failure of an accepted command and answers it.
//
// The binding is never released: releasing would let the same key run a second
// sweep and leave a consumed token ambiguous. What the walk managed to do is
// disclosed instead, because a client must never learn only "failed" about a
// command that may have deleted keys.
func (a *API) recordFailure(
	ctx context.Context,
	c *fiber.Ctx,
	keys records.Keys,
	fencing string,
	walker *sweeper,
	command bulkCommand,
	cause error,
) error {
	progress := walker.snapshotProgress()
	partial := partialOf(progress, command.DryRun)

	failure := interrupted("the command was interrupted after acceptance", partial)
	if errors.Is(cause, errDeadline) {
		failure = workLimit("the selection did not finish within the server's work limit; "+
			"narrow it, or reset rule by rule", partial)
	} else {
		a.Log.ErrorC(ctx, "a bulk reset failed after acceptance error=%v", cause)
	}

	if err := a.Records.Commit(ctx, records.Commit{
		Keys:    keys,
		Fencing: fencing,
		Outcome: records.Outcome{
			Failed:   true,
			Code:     failure.GetErrorCode().Code,
			ErrorID:  failure.GetId(),
			Message:  failure.GetDetail(),
			Progress: progress,
		},
	}); err != nil {
		if errors.Is(err, records.ErrLeaseLost) {
			return a.replayFrom(c, keys, command)
		}
		// The one error a walker cannot record is the store itself failing. The
		// record stays accepted, and the lease carries the recovery.
		a.Log.ErrorC(ctx, "failed to record a failed bulk reset error=%v", err)
		return storeDown("the counter store did not answer while recording the outcome")
	}
	return failure
}

// standing answers a retry by the record's state.
//
// The record is the operation: while the sweep runs, a retry is a poll; when it
// died, a retry is what finalizes it; once it ended, a retry replays the
// outcome. None of those re-runs the command.
func (a *API) standing(
	c *fiber.Ctx,
	keys records.Keys,
	record records.Record,
	command bulkCommand,
) error {
	if record.Command != command.command(domainOf(c)) {
		return conflict(ConflictCommandMismatch,
			"this Idempotency-Key is already bound to a different command; a new command needs a new key")
	}
	if record.Terminal {
		return a.replay(c, record, command)
	}
	if record.Alive() {
		// The sweep is running. There is no body to give: come back for the
		// outcome once the lease can no longer be alive.
		c.Set(fiber.HeaderRetryAfter, retryAfterSeconds(record.LeaseTTL))
		c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
		// No body: the answer is "not yet", and the outcome is what the next
		// retry comes for.
		return c.Status(fiber.StatusAccepted).Send(nil)
	}

	// Accepted, and its lease is gone: the walker died. The first retry to see
	// this finalizes the record, atomically, against the still-empty outcome.
	finalized, err := a.Records.Finalize(c.UserContext(), records.Finalize{
		Keys: keys,
		Outcome: records.Outcome{
			Failed:  true,
			Code:    CodeInterrupted.Code,
			ErrorID: newErrorID(),
			Message: "the command was interrupted after acceptance and its worker did not return",
		},
	})
	if err != nil {
		a.Log.ErrorC(c.UserContext(), "failed to finalize an interrupted bulk reset error=%v", err)
		return storeDown("the command record store did not answer")
	}
	if !finalized.Found {
		return errorf(CodeInternal, "the record of this command disappeared while it was being read")
	}
	if !finalized.Terminal {
		// Somebody claimed the domain again between the read and the write.
		c.Set(fiber.HeaderRetryAfter, retryAfterSeconds(finalized.LeaseTTL))
		return c.Status(fiber.StatusAccepted).Send(nil)
	}
	return a.replay(c, finalized, command)
}

// replayFrom re-reads the record and answers from it, for the case where this
// call lost its lease and another hand recorded the outcome.
func (a *API) replayFrom(c *fiber.Ctx, keys records.Keys, command bulkCommand) error {
	record, err := a.Records.Lookup(c.UserContext(), keys)
	if err != nil || !record.Found || !record.Terminal {
		return storeDown("the outcome of this command could not be read back")
	}
	return a.replay(c, record, command)
}

// replay answers from a recorded outcome: the same body, or the same error
// instance, with only the request id taken from the current call.
func (a *API) replay(c *fiber.Ctx, record records.Record, command bulkCommand) error {
	outcome := record.Outcome
	if !outcome.Failed {
		return writeJSON(c, resultOf(outcome, domainOf(c), command))
	}

	code := CodeInterrupted
	if outcome.Code == CodeWorkLimit.Code {
		code = CodeWorkLimit
	}
	return replayOf(code, outcome.ErrorID, outcome.Message,
		partialOf(outcome.Progress, command.DryRun))
}

// resultOf renders a completed command's body from what the record kept. The
// request is the same canonical command, so everything else about the answer is
// a function of it.
func resultOf(outcome records.Outcome, domain string, command bulkCommand) BulkResult {
	result := BulkResult{
		Domain:    domain,
		DryRun:    command.DryRun,
		Scanned:   outcome.Progress.Scanned,
		Keys:      outcome.Progress.Keys,
		Truncated: outcome.Progress.Truncated,
		Rules:     ruleCounts(outcome.Progress.Rules, command.DryRun),
	}
	if result.Keys == nil {
		result.Keys = []string{}
	}
	if command.DryRun {
		matched := outcome.Progress.Matched
		result.MatchedCount = &matched
		result.ConfirmationToken = outcome.Token
		if !outcome.TokenExpiresAt.IsZero() {
			expires := outcome.TokenExpiresAt
			result.ConfirmationExpiresAt = &expires
		}
		return result
	}
	reset := outcome.Progress.Reset
	result.ResetCount = &reset
	return result
}

// mintToken stores what the preview looked at, so the execution can prove it is
// the same look.
func (a *API) mintToken(
	ctx context.Context,
	domain, version string,
	subject Subject,
	command bulkCommand,
) (string, time.Time, *apiError) {
	token := newConfirmationToken()
	expires := a.now().Add(confirmationTTL)

	document, err := json.Marshal(tokenDocument{
		Selection:      command.selection(),
		Domain:         domain,
		Subject:        subject.Name,
		RuleSetVersion: version,
		ExpiresAt:      expires,
	})
	if err != nil {
		return "", time.Time{}, errorf(CodeInternal, "the confirmation token could not be encoded")
	}
	if err := a.Records.Put(ctx, tokenKey(domain, token), document, confirmationTTL); err != nil {
		a.Log.ErrorC(ctx, "failed to store a confirmation token error=%v", err)
		return "", time.Time{}, storeDown("the command record store did not answer")
	}
	return token, expires, nil
}

// idempotencyKeyOf reads the mandatory key of a mutation.
func idempotencyKeyOf(c *fiber.Ctx) (string, *apiError) {
	key := c.Get("Idempotency-Key")
	if key == "" {
		return "", invalid("this mutation needs an Idempotency-Key header", "Idempotency-Key")
	}
	if !requestIDPattern.MatchString(key) {
		// The key lands in the audit journal verbatim, so it is refused rather
		// than sanitized, exactly like a request id.
		return "", invalid("the Idempotency-Key does not match "+requestIDPattern.String(),
			"Idempotency-Key")
	}
	return key, nil
}

// domainOf is the domain of the path.
func domainOf(c *fiber.Ctx) string { return c.Params("domain") }

// retryAfterSeconds renders a wait as whole seconds, never below one: a
// Retry-After of zero invites the hot loop it exists to prevent.
func retryAfterSeconds(wait time.Duration) string {
	return strconv.Itoa(max(int(wait.Seconds()), 1))
}

// newErrorID mints the id of an error instance a record keeps, so every replay
// of it carries the same one.
func newErrorID() string { return uuid.NewString() }

// auditBulk records the acceptance of a sweep: who, which key, what selection.
//
// It is written at acceptance rather than at completion, because acceptance is
// the moment the deletions became inevitable. The request id is not a field
// here: the logger takes it from the context this call carries.
func (a *API) auditBulk(
	c *fiber.Ctx,
	subject Subject,
	idempotencyKey, domain string,
	command bulkCommand,
) {
	selector := "domain-wide"
	if !command.DomainWide {
		selector = string(command.Selector.canonical())
	}

	a.Log.InfoC(c.UserContext(),
		"management mutation accepted subject=%v idempotencyKey=%v domain=%v endpoint=%v "+
			"command=%v selection=%v dryRun=%v selector=%v",
		logSafe(subject.Name), idempotencyKey, domain, endpointResets,
		command.kind(), command.selection(), command.DryRun, selector)
}

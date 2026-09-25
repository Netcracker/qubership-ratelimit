# Management API v1

The management API of the rate limit service: read the enforced state, inspect and reset live counters, and simulate a
request. Resets go through `DELETE` for the addressed form and an action resource for the bulk forms; the error format
is NC.TMFErrorResponse.v1.0 (qubership-core-lib-go-error-handling). The canonical specification is the OpenAPI document
embedded in the binary, [`service/internal/management/openapi.yaml`](../service/internal/management/openapi.yaml),
served by `GET /openapi.yaml`. Worked scenarios are in the [cookbook](management-api-cookbook.md).

## Principles

1. The API mutates runtime state only: counters, and nothing else. Configuration (limits, rules, mappings) lives in
   the CR, the GitOps path; there are no configuration write endpoints.
2. Reads never charge counters: everything goes through Peek, and the state is judged at cost=1; an arbitrary cost is
   the simulation's job (it has cost).
3. Every mutation is audited: the carrier is a structured audit journal line (request id, subject, selector, outcome)
   into the platform's log pipeline. The service writes nothing to the API server, so there is no Kubernetes Event.
4. The destructive radius is bounded by construction: DELETE addresses one rule; anything wider goes through
   counter-resets, whose execution exists only with a single-use confirmation token from a mandatory preview; the
   sweep's work is bounded server-side: a deadline plus one sweep per domain.
5. The base path /ratelimit/v1 is a security boundary: authentication is the gateway's auth extension (a bearer JWT of
   the platform IdP), and authorization is role-based RBAC in the service itself, per path+verb pair.

## Surface

| Method and path | Role | Semantics |
| --- | --- | --- |
| GET /domains | viewer | The domains of the enforced set: per-domain ruleSetVersion, sizes (blocks/rules), effectiveKeys. No pagination: domains are few. |
| `GET /domains/{d}/rules?path=&method=&axis.<n>=` | viewer | The domain's enforced set, which can be a last-good generation rather than the latest object in the cluster, plus its ruleSetVersion. `path` and `method` filter down to blocks with the engine's matcher, and `axis.<n>` annotates every rule with its applicability under a partial identity, see "Applicability for a partial identity". |
| `GET /domains/{d}/counters?<grammar>&pageSize=&cursor=` | viewer | A Peek listing over the full selector grammar plus pagination. The listing skips counters of rules outside the enforced set (scanned counts them). |
| `DELETE /domains/{d}/counters?ruleId=&axis.<n>=&algorithm=&period=&limited=&expectedRuleSetVersion=&dryRun=` | operator | The addressed form: one full ruleId plus every axis of that rule, so the keys are computed from the snapshot rather than scanned. A partial axis set is 0400, and a rule outside the enforced set is 404. Idempotency-Key is mandatory; see "Selector grammar and work bounds". |
| POST /domains/{d}/counter-resets | operator | The bulk form, a oneOf of four bodies: preview or execute, over a selector or over the whole domain. Execution accepts only a confirmationToken minted by a preview of the same selection, runs to the end inside the call, and answers 200. Idempotency-Key is mandatory. |
| POST /simulations | viewer (post on the exact path) | Body {domain, path, method, identitySource?, token?, keys?, cost?} → a Peek decision: allowed, headers, per-rule verdicts, skips, extractedKeys. Not under /domains/{d}/: one non-mutating POST path with its own verb makes the role model trivial (viewer holds post here only). |
| GET /status | viewer | Per-replica view: the replica, the snapshot swap time, ruleSetVersions {domain: version} (skew between replicas during a rollout and last-good divergence), the store backend. |
| GET /openapi.yaml | viewer | The embedded specification (go:embed): what the binary was built against. |

## Selector grammar and work bounds

A selection = rules x window x identity x state. Where it lives:

- GET /counters: the full grammar in the query: ruleId is repeatable, a one-segment value is a block prefix;
  algorithm; period (normalized, 1m == 60s); `axis.<name>`: OR within one name, AND between names, and a counter of a
  rule without the named axis never matches; limited (enum [true]).
- DELETE /counters: the addressed subset: one full ruleId plus all of the rule's axes.
- POST /counter-resets: the full grammar in the JSON body (a URL is no place for bulk); a dryRun preview;
  confirmDomain is the domain-wide form, strictly on its own.

The canonical form of a selector (the single input for the confirmation token, the cursor fingerprint, and the
Idempotency hash): ruleIds are sorted and deduplicated; axis names are sorted; values within an axis are sorted and
deduplicated; period is canonicalized to seconds; algorithm is lowercased; absent fields are absent. One canonical
selection is not yet one command: Idempotency-Key hashes the canonical COMMAND BODY (see below).

Work bounds: only the pages of the GET listing keep a scan budget; the envelope carries scanned; a page can be
incomplete in the middle of the collection, and the only end signal is a missing nextCursor. Counter-resets is bounded
server-side, not client-side: the sweep has a DEADLINE (a server constant on the order of a minute; exceeding it is a
recorded failed outcome RLS-0422 with partial disclosure, and what was deleted stands); a domain runs at most one sweep
at a time (the slot lease is claimed atomically with acceptance, its value is the command's fencing token, and it is
released by recording the outcome; it expires slightly later than the deadline; a competitor gets 409 with Retry-After
BEFORE acceptance); a client disconnect does NOT stop the sweep: an accepted command runs to its recorded outcome
(completed or the deadline 0422); the commitment is acceptance, not the connection. Each batch is one atomic script:
verify the fencing token, delete the batch, and advance the progress in the record; there is no gap between the check
and the deletion, a walker that lost its lease deletes nothing further, and the terminal outcome commits only under its
own live token. Real wide selections fit in seconds; size the client timeout for that. A cursor is bound to its
selection: it carries the fingerprint of the canonical selector and a TTL; a foreign selection or expiry is 0400, not
silently a different listing. Pages are not a snapshot: a live SCAN can skip, duplicate, or show newer numbers. /domains
is not paginated at all. A page reads the store in whole steps, each of at most the room left on the page and in the
budget, and at most 128 steps; its cursor is the store's own cursor of the next step, so the walk stays on the chain
of cursors the store returns, which is what the store's completeness is conditioned on
(the [store contract](store-contract.md)). pageSize is the size a page asks for: exact on the in-process store, and on
Redis, whose step is a hint, a few items over at most; items are unsorted.

Semantics under live traffic: a reset is NOT a snapshot. resetCount is the keys actually deleted; traffic during the
sweep creates counters independently. Fence/generation mechanics are deliberately not introduced: the price is not
justified for a "clean slate" operation. For the addressed DELETE, the record, the deletions of the computed keys, and
the outcome commit in one atomic script.

Orphans (counters of rules that left the enforced set while their keys live out their TTL): the listing skips them
(there is nothing to render them against in the snapshot; scanned counts them); bulk selectors are NOT validated against
the snapshot: ruleIds/algorithm/period parse the key itself and therefore reach orphans (a stale ruleId is not 404 but
200 with the actual, possibly zero, count), whereas axes and limited need the rule definition (the axis name mapping,
the window budgets) and see enforced counters only; an addressed DELETE on an orphan is 404. Bulk execution resolves the
selector once, at the start of the sweep.

Rule set versions: ruleSetVersion is the opaque identity of the enforced set, PER DOMAIN (other domains do not disturb a
pin). It lives in RuleSetView and DomainSummary (required), in the addressed DELETE responses (required), and in /status
as a map by domain. DELETE accepts an optional expectedRuleSetVersion (a mismatch is 409); it is optional on purpose:
the radius is bounded, and making it mandatory would duplicate the token that was rejected for the addressed form. Bulk
responses do not need the field: there the confirmationToken forcibly binds the version (a snapshot change between the
steps is 409). ETag/If-Match on /rules is rejected: it would imply a conditional GET/304; the version is a body field
and an explicit parameter.

Applicability for a partial identity (the "the client knows only its name" scenario): GET /rules with `axis.<name>`
answers two questions at once: "which rules definitely apply to this client" (applicability: always, under every
completion of the unknown keys) and "which could" (conditional, under some completion; the gates are enumerated: a
missing axis, an undecided condition, possible preemption by an earlier deciding FirstMatch rule or by replacedRules).
The engine does the analysis: the cascade semantics cannot be reproduced with jq over the view (everyone is conditional
because of premium, heavy because of gold's replacedRules). never is not hidden but marked. List-valued keys
(listValuedKeys, for example roles) are repeatable in the scope and form the COMPLETE set of values; Contains/Exists
decide against it; scalar keys take one value, and a repeat is 0400. The absent parameter declares a key KNOWN ABSENT
(an empty set, which is exactly how the engine reads Exists/DoesNotExist; for a list-valued key that is the same as "an
empty list"): DoesNotExist decides as satisfied, Exists as failed, and rules that count by such a key become never; a
key both in `axis.*` and in absent is a contradiction, 0400, and absent on its own forms a scope: the annotations
appear even without a single `axis.*`. Gates are minimal: missing_axis is not reported alongside
undecided_condition on the same
key; deciding the condition decides the axis too, and a single condition stands as the gate. The simulation remains the
fact-finding tool (a real token, a real path); applicability is its static sibling.

## Idempotency and command lifecycle

Idempotency-Key is mandatory on both mutations; the scope is (authenticated subject, domain, endpoint): another domain
or subject neither replays a foreign outcome nor raises a false conflict. The key is bound to a hash of the canonical
command body: for bulk, the command type (preview/execute x selector/domain), the domain, the canonical selector or
confirmDomain, dryRun, and confirmationToken; for DELETE, the full query command (ruleId + all axes + algorithm/period +
limited + expectedRuleSetVersion) plus dryRun, normalized by the rules of the canonical selector. The same key with a
different command is 409. A preview and its execution are different commands over one selection and must use DIFFERENT
keys. The key does not lock the counter: a repeated reset of the same selection is a new command with a new key; the old
key is only a retry of the same call, and only the client can tell these two cases apart (which is why the key is
client-generated). The key pattern is log-safe, like X-Request-Id's (the value lands in the audit journal verbatim).

Acceptance is the point of no return. Accepting the command, consuming the confirmation token (for an execution), and
binding the key is one atomic step, before the first deletion. After acceptance the record is never released: an error
after acceptance, even with zero deletions, is recorded as the command's failed outcome (otherwise the same key would
start a second sweep, and the consumed token would hang in ambiguity). Only refusals BEFORE acceptance
(400/401/403/404/409/410) leave no record; a corrected repeat is re-evaluated afresh, including with the same key.

A record has two lives: ACCEPTED (the sweep may still be running) and TERMINAL (the outcome is recorded). A retry that
finds an accepted record checks against the sweep lease, the domain slot whose value is the command's fencing token: the
lease is live and belongs to this command → the sweep is ALIVE, and the retry answers 202 with Retry-After and no body
(the record is the operation, the retry is the poll: come back for the outcome); an error caught by a live walker in the
middle of the sweep is the same RLS-0501: it records the failed outcome with the progress under its live token and
answers with it immediately (the exception is a failure of the store itself: there is nothing to record with, the call
answers 0503, the record stays accepted, and from there the lease takes over); the lease expired and there is no outcome
→ the sweep died, and the retry FINALIZES the record atomically (compare-and-set against the empty outcome) as failed
(RLS-0501, interrupted); partialReset is taken from the recorded progress and is EXACT up to the last batch that ran;
later retries replay the terminal outcome, not a limbo. Completed: 200 with the same body; failed: the recorded error
with meta.partialReset. Partial deletions may have happened, and re-execution is exactly what the point of no return
forbids. After retention the idempotency guarantee simply ends: there is no record, and the request is evaluated afresh:
a preview runs again and mints a new token, while an execution normally gets 410 (its token was consumed or expired long
ago). Do not retry across days. The record is read BEFORE the confirmation token and rule set version checks: a
completed call does not get 409/410 after the fact. A repeat of a lost preview returns the original confirmationToken
rather than minting a second one. A replay of a recorded error keeps its id (the same error instance), but
meta.requestId always names the current call: the body and the X-Request-Id header do not diverge, whatever the status.

Record retention is at least 24 hours AFTER the recorded outcome; an interrupted record without an outcome lives from
acceptance. The record state table (a retry of the same key and command):

| Record | The retry gets | Transition |
| --- | --- | --- |
| none | executed as new (refusals bind nothing) | acceptance: one atomic write |
| accepted, lease live | 202 + Retry-After, no body (the sweep is running, the retry is the poll) | the owner writes the outcome |
| accepted, lease expired | finalization: failed 0501 (interrupted) + partialReset from progress | CAS to terminal |
| terminal completed | 200 with the recorded body | TTL, 24h+ after outcome |
| terminal failed | the recorded error (422 deadline / 500+0501 interrupted) with partialReset | TTL, 24h+ after outcome |
| none (retention passed) | evaluated afresh: a preview re-runs, an execution normally 410 | - |

The asymmetry of the addressed DELETE is deliberate, and there is no "release" of the record in it any more: the whole
command is ONE atomic script (record check/binding, deletions, outcome: one transition), and intermediate states do not
exist. A server error before the store means "nothing ran, nothing bound": a clean retry executes again; a lost response
after execution is a delay, not an ambiguity: the retry finds the recorded outcome and replays it. The addressed form
has no interrupted state by construction, unlike bulk, whose sweep cannot be expressed as one script.

meta.partialReset is the partial disclosure of a bulk command that failed after acceptance, a MIRROR of the successful
response cut at the stop; a oneOf of two forms with dryRun pinned (preview: mandatory matchedCount; execution: mandatory
resetCount, in the per-rule breakdown too), with MANDATORY rules and keys (empty arrays = it failed before the first
deletion), in the first 5xx and in every replay of it, interrupted included: progress commits batch by batch together
with the deletions, so the record always knows what happened; what was deleted stands. 409 answers with the
ConflictErrorResponse schema (meta.conflictType mandatory), while 422 and the interrupted branch of 500 of an accepted
command answer with the PartialResetErrorResponse schema (meta.partialReset mandatory): the disclosure and the branching
are enforced by the schema, not by prose; an internal failure BEFORE acceptance bound nothing and has nothing to
disclose, so it stays in the default envelope. The key field in all responses is an opaque diagnostic identifier for log
correlation: the client neither parses nor constructs it, and its format is outside the compatibility contract.

## Response observability and errors

X-Request-Id is a global contract: an optional request header on every operation (outside the log-safe pattern it is
0400, without sanitizing), a mandatory header on every response (round-tripped or generated), carried through to the
log, the audit journal, and the meta.requestId of every error body. 401 is an explicit response on all operations with a
mandatory WWW-Authenticate: Bearer.

Errors are NC.TMFErrorResponse.v1.0: id (the instance UUID), code (the contract for branching), reason (the code's
title), message (detail, not a contract), status (as a string), a mandatory meta.requestId, an optional meta.fields
(validation) and meta.partialReset (the partial disclosure of a failed bulk). The code catalog:

- RLS-0400 invalid request (query/body/cursor/header patterns)
- RLS-0401 authentication required
- RLS-0403 access denied
- RLS-0404 unknown resource (domain/rule/window; per endpoint, only what the endpoint actually validates: bulk and the
  listing, the domain only; DELETE, domain/rule/window)
- RLS-0409 conflict (a stale If-Match; the same Idempotency-Key with a different canonical command; a confirmation token
  whose selection/domain/subject/rule version no longer match; a mismatched expectedRuleSetVersion; a second concurrent
  sweep of the domain, refused BEFORE acceptance with Retry-After); meta.conflictType on every 409 names the recovery:
  command_mismatch / stale_confirmation / stale_rule_set / sweep_in_flight / stale_if_match
- RLS-0410 confirmation token expired or already used
- RLS-0422 selection exceeds the synchronous work limit: the sweep hit the server deadline; a failed outcome with
  partialReset, replayed; narrow the selection or reset per rule (422, not 413: the excess is the selection inside the
  store, not the request body)
- RLS-0501 command interrupted after acceptance: ANY unforeseen error that interrupted the command after acceptance; the
  outcome is written by the live walker itself (it caught the error, recorded under its live token, and answered) or by
  a finalizing retry on the expired lease of a dead one; replayed with the recorded progress; the status is the shared
  500, and the explicit response is described as a oneOf discriminated by code: the 0501 branch requires partialReset,
  and the 0500 branch (a plain internal one, before acceptance) discloses nothing, since there is nothing to disclose
- RLS-0500 internal error
- RLS-0503 counter store unavailable (including fail-closed on the idempotency lookup when the store is unreachable:
  unavailability is never read as "no record"; a store that fails in the middle of the sweep leaves no way to record the
  outcome: the record stays accepted, and recovery runs on the lease: the retry sees 202 while the lease is live and
  finalizes 0501 after it expires; a 0503 AT THE ACCEPTANCE WRITE is ambiguous, since the write may have landed: it is
  resolved by a retry with the SAME key, never a new one)

## Simulation

Three structural forms through a oneOf by identitySource: merge (the default when the field is absent; extraction from
the token plus explicit keys on top; with neither, an anonymous simulation), token (extraction only; the keys field is
inexpressible), keys (explicit values only; the token field is inexpressible); invalid combinations are rejected by the
schema. path/method are mandatory (the gateway always has them; matching without them is undefined). token is writeOnly
(≤8KiB): not echoed, not logged, and not quoted in errors. The response is a best-effort verdict as of evaluatedAt:
Peek reserves nothing.

The binding window and the response forms: RuleOutcome and Headers carry the algorithm + periodSeconds of
the window whose numbers are shown. The choice is deterministic, in strict priority: windows with capacity_exceeded rank
above any retryable refusals (a fundamental impossibility binds harder than a wait; retryAfterSeconds is undefined for
them, so among them the tie-break is immediately lexicographic by key); then retryable refusals by the largest
retryAfterSeconds; on an admission, the window with the smallest absolute remaining; a tie goes to the lexicographically
smaller counter key (which orders by block/rule, algorithm, and period, the same on every replica). Headers chooses
among all applied enforcing windows (shadow does not bind the headers), RuleOutcome among the windows of its own rule.
Contradictory combinations are inexpressible by the schema: SimulationResponse = oneOf {Admitted, RateLimited,
CapacityExceeded}; RuleOutcome is split by a oneOf on the verdict and refusalReason (rate_limited:
retryAfterSeconds is mandatory; capacity_exceeded: the field is inexpressible); Headers is split into
Admitted/RateLimited/CapacityExceeded. Only enforcing windows set refusalReason; shadow never does (their reasons live
in their own outcomes). Per-window outcomes are a possible v1.x extension, not v1.

A single mode vocabulary: enforce | shadow | bypass in all runtime views (lowercase); RuleView.mode is the rule's CR
behavior lowercased (Enforce/Shadow/Bypass → enforce/shadow/bypass), while BlockView.mode mirrors the CR's block mode
(All/FirstMatch), as RouteView.type does, since configuration views keep the configuration vocabulary. ConditionView is
five named forms with a discriminator by operator: Equals/Contains (a single value), In (values; a compiled InGroup
with the group resolved renders here too), Exists/DoesNotExist are unary, and a stray parameter is inexpressible by
the schema (a mirror of the engine's operatorArity); Contains is element membership in a list-valued claim, never a
substring; values are strings. periodSeconds is canonical, period is a derived display form; windowless algorithms
arrive only with a new API version.

## Security

Authentication is at the perimeter: the gateway's auth extension validates the bearer JWT of the platform IdP
(signature, expiry, issuer); unauthenticated traffic does not reach the service, and the service's ingress is restricted
to the gateway by a mesh policy. Authorization is in the service itself, and its trust boundary is explicit: identity is
read FROM EXACTLY ONE source, the bearer token in Authorization, whose signature the gateway has already verified; no
auxiliary identity headers (X-Forwarded-User and the like) are ever read, so there is nothing to forge. The safety of
this unverified read is a DEPLOYMENT REQUIREMENT, not an assumption: the mesh must restrict the service's ingress to the
gateway; a deployment that cannot do so must enable signature verification in the service itself. RLS applies the role
model per path+verb pair. The role model: viewer gets all GETs plus POST /simulations; operator gets the mutations
(DELETE /counters, POST /counter-resets) plus everything viewer has. The canonical names are viewer/operator; the
mapping to the actual IdP roles and claim names (subject, roles) is deployment configuration. The service needs the
subject unconditionally: the audit journal, the Idempotency-Key scope (subject, domain, endpoint), and the confirmation
token binding. A request without a bearer token is 401 (a TMF body), but that is hygiene, not protection: the service
does not verify signatures, and with a broken ingress requirement a forged token would pass; the model's security rests
on the requirement itself (or on in-service validation where the mesh does not provide it); an invalid token is normally
rejected earlier, at the gateway, in the perimeter's format. The management API has no cluster-scoped Kubernetes objects
at all. Roles are not narrowed to axis values: a viewer holder sees the values (client id) by design, a documented
property of the access model. Axis values and the Idempotency-Key land in the log verbatim, hence the log-safe patterns.

## What the API does not do

- **No negation in selectors** ("all except X"): enumerate the values.
- **No cross-domain calls**: domains are few, and there are no commands that span them; one call per domain.
- **No patterns in axis values** (`axis.path=/api/*`).
- **No what-if with changed limits**: that is what a rule's `Shadow` behavior in the CR is for.
- **No decision history**: metrics plus a sampled log answer "what happened"; the API reads live state.
- **No expansion from client to tenant**: that is the IdP's boundary, and the keys carry no such linkage.
- **No masking of axis values**: whoever holds `viewer` sees client ids, a documented property of the access model, and
  a reset requires the exact value anyway.
- **No sorting by "top consumers"**: metrics provide the aggregates.
- **No fence or generation on a reset**: a reset is not a snapshot, and the price of making it one is not justified for
  a "clean slate" operation.
- **No asynchronous submission mode for bulk** (202 intake, an operations resource, polling): an accepted command can
  outlive the client connection, but it is always run to its outcome inside the call.
- **No per-subject command budget**: the protection against a flood of commands is the one-sweep-per-domain slot, which
  answers 409, not a rate limit on the management plane itself.
- **"Who reset what"** is answered by the audit journal, read the standard way, not by an endpoint.

## How it works

- **Peek.** Every read goes through the engine's `Peek` facade: the same pipeline as `Decide`, but `store.Peek` charges
  nothing; the `ErrTooManyBuckets` backstop applies the same way. For `refusalReason` the facade computes a per-rule
  `CostExceedsCapacity` and a deterministic priority.
- **ruleSetVersion** identifies the enforced set of one domain. Every replica serving that set reports the same value,
  the value survives a restart, and it changes when the set changes: the blocks, rules, routes, conditions, windows,
  and effective keys that `GET /rules` renders. Editing a policy's annotations, changing another domain, or asking for
  applicability annotations leaves it alone, and a domain running on last-good reports the version of the set it is
  actually serving. Treat the value as opaque: compare it, and pin it with `expectedRuleSetVersion`, but do not parse
  or recompute it. The service computes it once, at the snapshot swap, so the decision path hashes nothing.
- **Bulk is always synchronous**: the selection is swept to the end inside the call, one code path (SCAN in batches plus
  UNLINK; a domain is one slot). The bounds are server-side rather than client knobs: the sweep deadline (a constant on
  the order of a minute; exceeding it is a recorded failed outcome RLS-0422 with partialReset) and the one-sweep-per-
  domain slot, claimed in the same acceptance Lua script (the slot key expires slightly later than the deadline and is
  released by recording the outcome; a competitor gets 409 before acceptance, with nothing bound). A client disconnect
  does not stop the sweep: an accepted command runs to its outcome, and the progress (scanned, resetCount, the per-rule
  breakdown, the key sample) lives in the record, advanced by the same batch script that deletes. The terminal outcome
  and the finalization are a compare-and-set under the live fencing token. Only the listing pages keep a scan budget.
  The addressed DELETE stays outside the sweeps: the record check and binding, the deletions of the computed keys, and
  the outcome are one Lua script, with no intermediate states.
- **Command storage.** Idempotency records and confirmation tokens live in the counter store itself, so fate sharing is
  total: losing the store zeroes both the counters and the records, and a re-executed reset over emptiness is harmless.
  Bulk acceptance (consume the token, bind the key, create the record, claim the sweep slot) is one Lua script; the
  outcome is appended to the record when the sweep completes and releases the slot. A retry of an accepted record
  checks against the lease: live means 202 with Retry-After (the retry is the poll), expired means finalization as
  interrupted by a compare-and-set against the empty outcome; the walker verifies the slot's fencing token on every
  SCAN batch. Retention is the native EXPIRE: the TTL is set at acceptance and refreshed by recording the outcome, and
  an interrupted record expires from acceptance, so no janitor is needed. An unreachable store on lookup is 0503,
  fail-closed.
- **Store requirements against partial state loss.** Eviction is forbidden (`maxmemory-policy=noeviction`): records and
  counters are correctness state, not a cache, and memory pressure must surface as a write failure rather than as a
  silently lost key after which a retry would repeat a destructive sweep. Acceptance is one atomic write in one slot,
  so the token and the record cannot be lost separately; after a failover the residual window is only the unreplicated
  acceptances, and a deployment can close it by requiring replica acknowledgement (`WAIT`) on the acceptance write.
- **Sharding by domain.** The record scope (subject, domain, endpoint) contains the domain, and there are no
  cross-domain commands, so records and tokens carry the same `{ns/domain}` hash tag as the counters: one slot,
  single-slot Lua legal on a cluster, and the independence of records between domains is the physical layout.
- **The in-memory store is single-replica by definition** (tests and the developer loop, a service started without
  `--redis-dbaas-microservice`): the chart never renders it, since every replica it installs reads its DBaaS database,
  and the service warns when it serves the management API over it, so the "the store is shared" assumption is never
  silent.
  Bulk still works fully there, since preview and execution are one pod.
- **The applicability evaluator** statically evaluates a rule against a partial identity: conditions over the supplied
  values (groups are resolved by compilation), availability of the counting axes (a block's captures are present for any
  request that reached a `Template` route), FirstMatch preemption (shadow does not decide, bypass cuts off), and
  `replacedRules`. Its property: `applicability: always` holds exactly when every simulation with a completed identity
  applies the rule, and `never` exactly when none does.
- **The identity middleware** takes the subject and the roles from the token the gateway forwarded, without
  cryptographic validation (trust through the mesh; validation is the auth extension's); the claim names are
  configurable, and without an identity the request fails closed with 401.
- **The OpenAPI document is embedded in the binary** (`go:embed`) and served by `GET /openapi.yaml`; a test checks the
  registered routes against the spec.
- **Deployment.** The API lives on the service, on a port of its own behind an AuthorizationPolicy that admits the
  private gateway alone ([chart](helm-chart.md)); the counters, the enforced set, and the command records are its
  state. The actual IdP role and claim names are deployment configuration, the chart values `management.claims` and
  `management.roles`.

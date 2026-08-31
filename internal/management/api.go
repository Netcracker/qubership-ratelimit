package management

import (
	"context"
	_ "embed"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/match"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/records"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// BasePath prefixes every endpoint.
//
// It deliberately does not start with /api. Kubernetes ships a ClusterRole
// named system:discovery that grants get on /api/* to the group
// system:authenticated, and it is bound by default, so an API served under
// /api/v1/... is readable by every identity a cluster recognizes, whatever this
// chart's roles say. The prefix is a security boundary, not a matter of taste.
const BasePath = "/ratelimit/v1"

// Endpoint names scope an Idempotency-Key, so one key used against two
// endpoints is two bindings rather than a false conflict.
const endpointCounters = "counters"

// specification is the API's own OpenAPI document, embedded at build time: what
// GET /openapi.yaml serves is what this binary was built against, not a copy
// that can drift. A test holds the routes below and the paths in it together.
//
//go:embed openapi.yaml
var specification []byte

// API serves the management endpoints.
type API struct {
	// Rules is the enforced rule set, the same value the decision path reads.
	Rules *store.Store

	// Counters is the store the engines count in.
	Counters counters.Store

	// Records binds Idempotency-Keys to the commands that claimed them.
	Records records.Store

	// Claims names the token claims the subject and its roles are read from;
	// the zero value uses DefaultClaimNames.
	Claims ClaimNames

	// Replica names this pod for the status endpoint and for the operations it
	// owns; empty falls back to POD_NAME and then the hostname.
	Replica string

	// CounterBackend describes where the counters live, in the words the
	// startup line uses.
	CounterBackend string

	// Now is the clock, injectable for tests; nil means time.Now.
	Now func() time.Time

	// Log is the platform logger. Its context-carrying methods are what put the
	// request id beside every line: propagation resolved it before the handler
	// ran, and the formatter reads it from the same context, so no handler has
	// to pass the id by hand.
	Log Logger

	mu      sync.Mutex
	basectx context.Context
}

// Logger is the part of the platform logger this package needs. The
// context-carrying methods are the whole point: the request id, the tenant, and
// the rest of the propagated fields come from the context they are given.
type Logger interface {
	DebugC(ctx context.Context, format string, args ...any)
	InfoC(ctx context.Context, format string, args ...any)
	ErrorC(ctx context.Context, format string, args ...any)
}

// DomainList is the domain index. Domains are few by design, so it is not
// paginated.
type DomainList struct {
	Items []ruleview.DomainSummary `json:"items"`
}

// Register mounts the endpoints on a router of the platform's Fiber app.
//
// The middleware order is the order the concerns have to happen in: a request
// id first, so everything after it can be correlated and every error body can
// name it; recovery next, so a panic in any later layer is still answered; then
// identity, immediately in front of the handlers, so nothing routed can be
// reached without a subject to audit the call against.
func (a *API) Register(router fiber.Router) {
	claims := a.Claims
	if claims.Subject == "" {
		claims = DefaultClaimNames
	}

	group := router.Group(BasePath)
	group.Use(withRequestID)
	group.Use(recover.New())
	group.Use(withIdentity(claims))

	group.Get("/domains", requireRole(RoleViewer, a.handleDomains))
	group.Get("/domains/:domain/rules", requireRole(RoleViewer, a.handleRules))
	group.Get("/domains/:domain/counters", requireRole(RoleViewer, a.handleCounters))
	group.Delete("/domains/:domain/counters", requireRole(RoleOperator, a.handleReset))
	group.Post("/domains/:domain/counter-resets", requireRole(RoleOperator, a.handleBulkReset))
	group.Post("/simulations", requireRole(RoleViewer, a.handleSimulation))
	group.Get("/status", requireRole(RoleViewer, a.handleStatus))
	group.Get("/openapi.yaml", requireRole(RoleViewer, a.handleSpecification))

	// A route under this prefix that nothing serves gets the same error shape
	// as everything else, so a client only ever parses one.
	group.Use(func(c *fiber.Ctx) error {
		return notFound("no endpoint serves " + c.Method() + " on this path")
	})
}

// handleDomains reports every domain the enforced set carries.
func (a *API) handleDomains(c *fiber.Ctx) error {
	ruleSet := a.Rules.Load()
	items := make([]ruleview.DomainSummary, 0, ruleSet.Len())
	for _, domain := range ruleSet.Domains() {
		snapshot := ruleSet.Snapshot(domain)
		if snapshot == nil {
			continue
		}
		items = append(items, ruleview.Summary(snapshot, ruleSet.Version(domain)))
	}
	return writeJSON(c, DomainList{Items: items})
}

// handleRules reports the rule set the domain's engine is deciding with,
// filtered to a request and annotated for a partial identity when the caller
// asks for either.
func (a *API) handleRules(c *fiber.Ctx) error {
	snapshot, version, apiErr := a.snapshot(c)
	if apiErr != nil {
		return apiErr
	}

	query := queryValues(c)
	path, method := query.Get("path"), query.Get("method")
	if path == "" && method != "" {
		// A method alone does not name a request, and answering the unfiltered
		// set would look like the filter had been applied.
		return invalid("method filters a route match and is meaningful only with path", "method")
	}

	sc, apiErr := parseScope(snapshot, query)
	if apiErr != nil {
		return apiErr
	}

	view := ruleview.RuleSetView{
		Domain:         snapshot.Domain,
		RuleSetVersion: version,
		EffectiveKeys:  snapshot.EffectiveKeys,
		ListValuedKeys: ruleview.ListValuedKeys(snapshot),
		Blocks:         make([]ruleview.BlockView, 0, len(snapshot.Blocks)),
	}
	if view.EffectiveKeys == nil {
		view.EffectiveKeys = []string{}
	}

	for _, block := range selectBlocks(snapshot, path, method) {
		rendered := ruleview.Block(block)
		if sc.present {
			annotate(block, &rendered, sc)
		}
		view.Blocks = append(view.Blocks, rendered)
	}
	return writeJSON(c, view)
}

// selectBlocks filters the snapshot to the blocks targeting one request, using
// the engine's own route matcher: a second implementation of segment-based
// prefixes and template captures is exactly where a filter drifts from what is
// enforced.
func selectBlocks(snapshot *compile.Snapshot, path, method string) []*compile.Block {
	if path == "" {
		out := make([]*compile.Block, 0, len(snapshot.Blocks))
		for i := range snapshot.Blocks {
			out = append(out, &snapshot.Blocks[i])
		}
		return out
	}
	return match.Match(snapshot, path, method).Blocks()
}

// handleCounters lists live counters without charging them.
func (a *API) handleCounters(c *fiber.Ctx) error {
	snapshot, _, apiErr := a.snapshot(c)
	if apiErr != nil {
		return apiErr
	}

	query := queryValues(c)
	sel, apiErr := parseSelector(query)
	if apiErr != nil {
		return apiErr
	}
	pageSize, apiErr := parsePageSize(query.Get("pageSize"))
	if apiErr != nil {
		return apiErr
	}

	now := a.now()
	after := ""
	if raw := query.Get("cursor"); raw != "" {
		after, apiErr = decodeCursor(raw, sel, now)
		if apiErr != nil {
			return apiErr
		}
	}

	list, apiErr := a.listCounters(c.UserContext(), snapshot, sel, pageSize, after, now)
	if apiErr != nil {
		return apiErr
	}
	return writeJSON(c, list)
}

// handleReset drops the counter state of one addressed rule.
func (a *API) handleReset(c *fiber.Ctx) error {
	snapshot, version, apiErr := a.snapshot(c)
	if apiErr != nil {
		return apiErr
	}

	idempotencyKey, apiErr := idempotencyKeyOf(c)
	if apiErr != nil {
		return apiErr
	}

	command, apiErr := parseReset(snapshot, queryValues(c))
	if apiErr != nil {
		return apiErr
	}
	if command.ExpectedVersion != "" && command.ExpectedVersion != version {
		return conflict(ConflictStaleRuleSet,
			"the enforced rule set is now "+version+", not the "+logSafe(command.ExpectedVersion)+
				" this call pinned; re-read the rules and repeat the command")
	}

	// Everything above can refuse without binding anything: a corrected repeat
	// re-evaluates cleanly, with the same key if the client wants.
	subject := subjectOf(c)
	name := recordKey(snapshot.Domain, endpointCounters, subject.Name, idempotencyKey)

	response, apiErr := a.runReset(c.UserContext(), snapshot, version, command, name)
	if apiErr != nil {
		a.auditReset(c, subject, idempotencyKey, snapshot.Domain, command, nil, apiErr)
		return apiErr
	}
	a.auditReset(c, subject, idempotencyKey, snapshot.Domain, command, &response, nil)
	return writeJSON(c, response)
}

// handleSimulation judges one request without charging anything.
func (a *API) handleSimulation(c *fiber.Ctx) error {
	var request SimulationRequest
	if apiErr := decodeJSON(c, &request); apiErr != nil {
		return apiErr
	}
	if apiErr := request.validate(); apiErr != nil {
		return apiErr
	}

	response, apiErr := a.simulate(c.UserContext(), request)
	if apiErr != nil {
		return apiErr
	}
	return writeJSON(c, response)
}

// auditReset writes the audit record of one mutation.
//
// The journal is the primary carrier: who called, which key they used, what they
// addressed, and what came of it, in one line the platform's log pipeline
// collects. The request id is not among the fields because the logger puts it
// there from the context. Caller-supplied values are recorded verbatim, which is
// why they had to pass a log-safe pattern to get here.
func (a *API) auditReset(
	c *fiber.Ctx,
	subject Subject,
	idempotencyKey, domain string,
	command resetCommand,
	response *ResetResponse,
	failure *apiError,
) {
	outcome, count := "failed", 0
	switch {
	case failure != nil:
		outcome = "failed " + failure.GetErrorCode().Code
	case response != nil && response.ResetCount != nil:
		outcome, count = "reset", *response.ResetCount
	case response != nil && response.MatchedCount != nil:
		outcome, count = "previewed", *response.MatchedCount
	}

	a.Log.InfoC(c.UserContext(),
		"management mutation subject=%v idempotencyKey=%v domain=%v endpoint=%v ruleId=%v axes=%v dryRun=%v outcome=%v count=%v",
		logSafe(subject.Name), idempotencyKey, domain, endpointCounters,
		command.Selector.RuleIDs[0], command.AxesByName, command.DryRun, outcome, count)
}

// snapshot resolves the domain of the path to the set being enforced.
func (a *API) snapshot(c *fiber.Ctx) (*compile.Snapshot, string, *apiError) {
	domain := c.Params("domain")
	ruleSet := a.Rules.Load()
	snapshot := ruleSet.Snapshot(domain)
	if snapshot == nil {
		return nil, "", notFound("domain " + logSafe(domain) + " is not in the enforced rule set")
	}
	return snapshot, ruleSet.Version(domain), nil
}

// parsePageSize bounds one page. A page can still be shorter than asked when
// the scan budget fills first, so the size is an upper bound and never a
// promise.
func parsePageSize(raw string) (int, *apiError) {
	if raw == "" {
		return defaultPageSize, nil
	}
	size, err := strconv.Atoi(raw)
	if err != nil || size < 1 {
		return 0, invalid("the pageSize must be a positive whole number", "pageSize")
	}
	if size > maxPageSize {
		return 0, invalid("the pageSize is at most "+strconv.Itoa(maxPageSize), "pageSize")
	}
	return size, nil
}

// handleSpecification serves the embedded document.
func (a *API) handleSpecification(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "application/yaml")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	return c.Status(fiber.StatusOK).Send(specification)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// StartBackground gives the API the context an accepted sweep runs under: the
// process's lifetime, not the request's. A client that disconnects changes
// nothing for a command that was already accepted — it runs to a recorded
// outcome either way — and only shutdown ends it early.
func (a *API) StartBackground(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.basectx = ctx
}

// backgroundContext is what an accepted sweep runs under.
func (a *API) backgroundContext() context.Context {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.basectx == nil {
		return context.Background()
	}
	return a.basectx
}

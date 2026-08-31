package management

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// The bulk reset: everything the addressed DELETE refuses to do.
//
// A sweep cannot compute its keys, so it scans, and a scan deserves a preview,
// a work budget, and an explicit body. The two-step is enforced by
// construction: an execution runs only from a confirmation token minted by a
// preview of the same normalized selection, because a bare algorithm or period
// filter is a near-domain-wide deletion and deserves the same ceremony as
// naming the domain out loud.
//
// The work is bounded by the server, not by the client's patience. A sweep runs
// synchronously to its end under a deadline; there is no submission mode, no
// operation to poll, and no handle to lose. What a client holds instead is the
// Idempotency-Key, and the record behind it answers every retry.

// confirmationTTL is how long a preview's token stays usable. It is short on
// purpose: the token says "I looked", and a look from an hour ago is not a look.
const confirmationTTL = 10 * time.Minute

// sweepDeadline bounds one walk. Real selections finish in seconds — a domain
// is one store slot — so hitting this means the selection was wider than the
// synchronous contract admits, which is a different failure from a defect and
// carries its own code.
const sweepDeadline = time.Minute

// leaseTTL outlives the deadline, so a lease expires only once the walk it
// protects can no longer be running. A retry that finds an expired lease may
// therefore conclude the walker is dead without racing it.
const leaseTTL = sweepDeadline + 15*time.Second

// keySampleLimit bounds the key list an answer carries. The counts are always
// exact; the sample is there to recognize what was swept, and no client
// benefits from being handed a hundred thousand keys.
const keySampleLimit = 100

// BulkResetRequest is the body of the counter-resets action: exactly one of four
// shapes, preview or execute, by selector or domain-wide.
type BulkResetRequest struct {
	Selector *SelectorBody `json:"selector,omitempty"`

	// ConfirmDomain is the domain-wide selection. It must equal the domain in
	// the path and stand alone: combining it with narrowing selectors is a
	// confused call, and this is the single deliberate way to reset a domain.
	ConfirmDomain string `json:"confirmDomain,omitempty"`

	// DryRun marks a preview. Only true exists: a command is either the preview
	// or the execution, never an ambiguous explicit false.
	DryRun *bool `json:"dryRun,omitempty"`

	// ConfirmationToken is what proves the look happened.
	ConfirmationToken string `json:"confirmationToken,omitempty"`
}

// SelectorBody is the selection grammar as a JSON body. A bulk selection can
// carry a thousand client ids, which is not something a URL should hold.
type SelectorBody struct {
	RuleIDs   []string            `json:"ruleIds,omitempty"`
	Algorithm string              `json:"algorithm,omitempty"`
	Period    string              `json:"period,omitempty"`
	Axes      map[string][]string `json:"axes,omitempty"`
	Limited   *bool               `json:"limited,omitempty"`
}

// BulkResult is what a completed bulk command answers with, as a preview or as
// an execution. It is not a consistent snapshot: counts are keys actually
// matched or deleted, and traffic during the sweep creates counters
// independently.
type BulkResult struct {
	Domain string `json:"domain"`

	DryRun bool `json:"dryRun"`

	// Scanned is how many keys the sweep examined, which a narrow filter over a
	// busy domain makes much larger than what it matched.
	Scanned int `json:"scanned"`

	// Keys is a sample bounded by keySampleLimit; Truncated says it was cut.
	Keys      []string `json:"keys"`
	Truncated bool     `json:"truncated,omitempty"`

	// Rules is the complete per-rule breakdown: its counts sum to the total.
	Rules []BulkRuleCount `json:"rules"`

	// MatchedCount answers a preview and ResetCount an execution.
	MatchedCount *int `json:"matchedCount,omitempty"`
	ResetCount   *int `json:"resetCount,omitempty"`

	// ConfirmationToken and ConfirmationExpiresAt are minted by a preview and
	// are what the execution step presents.
	ConfirmationToken     string     `json:"confirmationToken,omitempty"`
	ConfirmationExpiresAt *time.Time `json:"confirmationExpiresAt,omitempty"`
}

// BulkRuleCount is one rule's share of a sweep.
type BulkRuleCount struct {
	RuleID string `json:"ruleId"`

	MatchedCount *int `json:"matchedCount,omitempty"`
	ResetCount   *int `json:"resetCount,omitempty"`
}

// PartialReset is what a bulk command that failed after acceptance discloses:
// the same facts a completed answer carries, cut at the stop.
//
// It is mandatory on those failures and on every replay of them. Progress
// commits batch by batch together with the deletions it counts, so the record
// always knows what happened, and zeroes with empty arrays mean the failure
// preceded the first deletion.
type PartialReset struct {
	DryRun bool `json:"dryRun"`

	Scanned int `json:"scanned"`

	MatchedCount *int `json:"matchedCount,omitempty"`
	ResetCount   *int `json:"resetCount,omitempty"`

	Rules []BulkRuleCount `json:"rules"`

	Keys      []string `json:"keys"`
	Truncated bool     `json:"truncated,omitempty"`
}

// bulkCommand is a validated bulk request.
type bulkCommand struct {
	// Selector is the canonical selection; DomainWide marks the form that names
	// the domain instead.
	Selector   selector
	DomainWide bool

	DryRun            bool
	ConfirmationToken string
}

// selection identifies what a command deletes, which is what a confirmation
// token is bound to: two spellings of one selection are one selection, and the
// domain-wide form is its own.
func (c bulkCommand) selection() string {
	if c.DomainWide {
		return "domain"
	}
	return c.Selector.fingerprint()
}

// command hashes the canonical command body: the type, the selection, dryRun,
// and the token. Two bodies with one canonical selector are one selection but
// not necessarily one command, since a preview and its execution differ here,
// which is why they need different keys.
func (c bulkCommand) command(domain string) string {
	payload := struct {
		Kind          string   `json:"kind"`
		Domain        string   `json:"domain"`
		Selector      selector `json:"selector"`
		ConfirmDomain string   `json:"confirmDomain,omitempty"`
		DryRun        bool     `json:"dryRun,omitempty"`
		Token         string   `json:"confirmationToken,omitempty"`
	}{
		Kind:     c.kind(),
		Domain:   domain,
		Selector: c.Selector,
		DryRun:   c.DryRun,
		Token:    c.ConfirmationToken,
	}
	if c.DomainWide {
		payload.ConfirmDomain = domain
	}

	buf, err := json.Marshal(payload)
	if err != nil {
		panic("management: the bulk command failed to marshal: " + err.Error())
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// kind names the command's shape, so a preview and an execution of one
// selection hash differently even before dryRun is considered.
func (c bulkCommand) kind() string {
	form := "selector"
	if c.DomainWide {
		form = "domain"
	}
	step := "execute"
	if c.DryRun {
		step = "preview"
	}
	return step + "-" + form
}

// parseBulk validates a body into a command.
//
// The four shapes are checked here rather than trusted from the schema: a body
// that matches none of them, or one that mixes the domain-wide form with
// narrowing selectors, is a confused call and is refused instead of being
// interpreted generously.
func parseBulk(domain string, request BulkResetRequest) (bulkCommand, *apiError) {
	command := bulkCommand{ConfirmationToken: request.ConfirmationToken}

	if request.DryRun != nil {
		if !*request.DryRun {
			return bulkCommand{}, invalid(
				"the only value of dryRun is true; omit the field to execute", "dryRun")
		}
		command.DryRun = true
	}
	if command.DryRun && request.ConfirmationToken != "" {
		return bulkCommand{}, invalid(
			"a preview mints a confirmation token; it does not take one", "confirmationToken")
	}
	if !command.DryRun {
		switch {
		case request.ConfirmationToken == "":
			return bulkCommand{}, invalid(
				"an execution needs the confirmationToken from a preview of this same selection; "+
					"run the preview first with dryRun=true", "confirmationToken")
		case !confirmationTokenPattern.MatchString(request.ConfirmationToken):
			return bulkCommand{}, invalid(
				"the confirmationToken is not a token this API mints", "confirmationToken")
		}
	}

	switch {
	case request.ConfirmDomain != "" && request.Selector != nil:
		return bulkCommand{}, invalid(
			"confirmDomain is the domain-wide selection and stands alone; it does not combine with a selector",
			"confirmDomain")

	case request.ConfirmDomain != "":
		if request.ConfirmDomain != domain {
			return bulkCommand{}, invalid("confirmDomain "+logSafe(request.ConfirmDomain)+
				" does not match the path domain "+logSafe(domain), "confirmDomain")
		}
		command.DomainWide = true
		return command, nil

	case request.Selector != nil:
		sel, apiErr := request.Selector.parse()
		if apiErr != nil {
			return bulkCommand{}, apiErr
		}
		command.Selector = sel
		return command, nil

	default:
		return bulkCommand{}, invalid(
			"the body names no selection: give a selector, or confirmDomain for the domain-wide form")
	}
}

// parse turns a selector body into the canonical selection, with the same
// normalization the query grammar uses. Without one normalization for both, a
// cursor and a token would disagree about what "the same selection" means.
func (s *SelectorBody) parse() (selector, *apiError) {
	out := selector{}

	for _, id := range s.RuleIDs {
		if apiErr := checkRuleIDForm(id); apiErr != nil {
			return selector{}, apiErr
		}
	}
	out.RuleIDs = sortedUnique(s.RuleIDs)

	if s.Algorithm != "" {
		out.Algorithm = strings.ToLower(s.Algorithm)
	}
	if s.Period != "" {
		seconds, apiErr := parsePeriod(s.Period)
		if apiErr != nil {
			return selector{}, apiErr
		}
		out.PeriodSeconds = seconds
	}
	if s.Limited != nil {
		if !*s.Limited {
			return selector{}, invalid(
				"the only value of limited is true; omit the field instead", "selector.limited")
		}
		out.LimitedOnly = true
	}

	for name, values := range s.Axes {
		if name == "" {
			return selector{}, invalid("an axis in selector.axes needs a name", "selector.axes")
		}
		if len(values) == 0 {
			return selector{}, invalid("axis "+logSafe(name)+" carries no values; omit it instead",
				"selector.axes")
		}
		if slices.Contains(values, "") {
			return selector{}, invalid("axis "+logSafe(name)+
				" has an empty value, which addresses no counter", "selector.axes")
		}
		if out.Axes == nil {
			out.Axes = map[string][]string{}
		}
		out.Axes[name] = sortedUnique(values)
	}

	if len(out.RuleIDs) == 0 && out.Algorithm == "" && out.PeriodSeconds == 0 &&
		len(out.Axes) == 0 && !out.LimitedOnly {
		return selector{}, invalid(
			"the selector names nothing; use confirmDomain for the domain-wide form", "selector")
	}
	return out, nil
}

// tokenDocument is what a confirmation token stands for. The token is bound to
// all of it: a token is permission to delete one selection, in one domain, as
// one subject, over one enforced rule set, not permission to delete.
type tokenDocument struct {
	Selection      string    `json:"selection"`
	Domain         string    `json:"domain"`
	Subject        string    `json:"subject"`
	RuleSetVersion string    `json:"ruleSetVersion"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

// confirmationTokenPattern is the shape this API mints. A value outside it was
// never a token of ours, which is a malformed request rather than a look that
// went stale: the client mistyped something, and telling them "expired" would
// send them to run a preview they already ran.
var confirmationTokenPattern = regexp.MustCompile(`^ct-[0-9a-f]{12}$`)

// newConfirmationToken mints an opaque single-use token.
func newConfirmationToken() string { return "ct-" + randomID() }

// newFencing mints the token a sweep stamps on every write it makes. It is the
// lease's value, which is what lets a batch prove it still owns the domain.
func newFencing() string { return randomID() + randomID() }

func randomID() string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("management: the system random source failed: " + err.Error())
	}
	return hex.EncodeToString(buf[:])
}

// Storage keys. They carry the domain's hash tag for the same reason counter
// keys do: one slot per domain is what lets an acceptance, and every batch after
// it, be one atomic write over the record, the lease, and the counters together.
func tokenKey(domain, token string) string {
	return "rlm:v1:{" + domain + "}:ct:" + token
}

// leaseKey is the domain's sweep slot: one sweep at a time, by construction.
func leaseKey(domain string) string {
	return "rlm:v1:{" + domain + "}:sweep"
}

// commandKeys names everything one bulk command touches.
func commandKeys(domain, record string, command bulkCommand) records.Keys {
	keys := records.Keys{Record: record, Lease: leaseKey(domain)}
	if !command.DryRun {
		keys.Token = tokenKey(domain, command.ConfirmationToken)
	}
	return keys
}

// progressOf renders a sweep's committed progress as the disclosure a failed
// command owes.
func partialOf(progress records.Progress, dryRun bool) *PartialReset {
	partial := &PartialReset{
		DryRun:    dryRun,
		Scanned:   progress.Scanned,
		Rules:     ruleCounts(progress.Rules, dryRun),
		Keys:      progress.Keys,
		Truncated: progress.Truncated,
	}
	if partial.Keys == nil {
		partial.Keys = []string{}
	}
	if dryRun {
		matched := progress.Matched
		partial.MatchedCount = &matched
		return partial
	}
	reset := progress.Reset
	partial.ResetCount = &reset
	return partial
}

// ruleCounts renders the per-rule breakdown in rule order, so two answers over
// one walk read the same.
func ruleCounts(rules map[string]int, dryRun bool) []BulkRuleCount {
	out := make([]BulkRuleCount, 0, len(rules))
	for _, id := range slices.Sorted(maps.Keys(rules)) {
		count := rules[id]
		line := BulkRuleCount{RuleID: id}
		if dryRun {
			line.MatchedCount = &count
		} else {
			line.ResetCount = &count
		}
		out = append(out, line)
	}
	return out
}

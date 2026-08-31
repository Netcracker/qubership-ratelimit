package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/key"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	counters "github.com/netcracker/qubership-ratelimit/engine/store"
	"github.com/netcracker/qubership-ratelimit/internal/records"
)

// The addressed reset: the form whose blast radius is bounded by construction.
//
// The invariant is key computability. One full policy/block/rule id and one
// value for every axis the rule declares name a finite set of keys, one per
// window, computed from the snapshot and never scanned. Everything
// wider ("all paths of alice", a block, a domain) is a sweep, and a sweep
// belongs to the counter-resets action with its preview, its confirmation
// token, and its work budget. A partial axis selection is refused here rather
// than silently widened, because silently widening a deletion is the one
// failure mode this endpoint exists to make impossible.

// ResetResponse answers the addressed DELETE, as a preview or as an execution.
type ResetResponse struct {
	Domain string `json:"domain"`
	RuleID string `json:"ruleId"`

	// RuleSetVersion is the enforced set the keys were computed from: what
	// expectedRuleSetVersion pins.
	RuleSetVersion string `json:"ruleSetVersion"`

	// Axes echoes the identity the call addressed.
	Axes map[string]string `json:"axes,omitempty"`

	// Keys is the complete computed list, not a sample: the addressed form
	// computes keys instead of scanning, so its size is the rule's window
	// count.
	Keys []string `json:"keys"`

	DryRun bool `json:"dryRun"`

	// MatchedCount answers a preview, ResetCount an execution; exactly one is
	// present, which is what tells the two answers apart.
	MatchedCount *int `json:"matchedCount,omitempty"`
	ResetCount   *int `json:"resetCount,omitempty"`
}

// resetCommand is a validated addressed reset.
type resetCommand struct {
	// Selector is the canonical selection, shared with the listing grammar so
	// that one normalization serves both.
	Selector selector

	DryRun          bool
	ExpectedVersion string

	// AxesByName is the addressed identity, and Ordered is the same values in the
	// rule's axis order, which is the order a key is built in.
	AxesByName map[string]string
	Ordered    []string

	block *compile.Block
	rule  *compile.Rule
}

// command hashes what an Idempotency-Key is bound to: this call's whole
// canonical command, so 1m and 60s are one command and a preview is never
// mistaken for the execution that follows it.
func (c resetCommand) command() string {
	payload := struct {
		Selector        selector `json:"selector"`
		DryRun          bool     `json:"dryRun,omitempty"`
		ExpectedVersion string   `json:"expectedRuleSetVersion,omitempty"`
	}{Selector: c.Selector, DryRun: c.DryRun, ExpectedVersion: c.ExpectedVersion}

	buf, err := json.Marshal(payload)
	if err != nil {
		panic("management: the reset command failed to marshal: " + err.Error())
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// parseReset validates the query into a command against the enforced set.
func parseReset(snapshot *compile.Snapshot, query url.Values) (resetCommand, *apiError) {
	sel, apiErr := parseSelector(query)
	if apiErr != nil {
		return resetCommand{}, apiErr
	}
	if len(sel.RuleIDs) != 1 {
		return resetCommand{}, invalid(
			"the addressed reset takes exactly one full policy/block/rule id; wider selections are a counter-resets action",
			"ruleId")
	}
	id := sel.RuleIDs[0]
	policy, block, rule, ok := splitFullID(id)
	if !ok {
		return resetCommand{}, invalid("the ruleId "+logSafe(id)+
			" is not a full policy/block/rule triple; prefix forms are refused here", "ruleId")
	}

	command := resetCommand{Selector: sel, ExpectedVersion: query.Get("expectedRuleSetVersion")}
	if apiErr := parseEnumTrue(query, "dryRun", &command.DryRun); apiErr != nil {
		return resetCommand{}, apiErr
	}

	command.block, command.rule = findRule(snapshot, policy, block, rule)
	if command.rule == nil {
		return resetCommand{}, notFound("no rule " + logSafe(id) + " is enforced in domain " +
			logSafe(snapshot.Domain) + "; a rule missing here but present in a policy object means the " +
			"policy was rejected or is running on an earlier spec")
	}
	if apiErr := command.resolveAxes(id, sel.Axes); apiErr != nil {
		return resetCommand{}, apiErr
	}
	return command, nil
}

// resolveAxes checks the addressed identity against the axes the rule declares.
//
// Every axis, one value each. A missing axis is refused rather than read as a
// wildcard, and a value the rule does not count by is refused rather than
// ignored: both mistakes would delete a different set of counters than the
// caller named.
func (c *resetCommand) resolveAxes(id string, axes map[string][]string) *apiError {
	declared := c.rule.Counters

	for name := range axes {
		if !slices.Contains(declared, name) {
			return invalid("rule "+logSafe(id)+" does not count by axis "+logSafe(name)+
				"; it counts by ["+strings.Join(declared, " ")+"]", axisPrefix+name)
		}
	}
	if len(axes) != len(declared) {
		return invalid("the addressed reset needs one value for every axis of "+logSafe(id)+
			" ["+strings.Join(declared, " ")+"]; a partial selection is a counter-resets action, "+
			"never a silently wider reset", "axis")
	}

	c.AxesByName = make(map[string]string, len(declared))
	c.Ordered = make([]string, 0, len(declared))
	for _, name := range declared {
		values := axes[name]
		if len(values) != 1 {
			return invalid("axis "+logSafe(name)+" of rule "+logSafe(id)+
				" takes exactly one value here; several values address several counters", axisPrefix+name)
		}
		c.AxesByName[name] = values[0]
		c.Ordered = append(c.Ordered, values[0])
	}
	return nil
}

// keys computes the counter keys the command addresses, one per window that
// survives the algorithm and period narrowing.
//
// They are computed, never scanned: with the identity fully named there is
// nothing to search for, and the set is bounded by the rule's window count. The
// domain is already baked into each rate prefix by compilation, so there is
// nothing here to get wrong about it.
func (c resetCommand) keys() []string {
	out := make([]string, 0, len(c.rule.Rates))
	seen := make(map[string]struct{}, len(c.rule.Rates))
	for i := range c.rule.Rates {
		rate := &c.rule.Rates[i]
		if !c.windowSelected(rate) {
			continue
		}
		bucket := key.Bucket(rate.Prefix, c.Ordered)
		if _, duplicate := seen[bucket]; duplicate {
			continue
		}
		seen[bucket] = struct{}{}
		out = append(out, bucket)
	}
	sort.Strings(out)
	return out
}

// windowSelected applies the optional algorithm and period narrowing. Both may
// be omitted: a rule's window set is finite and known, so omission still
// computes.
func (c resetCommand) windowSelected(rate *compile.Rate) bool {
	if c.Selector.Algorithm != "" && strings.ToLower(rate.Algorithm.Name()) != c.Selector.Algorithm {
		return false
	}
	if c.Selector.PeriodSeconds != 0 &&
		int64(rate.Window.Period/time.Second) != c.Selector.PeriodSeconds {
		return false
	}
	return true
}

// runReset resolves what the command addresses and, unless it is a preview,
// drops it.
//
// The whole form is one atomic step in the store: bind the key, delete the
// computed keys, record the outcome. That is what leaves it with no intermediate
// states — a server error before the store means nothing was bound and nothing
// ran, so a clean retry re-executes, and a lost answer after it is a delay
// rather than an ambiguity, because the retry finds the recorded outcome.
func (a *API) runReset(
	ctx context.Context,
	snapshot *compile.Snapshot,
	version string,
	command resetCommand,
	name string,
) (ResetResponse, *apiError) {
	computed := command.keys()
	if len(computed) == 0 {
		return ResetResponse{}, notFound("rule " + logSafe(command.Selector.RuleIDs[0]) +
			" has no window matching the algorithm and period given")
	}

	drop := computed
	if command.Selector.LimitedOnly {
		var apiErr *apiError
		if drop, apiErr = a.refusing(ctx, computed, command); apiErr != nil {
			return ResetResponse{}, apiErr
		}
	}

	outcome, err := a.Records.Reset(ctx, records.Addressed{
		Record:  name,
		Command: command.command(),
		Delete:  drop,
		DryRun:  command.DryRun,
	})
	if err != nil {
		a.Log.ErrorC(ctx, "failed to run an addressed reset domain=%v ruleId=%v error=%v",
			snapshot.Domain, command.Selector.RuleIDs[0], err)
		return ResetResponse{}, storeDown(
			"the counter store did not accept the reset; nothing was bound, so the call can be retried")
	}
	if outcome.Replayed && outcome.Command != command.command() {
		return ResetResponse{}, conflict(ConflictCommandMismatch,
			"this Idempotency-Key is already bound to a different command; a new command needs a new key")
	}

	response := ResetResponse{
		Domain:         snapshot.Domain,
		RuleID:         command.Selector.RuleIDs[0],
		RuleSetVersion: version,
		Axes:           command.AxesByName,
		Keys:           computed,
		DryRun:         command.DryRun,
	}
	count := outcome.Count
	if command.DryRun {
		response.MatchedCount = &count
		return response, nil
	}
	response.ResetCount = &count
	return response, nil
}

// refusing keeps the keys whose windows would refuse the next cost-1 request.
func (a *API) refusing(ctx context.Context, computed []string, command resetCommand) ([]string, *apiError) {
	byPrefix := make(map[string]*compile.Rate, len(command.rule.Rates))
	for i := range command.rule.Rates {
		byPrefix[key.Bucket(command.rule.Rates[i].Prefix, command.Ordered)] = &command.rule.Rates[i]
	}

	buckets := make([]counters.Bucket, 0, len(computed))
	for _, k := range computed {
		rate, ok := byPrefix[k]
		if !ok {
			continue
		}
		buckets = append(buckets, counters.Bucket{
			Key:       k,
			Algorithm: rate.Algorithm.ID(),
			Window:    rate.Window,
			Shadow:    command.rule.Behavior == model.BehaviorShadow,
		})
	}

	verdicts, err := a.Counters.Peek(ctx, buckets, 1)
	if err != nil {
		a.Log.ErrorC(ctx, "failed to read counters before resetting them error=%v", err)
		return nil, storeDown("the counter store did not answer the read")
	}
	if len(verdicts) != len(buckets) {
		return nil, errorf(CodeInternal, "the counter store answered a different number of verdicts than keys")
	}

	out := make([]string, 0, len(buckets))
	for i := range buckets {
		if !verdicts[i].Allowed {
			out = append(out, buckets[i].Key)
		}
	}
	return out, nil
}

// recordKey scopes an Idempotency-Key to the subject, the domain, and the
// endpoint, so one client's key never answers another's call and a key reused
// across domains never produces a false conflict. The domain sits in a hash tag
// for the same reason counter keys do: one slot per domain keeps the record and
// the counters it describes together.
func recordKey(domain, endpoint, subject, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(subject + "\x00" + idempotencyKey))
	return "rlm:v1:{" + domain + "}:idem:" + endpoint + ":" + hex.EncodeToString(sum[:])[:32]
}

// findRule locates one rule of the snapshot by its triple.
func findRule(snapshot *compile.Snapshot, policy, block, rule string) (*compile.Block, *compile.Rule) {
	for i := range snapshot.Blocks {
		candidate := &snapshot.Blocks[i]
		if candidate.Policy != policy || candidate.Name != block {
			continue
		}
		for j := range candidate.Rules {
			if candidate.Rules[j].Name == rule {
				return candidate, &candidate.Rules[j]
			}
		}
	}
	return nil, nil
}

// splitFullID accepts only the three-segment form.
func splitFullID(id string) (policy, block, rule string, ok bool) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

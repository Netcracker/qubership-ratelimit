// Package policy decides which generation of each custom resource the engine is
// given, and turns what the engine says back into object status.
//
// The rules themselves are compiled by the engine module, which knows nothing of
// Kubernetes. What lives here is the part that does: an invalid edit falls back to
// the last-good generation rather than taking the working rules down with it, and
// a mapping that would stop running rules is refused before the engine sees it.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// Input is the set of objects one compilation reads, plus the last-good state of
// each domain.
type Input struct {
	Policies []v1alpha1.RateLimitPolicy
	Mappings []v1alpha1.RateLimitMapping

	// State is the persisted last-good state, keyed by domain. An empty map is a
	// cold start: the latest specs are validated, and there is nothing to fall
	// back to.
	State map[string]Bundle
}

// Outcome is what compilation has to say about any one object: which generation it
// read, which one ended up in effect, and whether the spec held together at all.
// Both kinds answer those three questions the same way, and asking "is what I
// wrote what is running" has one implementation because it has one meaning.
type Outcome struct {
	// Generation is the latest generation, the one the problems are about.
	Generation int64

	// ActiveGeneration is the generation in effect. It differs from Generation
	// when the latest one is not enforced and an earlier one keeps running; zero
	// means nothing of this object is in effect.
	ActiveGeneration int64

	// Err is set when the latest spec is structurally invalid.
	Err error
}

// Ready reports whether the latest generation is the one in effect.
func (o Outcome) Ready() bool {
	return o.Err == nil && o.ActiveGeneration == o.Generation
}

// PolicyOutcome is what compilation has to say about one policy.
type PolicyOutcome struct {
	Outcome

	// Problems describes the latest generation. A single blocking entry keeps it
	// out of the snapshot entirely.
	Problems []v1alpha1.RuleProblem

	// Reason is the Ready reason when the latest generation is not the one being
	// enforced.
	Reason string

	// Blocks and Rules are what the active generation contributed.
	Blocks int
	Rules  int
}

// MappingOutcome is what compilation has to say about one mapping. Zero for
// ActiveGeneration here means the domain fell back to its built-in keys.
type MappingOutcome struct {
	Outcome

	// EffectiveKeys is the key set of the active generation, not of the
	// candidate: a rule author has to read what is in effect.
	EffectiveKeys []string

	// RejectedBy lists the policies that vetoed the latest generation.
	RejectedBy []v1alpha1.MappingRejection
}

// Result is one compilation.
type Result struct {
	// Snapshots is what the engine evaluates, one per domain.
	Snapshots map[string]*enginecompile.Snapshot

	// Policies and Mappings carry the per-object status, keyed by object.
	Policies map[client.ObjectKey]PolicyOutcome
	Mappings map[client.ObjectKey]MappingOutcome

	// State is the last-good state to persist, keyed by domain. It describes the
	// generations these snapshots were built from, so writing it before swapping
	// them leaves a crash in between recoverable.
	State map[string]Bundle

	// Warnings are the domain-level informational records of the compilation,
	// keyed by domain — the domain-budget note among them. They exclude nobody
	// and block nothing, but dropping them would silence the one signal that
	// says the runtime backstop is within reach.
	Warnings map[string][]string
}

// Compile turns the objects of a namespace into one snapshot per domain.
//
// Compilation never fails as a whole: an object it rejects is reported through its
// own outcome and left out, and the rest of the namespace keeps working. A single
// bad policy must not be able to turn the limits of a whole gateway off.
func Compile(in Input) *Result {
	result := &Result{
		Snapshots: make(map[string]*enginecompile.Snapshot),
		Policies:  make(map[client.ObjectKey]PolicyOutcome, len(in.Policies)),
		Mappings:  make(map[client.ObjectKey]MappingOutcome, len(in.Mappings)),
		State:     make(map[string]Bundle),
		Warnings:  make(map[string][]string),
	}

	mappings, policies := index(in)
	for _, domain := range domainNames(mappings, policies) {
		compileDomain(domain, mappings[domain], policies[domain], in.State[domain], result)
	}

	// A mapping that served no domain has no outcome yet. Leaving its status blank
	// would show an accepted mapping that is not in effect, which is the one
	// failure the singleton design is meant to make visible.
	for i := range in.Mappings {
		mapping := &in.Mappings[i]
		objectKey := client.ObjectKeyFromObject(mapping)
		if _, reported := result.Mappings[objectKey]; reported {
			continue
		}
		result.Mappings[objectKey] = MappingOutcome{
			Outcome: Outcome{Generation: mapping.Generation, Err: rejection(mapping)},
		}
	}
	return result
}

// rejection says why a mapping took no part in its domain.
func rejection(mapping *v1alpha1.RateLimitMapping) error {
	if mapping.Name != mapping.Spec.Domain {
		return fmt.Errorf("metadata.name %q does not equal spec.domain %q",
			mapping.Name, mapping.Spec.Domain)
	}
	// Object names are unique per namespace and a name equals its domain, so this
	// needs two namespaces in one compilation to happen at all.
	return fmt.Errorf("another mapping already serves domain %q", mapping.Spec.Domain)
}

// compileDomain settles the mapping of one domain, then the policies under it.
func compileDomain(
	domain string,
	mapping *v1alpha1.RateLimitMapping,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
	result *Result,
) {
	active, activeGeneration, rejectedBy := settleMapping(domain, mapping, policies, previous)
	env := modelMapping(active)

	bundle := Bundle{}
	if mapping != nil && active != nil {
		bundle.Mapping = &MappingState{
			UID:            string(mapping.UID),
			GoodGeneration: activeGeneration,
			GoodSpec:       *active.DeepCopy(),
		}
	}

	// The engine is handed the generation of each object that is in effect and
	// nothing else. It decides what those specs compile to, and drops any that
	// still do not hold together — the same atomicity rule, enforced once.
	// Between choosing and compiling stands the domain gate: a candidate that
	// would push the whole domain over its reference bounds yields to its own
	// last-good generation instead of taking a neighbor down.
	slots := admitPolicies(domain, policies, previous, env)

	chosen, outcomes, states := settlePolicies(policies, slots, env)
	bundle.Policies = states

	snapshot, problems := enginecompile.Compile(domain, chosen, env)
	for _, problem := range problems {
		if problem.Policy == "" && !problem.Blocking {
			result.Warnings[domain] = append(result.Warnings[domain], problem.Message)
		}
	}
	for _, object := range policies {
		outcome := outcomes[object.Name]
		outcome.Blocks, outcome.Rules = contribution(snapshot, object.Name)
		result.Policies[client.ObjectKeyFromObject(object)] = outcome
	}

	if mapping != nil {
		result.Mappings[client.ObjectKeyFromObject(mapping)] = MappingOutcome{
			Outcome: Outcome{
				Generation:       mapping.Generation,
				ActiveGeneration: activeGeneration,
				Err:              domainError(problems),
			},
			EffectiveKeys: snapshot.EffectiveKeys,
			RejectedBy:    rejectedBy,
		}
	}

	// A domain whose only policy was rejected still gets an entry: a domain with
	// no blocks is a claimed domain that nothing matched, and dropping it would
	// turn a rejected policy into an unknown-domain log line, which points at the
	// wrong thing entirely.
	result.Snapshots[domain] = snapshot
	result.State[domain] = bundle
}

// settlePolicies turns the admitted slots into what the rest of compilation
// needs: the specs to compile, the per-object outcome, and the policy half of
// the bundle to persist.
//
// Only a running policy contributes a spec and a persisted state — a rejected
// one keeps its outcome, so its status still says why, and puts nothing into
// the snapshot.
func settlePolicies(
	policies []*v1alpha1.RateLimitPolicy,
	slots map[string]*slot,
	env *model.Mapping,
) ([]model.Policy, map[string]PolicyOutcome, []PolicyState) {
	chosen := make([]model.Policy, 0, len(policies))
	outcomes := make(map[string]PolicyOutcome, len(policies))
	var states []PolicyState

	for _, object := range policies {
		s := slots[object.Name]

		outcome := PolicyOutcome{
			Outcome:  Outcome{Generation: object.Generation, Err: structural(s.latest.problems)},
			Problems: ruleProblems(s.latest.problems),
		}
		if s.running {
			outcome.ActiveGeneration = s.final.generation
			chosen = append(chosen, modelPolicy(object.Name, s.final.spec))

			states = append(states, PolicyState{
				Name:           object.Name,
				UID:            string(object.UID),
				GoodGeneration: s.final.generation,
				GoodSpec:       *s.final.spec.DeepCopy(),
			})
		}
		if !outcome.Ready() {
			outcome.Reason = notReadyReason(s, env)
		}
		outcomes[object.Name] = outcome
	}
	return chosen, outcomes, states
}

// notReadyReason names why a policy is not ready: the domain gate turned it
// away, or its own spec did not hold together.
func notReadyReason(s *slot, env *model.Mapping) string {
	if s.rejected {
		return v1alpha1.ReasonRejectedByDomainBudget
	}
	return readyReason(s.latest.problems, env != nil)
}

// contribution counts what one policy put into the snapshot.
func contribution(snapshot *enginecompile.Snapshot, name string) (blocks, rules int) {
	for i := range snapshot.Blocks {
		if snapshot.Blocks[i].Policy != name {
			continue
		}
		blocks++
		rules += len(snapshot.Blocks[i].Rules)
	}
	return blocks, rules
}

// settleMapping decides which mapping spec is in effect.
//
// A new spec has to pass the transaction gate: it is accepted only if no policy
// that is running something would be left with nothing to run. The check is about
// the policies, not about the mapping — a policy already broken by its own spec has
// no vote, because otherwise one team's typo would freeze a platform resource for
// the whole domain.
func settleMapping(
	domain string,
	mapping *v1alpha1.RateLimitMapping,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
) (*v1alpha1.RateLimitMappingSpec, int64, []v1alpha1.MappingRejection) {
	if mapping == nil {
		// Deleting a mapping is outside the gate: it is a deliberate act, and the
		// domain falls back to its built-in keys.
		return nil, 0, nil
	}

	good := previous.mapping(string(mapping.UID))
	if good != nil && good.GoodGeneration == mapping.Generation {
		// The candidate is already what runs, so there is no transition to gate.
		return &mapping.Spec, mapping.Generation, nil
	}

	var (
		before           *v1alpha1.RateLimitMappingSpec
		beforeGeneration int64
	)
	if good != nil {
		before, beforeGeneration = &good.GoodSpec, good.GoodGeneration
	}

	// The gate runs even with nothing to fall back to. A first mapping usually
	// only adds keys, but it can also redefine client as an array, and that would
	// invalidate every rule counting by client.
	rejectedBy := gate(domain, modelMapping(before), modelMapping(&mapping.Spec), policies, previous)
	if len(rejectedBy) == 0 {
		return &mapping.Spec, mapping.Generation, nil
	}
	return before, beforeGeneration, rejectedBy
}

// gate collects the policies that veto a candidate mapping.
//
// The priority inside "what would run after" matters: etcd is the desired state and
// a last-good spec is a crutch, so as soon as the desired spec becomes valid under
// the candidate it is the one that would run. Without that priority a policy could
// never be fixed through the mapping — its stale last-good spec would demand
// compatibility with itself forever.
func gate(
	domain string,
	before, after *model.Mapping,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
) []v1alpha1.MappingRejection {
	var rejectedBy []v1alpha1.MappingRejection

	for _, object := range policies {
		wasRunning, running := choose(
			try(domain, object.Name, object.Generation, &object.Spec, before),
			lastGoodPolicy(domain, object, previous, before),
		)
		if !running {
			// Already running nothing, so the candidate cannot make it worse. Its
			// breakage is in its own spec, and the gate protects policies from the
			// mapping rather than the mapping from policies.
			continue
		}

		latestAfter := try(domain, object.Name, object.Generation, &object.Spec, after)
		if _, stillRunning := choose(latestAfter, lastGoodPolicy(domain, object, previous, after)); stillRunning {
			continue
		}

		// The vetoing generation is the one that was running, which may not be the
		// latest in etcd. Reporting the latest would name a spec that no longer
		// explains the veto.
		rejection := v1alpha1.MappingRejection{
			Policy:     object.Name,
			Generation: wasRunning.generation,
			Reason:     v1alpha1.ProblemUnresolvedKeyReference,
		}
		if problem := firstBlocking(latestAfter.problems); problem != nil {
			rejection.Block, rejection.Rule = problem.Block, problem.Rule
			rejection.Reason = string(problem.Reason)
		}
		rejectedBy = append(rejectedBy, rejection)
	}
	return rejectedBy
}

// slot is what the domain gate decided about one policy: the attempt that
// runs, whether anything runs at all, and whether the gate refused the latest
// generation.
type slot struct {
	latest   attempt
	final    attempt
	running  bool
	rejected bool
}

// admitPolicies picks the spec of every policy under the domain bounds.
//
// A policy whose latest generation already holds its seat — it is the
// persisted active one — is not a candidate and is never re-litigated: seats
// were gated when they were admitted, and re-judging them would let a new
// edit evict a neighbor. Everything else is a candidate: a new generation, or
// a policy with no seat at all. Candidates are judged one at a time against
// the seats of everyone plus the candidates already admitted, oldest object
// first (creationTimestamp, then name): on a cold start with no seats that
// order is what makes the outcome a function of the set, and in steady state
// it never matters because a candidate that fits is admitted regardless.
//
// A refused candidate falls back to its own seat — the last-good generation
// keeps running — or, seatless, runs nothing. The judge is the engine: the
// trial compilation of the exact resulting set either carries the
// domain-budget record or it does not, so neither the bounds nor the formula
// exist twice. A seat set inherited over the bounds (state written before the
// gate existed) stays as it is — seats are not evicted — and the runtime
// backstop keeps the store safe while the warning says so.
func admitPolicies(
	domain string,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
	env *model.Mapping,
) map[string]*slot {
	slots, view, candidates := partitionBySeat(domain, policies, previous, env)
	sortByAge(candidates)
	admitCandidates(domain, slots, view, candidates, env)
	return slots
}

// partitionBySeat splits the domain's policies into those already holding their
// seat and those still to be judged.
//
// It returns a slot per policy, the view of what is running — seats plus the
// last-good generations of policies whose latest edit is a candidate — and the
// candidates themselves.
func partitionBySeat(
	domain string,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
	env *model.Mapping,
) (map[string]*slot, map[string]attempt, []*v1alpha1.RateLimitPolicy) {
	slots := make(map[string]*slot, len(policies))
	view := make(map[string]attempt, len(policies))
	var candidates []*v1alpha1.RateLimitPolicy

	for _, object := range policies {
		s := &slot{latest: try(domain, object.Name, object.Generation, &object.Spec, env)}
		slots[object.Name] = s

		state := previous.policy(object.Name, string(object.UID))
		if state != nil && state.GoodGeneration == object.Generation {
			// The latest generation is the seated one; nothing new to judge.
			s.final, s.running = choose(s.latest, attempt{})
			if s.running {
				view[object.Name] = s.final
			}
			continue
		}
		if state != nil {
			seat := lastGoodPolicy(domain, object, previous, env)
			if seat.runnable() {
				view[object.Name] = seat
			}
		}
		candidates = append(candidates, object)
	}
	return slots, view, candidates
}

// sortByAge orders candidates oldest object first, by creation timestamp and
// then by name. On a cold start with no seats that order is what makes the
// outcome a function of the set rather than of the order events arrived in.
func sortByAge(candidates []*v1alpha1.RateLimitPolicy) {
	sort.SliceStable(candidates, func(a, b int) bool {
		first, second := candidates[a], candidates[b]
		if !first.CreationTimestamp.Equal(&second.CreationTimestamp) {
			return first.CreationTimestamp.Before(&second.CreationTimestamp)
		}
		return first.Name < second.Name
	})
}

// admitCandidates judges each candidate against the seats of everyone plus the
// candidates already admitted. A refused candidate falls back to its own seat,
// or, seatless, runs nothing.
func admitCandidates(
	domain string,
	slots map[string]*slot,
	view map[string]attempt,
	candidates []*v1alpha1.RateLimitPolicy,
	env *model.Mapping,
) {
	for _, object := range candidates {
		s := slots[object.Name]
		seat, seated := view[object.Name]

		if s.latest.runnable() {
			if fitsDomain(domain, view, object.Name, s.latest, env) {
				s.final, s.running = s.latest, true
				view[object.Name] = s.latest
				continue
			}
			s.rejected = true
		}
		s.final, s.running = seat, seated
	}
}

// fitsDomain asks the engine whether the view, with one policy replaced by the
// given attempt, stays inside the domain bounds.
func fitsDomain(
	domain string,
	view map[string]attempt,
	name string,
	candidate attempt,
	env *model.Mapping,
) bool {
	set := make([]model.Policy, 0, len(view)+1)
	for member, seated := range view {
		if member == name {
			continue
		}
		set = append(set, modelPolicy(member, seated.spec))
	}
	set = append(set, modelPolicy(name, candidate.spec))

	_, problems := enginecompile.Compile(domain, set, env)
	for _, problem := range problems {
		if problem.Policy == "" && !problem.Blocking &&
			problem.Reason == enginecompile.ReasonDomainBudgetExceeded {
			return false
		}
	}
	return true
}

// attempt is one spec put to the engine against one mapping.
//
// It keeps the problems as the engine stated them, because the engine decides
// which of them block: repeating that classification here would be a second
// opinion on a question that already has an owner.
type attempt struct {
	generation int64
	spec       *v1alpha1.RateLimitPolicySpec
	problems   []enginecompile.Problem
}

// runnable reports whether this spec may enter the snapshot. A generation with one
// blocking problem is invalid as a whole — the rule the engine applies too, which
// is why asking it is the same as asking what would run.
func (a attempt) runnable() bool {
	return a.spec != nil && firstBlocking(a.problems) == nil
}

// try asks the engine what it makes of one spec on its own.
func try(
	domain, name string,
	generation int64,
	spec *v1alpha1.RateLimitPolicySpec,
	mapping *model.Mapping,
) attempt {
	_, problems := enginecompile.Compile(domain, []model.Policy{modelPolicy(name, spec)}, mapping)

	// Problems of other policies cannot arise here — one policy went in — but a
	// domain or mapping concern can, and it belongs to the mapping rather than to
	// whichever policy happened to be compiled alongside it.
	mine := problems[:0]
	for _, problem := range problems {
		if problem.Policy == name {
			mine = append(mine, problem)
		}
	}
	return attempt{generation: generation, spec: spec, problems: mine}
}

// choose picks the spec that runs: the latest one when it is valid, otherwise the
// last-good one, otherwise nothing.
func choose(latest, fallback attempt) (attempt, bool) {
	if latest.runnable() {
		return latest, true
	}
	if fallback.runnable() {
		return fallback, true
	}
	return attempt{}, false
}

// lastGoodPolicy puts the persisted spec of a policy to the engine, if it has one.
func lastGoodPolicy(
	domain string,
	object *v1alpha1.RateLimitPolicy,
	previous Bundle,
	mapping *model.Mapping,
) attempt {
	state := previous.policy(object.Name, string(object.UID))
	if state == nil {
		return attempt{}
	}
	if state.GoodGeneration == object.Generation {
		// The latest generation is the good one, so there is nothing to fall back
		// to and compiling it twice would only duplicate the work.
		return attempt{}
	}
	return try(domain, object.Name, state.GoodGeneration, &state.GoodSpec, mapping)
}

// ruleProblems renders the problems of one policy for its status.
func ruleProblems(problems []enginecompile.Problem) []v1alpha1.RuleProblem {
	if len(problems) == 0 {
		return nil
	}
	out := make([]v1alpha1.RuleProblem, 0, len(problems))
	for _, problem := range problems {
		out = append(out, v1alpha1.RuleProblem{
			Block:   problem.Block,
			Rule:    problem.Rule,
			Reason:  string(problem.Reason),
			Message: problem.Message,
		})
	}
	return out
}

// domainError renders the problems that belong to no single policy: a domain that
// does not name, a mapping that does not hold together, a budget the whole domain
// went over.
func domainError(problems []enginecompile.Problem) error {
	var messages []string
	for _, problem := range problems {
		if problem.Policy == "" && problem.Blocking {
			messages = append(messages, problem.Message)
		}
	}
	if len(messages) == 0 {
		return nil
	}
	return errors.New(strings.Join(messages, "; "))
}

// structural reports a spec that is malformed rather than merely unresolvable,
// which is what separates Accepted from Ready. The decision budget and the
// window math belong here too: both are defects of the spec alone — no
// reference and no neighbor is involved — and leaving Accepted true for them
// would contradict the Ready reason that already says InvalidSpec.
func structural(problems []enginecompile.Problem) error {
	for _, problem := range problems {
		switch problem.Reason {
		case enginecompile.ReasonInvalidSpec,
			enginecompile.ReasonInvalidWindow,
			enginecompile.ReasonDecisionBudgetExceeded:
			return errors.New(problem.Message)
		}
	}
	return nil
}

func firstBlocking(problems []enginecompile.Problem) *enginecompile.Problem {
	for i := range problems {
		if problems[i].Blocking {
			return &problems[i]
		}
	}
	return nil
}

// readyReason names why the latest generation is not the one being enforced.
func readyReason(problems []enginecompile.Problem, declared bool) string {
	problem := firstBlocking(problems)
	if problem == nil {
		// Valid but not running: the only way here is a snapshot that has not
		// caught up yet.
		return v1alpha1.ReasonReconciling
	}
	switch problem.Reason {
	case enginecompile.ReasonInvalidSpec, enginecompile.ReasonInvalidWindow,
		enginecompile.ReasonDecisionBudgetExceeded:
		// The budget is a structural property of the spec itself: no reference
		// and no neighbor is involved, so reporting it as a reference problem
		// would point the author at the wrong fix.
		return v1alpha1.ReasonInvalidSpec
	case enginecompile.ReasonUnresolvedKeyReference, enginecompile.ReasonUnresolvedGroupReference:
		if !declared {
			// The domain has no mapping at all, which is a different fix from a
			// mapping that does not declare the key.
			return v1alpha1.ReasonMappingRequired
		}
		return v1alpha1.ReasonUnresolvedReferences
	default:
		return v1alpha1.ReasonIncompatibleReferences
	}
}

// index groups the input by domain and puts the policies of each domain in a
// stable order, which is what makes the snapshot a function of the set rather than
// of the arrival order.
func index(in Input) (map[string]*v1alpha1.RateLimitMapping, map[string][]*v1alpha1.RateLimitPolicy) {
	mappings := make(map[string]*v1alpha1.RateLimitMapping, len(in.Mappings))
	for i := range in.Mappings {
		mapping := &in.Mappings[i]
		// The name of a mapping equals its domain, so the API server has already
		// rejected a second mapping of the same domain. A mapping that reaches here
		// with a mismatched name was written by a client that bypassed validation,
		// and taking it would make the singleton a lie.
		if mapping.Name != mapping.Spec.Domain {
			continue
		}
		mappings[mapping.Spec.Domain] = mapping
	}

	policies := make(map[string][]*v1alpha1.RateLimitPolicy)
	for i := range in.Policies {
		object := &in.Policies[i]
		policies[object.Spec.Domain] = append(policies[object.Spec.Domain], object)
	}
	for _, list := range policies {
		sort.Slice(list, func(a, b int) bool {
			if list[a].Namespace != list[b].Namespace {
				return list[a].Namespace < list[b].Namespace
			}
			return list[a].Name < list[b].Name
		})
	}
	return mappings, policies
}

func domainNames(
	mappings map[string]*v1alpha1.RateLimitMapping,
	policies map[string][]*v1alpha1.RateLimitPolicy,
) []string {
	seen := make(map[string]struct{}, len(mappings)+len(policies))
	for name := range mappings {
		seen[name] = struct{}{}
	}
	for name := range policies {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

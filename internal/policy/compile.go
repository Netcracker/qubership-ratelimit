package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/internal/route"
)

// Period bounds. The CRD checks them too; the compiler repeats the check because
// a snapshot is also built from a last-good spec that an older schema admitted.
const (
	minPeriod = time.Second
	maxPeriod = 24 * time.Hour
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

// Outcome is what the compiler has to say about any one object: which generation
// it read, which one ended up in effect, and whether the spec held together at
// all. Both kinds answer those three questions the same way, and asking "is what
// I wrote what is running" has one implementation because it has one meaning.
type Outcome struct {
	// Generation is the latest generation, the one the problems are about.
	Generation int64

	// ActiveGeneration is the generation in effect. It differs from Generation
	// when the latest one is not enforced and an earlier one keeps running; zero
	// means nothing of this object is in effect.
	ActiveGeneration int64

	// Err is set when the latest spec is structurally invalid. Only checks the
	// CRD schema cannot express land here.
	Err error
}

// Ready reports whether the latest generation is the one in effect.
func (o Outcome) Ready() bool {
	return o.Err == nil && o.ActiveGeneration == o.Generation
}

// PolicyOutcome is what the compiler has to say about one policy.
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

// MappingOutcome is what the compiler has to say about one mapping. Zero for
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
	// Snapshot is the compiled state of every domain, built from the generations
	// that are in effect.
	Snapshot *Snapshot

	// Policies and Mappings carry the per-object status, keyed by object.
	Policies map[client.ObjectKey]PolicyOutcome
	Mappings map[client.ObjectKey]MappingOutcome

	// State is the last-good state to persist, keyed by domain. It describes the
	// generations this snapshot was built from, so writing it before swapping the
	// snapshot leaves a crash in between recoverable.
	State map[string]Bundle
}

// Compile turns the objects of a namespace into one snapshot.
//
// Compilation never fails as a whole: an object the compiler rejects is reported
// through its own outcome and left out, and the rest of the namespace keeps
// working. A single bad policy must not be able to turn the limits of a whole
// gateway off.
func Compile(in Input) *Result {
	result := &Result{
		Snapshot: &Snapshot{domains: make(map[string]*Domain)},
		Policies: make(map[client.ObjectKey]PolicyOutcome, len(in.Policies)),
		Mappings: make(map[client.ObjectKey]MappingOutcome, len(in.Mappings)),
		State:    make(map[string]Bundle),
	}

	mappings, policies := index(in)

	for _, domainName := range domainNames(mappings, policies) {
		compileDomain(domainName, mappings[domainName], policies[domainName], in.State[domainName], result)
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
	name string,
	mapping *v1alpha1.RateLimitMapping,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
	result *Result,
) {
	active, activeGeneration, rejectedBy := settleMapping(mapping, policies, previous)
	env := newEnvironment(active)

	domain := &Domain{Name: name, Keys: env.keys}
	bundle := Bundle{}
	if mapping != nil && active != nil {
		bundle.Mapping = &MappingState{
			UID:            string(mapping.UID),
			GoodGeneration: activeGeneration,
			GoodSpec:       *active.DeepCopy(),
		}
	}

	for _, object := range policies {
		latest := try(object.Name, object.Generation, &object.Spec, env)
		chosen, running := choose(latest, lastGoodPolicy(object, previous, env))

		outcome := PolicyOutcome{
			Outcome:  Outcome{Generation: object.Generation, Err: latest.err},
			Problems: latest.problems,
		}
		if running {
			outcome.ActiveGeneration = chosen.generation
			outcome.Blocks = len(chosen.blocks)
			for _, block := range chosen.blocks {
				outcome.Rules += len(block.Rules)
			}
			domain.Blocks = append(domain.Blocks, chosen.blocks...)

			bundle.Policies = append(bundle.Policies, PolicyState{
				Name:           object.Name,
				UID:            string(object.UID),
				GoodGeneration: chosen.generation,
				GoodSpec:       *chosen.spec.DeepCopy(),
			})
		}
		if !outcome.Ready() {
			outcome.Reason = readyReason(latest, env)
		}
		result.Policies[client.ObjectKeyFromObject(object)] = outcome
	}

	if mapping != nil {
		result.Mappings[client.ObjectKeyFromObject(mapping)] = MappingOutcome{
			Outcome: Outcome{
				Generation:       mapping.Generation,
				ActiveGeneration: activeGeneration,
			},
			EffectiveKeys: domain.EffectiveKeys(),
			RejectedBy:    rejectedBy,
		}
	}

	// A domain whose only policy was rejected still gets an entry: a domain with
	// no blocks is a claimed domain that nothing matched, and dropping it would
	// turn a rejected policy into an unknown-domain log line, which points at the
	// wrong thing entirely.
	result.Snapshot.domains[name] = domain
	result.State[name] = bundle
}

// settleMapping decides which mapping spec is in effect.
//
// A new spec has to pass the transaction gate: it is accepted only if no policy
// that is running something would be left with nothing to run. The check is about
// the policies, not about the mapping — a policy already broken by its own spec
// has no vote, because otherwise one team's typo would freeze a platform resource
// for the whole domain.
func settleMapping(
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
	rejectedBy := gate(newEnvironment(before), newEnvironment(&mapping.Spec), policies, previous)
	if len(rejectedBy) == 0 {
		return &mapping.Spec, mapping.Generation, nil
	}
	return before, beforeGeneration, rejectedBy
}

// gate collects the policies that veto a candidate mapping.
//
// The priority inside "what would run after" matters: etcd is the desired state
// and a last-good spec is a crutch, so as soon as the desired spec becomes valid
// under the candidate it is the one that would run. Without that priority a policy
// could never be fixed through the mapping — its stale last-good spec would demand
// compatibility with itself forever.
func gate(
	before, after *environment,
	policies []*v1alpha1.RateLimitPolicy,
	previous Bundle,
) []v1alpha1.MappingRejection {
	var rejectedBy []v1alpha1.MappingRejection

	for _, object := range policies {
		wasRunning, running := choose(
			try(object.Name, object.Generation, &object.Spec, before),
			lastGoodPolicy(object, previous, before),
		)
		if !running {
			// Already running nothing, so the candidate cannot make it worse. Its
			// breakage is in its own spec, and the gate protects policies from the
			// mapping rather than the mapping from policies.
			continue
		}

		latestAfter := try(object.Name, object.Generation, &object.Spec, after)
		if _, stillRunning := choose(latestAfter, lastGoodPolicy(object, previous, after)); stillRunning {
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
			rejection.Block, rejection.Rule, rejection.Reason = problem.Block, problem.Rule, problem.Reason
		}
		rejectedBy = append(rejectedBy, rejection)
	}
	return rejectedBy
}

// attempt is one spec compiled against one environment.
type attempt struct {
	generation int64
	spec       *v1alpha1.RateLimitPolicySpec
	blocks     []*Block
	problems   []v1alpha1.RuleProblem
	err        error
}

// runnable reports whether this spec may enter the snapshot. A generation with
// one blocking problem is invalid as a whole: "applied" has to mean "applied as
// written", or a FirstMatch cascade with one dead rule would silently hand its
// traffic to the neighbours.
func (a attempt) runnable() bool {
	return a.spec != nil && a.err == nil && firstBlocking(a.problems) == nil
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

// lastGoodPolicy compiles the persisted spec of a policy, if it has one.
func lastGoodPolicy(object *v1alpha1.RateLimitPolicy, previous Bundle, env *environment) attempt {
	state := previous.policy(object.Name, string(object.UID))
	if state == nil {
		return attempt{}
	}
	if state.GoodGeneration == object.Generation {
		// The latest generation is the good one, so there is nothing to fall back
		// to and compiling it twice would only duplicate the work.
		return attempt{}
	}
	return try(object.Name, state.GoodGeneration, &state.GoodSpec, env)
}

func firstBlocking(problems []v1alpha1.RuleProblem) *v1alpha1.RuleProblem {
	for i := range problems {
		if v1alpha1.Blocking(problems[i].Reason) {
			return &problems[i]
		}
	}
	return nil
}

// readyReason names why the latest generation is not the one being enforced.
func readyReason(latest attempt, env *environment) string {
	if latest.err != nil {
		return v1alpha1.ReasonInvalidSpec
	}
	problem := firstBlocking(latest.problems)
	if problem == nil {
		// Valid but not running: the only way here is a snapshot that has not
		// caught up yet.
		return v1alpha1.ReasonReconciling
	}
	switch problem.Reason {
	case v1alpha1.ProblemUnresolvedKeyReference, v1alpha1.ProblemUnresolvedGroupReference:
		if !env.declared {
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
// stable order, which is what makes the snapshot a function of the set rather
// than of the arrival order.
func index(in Input) (map[string]*v1alpha1.RateLimitMapping, map[string][]*v1alpha1.RateLimitPolicy) {
	mappings := make(map[string]*v1alpha1.RateLimitMapping, len(in.Mappings))
	for i := range in.Mappings {
		mapping := &in.Mappings[i]
		// The name of a mapping equals its domain, so the API server has already
		// rejected a second mapping of the same domain. A mapping that reaches
		// here with a mismatched name was written by a client that bypassed
		// validation, and taking it would make the singleton a lie.
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

// try compiles one policy spec against one environment. It builds the blocks even
// when a problem makes them unusable: the same walk that finds the problem builds
// them, and the caller decides whether to keep them.
func try(
	policyName string,
	generation int64,
	spec *v1alpha1.RateLimitPolicySpec,
	env *environment,
) attempt {
	out := attempt{generation: generation, spec: spec}
	groups := env.groupsFor(spec)

	for i := range spec.Limits {
		source := &spec.Limits[i]

		routes, captures, err := compileRoutes(source)
		if err != nil {
			out.err = fmt.Errorf("block %q: %w", source.Name, err)
			return out
		}
		if err := checkReplaces(source); err != nil {
			out.err = fmt.Errorf("block %q: %w", source.Name, err)
			return out
		}

		block := &Block{
			Policy: policyName,
			Name:   source.Name,
			Mode:   mode(source.Mode),
			Routes: routes,
			Rules:  make([]*Rule, 0, len(source.Rules)),
		}

		// A capture takes precedence over a mapped key of the same name inside
		// its block, which is worth saying out loud: the author of the rule sees
		// one name and two possible sources.
		for _, name := range sortedKeys(captures) {
			if _, mapped := env.keys[name]; mapped {
				out.problems = append(out.problems, v1alpha1.RuleProblem{
					Block:  source.Name,
					Reason: v1alpha1.ProblemCaptureShadowsMappedKey,
					Message: fmt.Sprintf(
						"route capture %q shadows the mapped key of the same name inside this block", name),
				})
			}
		}

		for j := range source.Rules {
			rule, problems, err := compileRule(&source.Rules[j], env, captures, groups)
			if err != nil {
				out.err = fmt.Errorf("block %q rule %q: %w", source.Name, source.Rules[j].Name, err)
				return out
			}
			for k := range problems {
				problems[k].Block = source.Name
			}
			out.problems = append(out.problems, problems...)
			block.Rules = append(block.Rules, rule)
		}
		out.blocks = append(out.blocks, block)
	}
	return out
}

func mode(m v1alpha1.BlockMode) v1alpha1.BlockMode {
	if m == "" {
		return v1alpha1.BlockModeAll
	}
	return m
}

// compileRoutes compiles the routes of a block and collects the capture names
// they produce. A capture of one route is visible to the rules of the block, so
// the names are collected across routes.
func compileRoutes(block *v1alpha1.LimitBlock) ([]Route, map[string]struct{}, error) {
	if block.Target == nil || len(block.Target.Routes) == 0 {
		return nil, nil, nil
	}

	routes := make([]Route, 0, len(block.Target.Routes))
	var captures map[string]struct{}

	for i := range block.Target.Routes {
		source := &block.Target.Routes[i]
		matcher, err := route.Compile(kind(source.Path.Type), source.Path.Value)
		if err != nil {
			return nil, nil, err
		}
		compiled := Route{Matcher: matcher}
		if len(source.Methods) > 0 {
			compiled.Methods = make(map[string]struct{}, len(source.Methods))
			for _, method := range source.Methods {
				compiled.Methods[string(method)] = struct{}{}
			}
		}
		routes = append(routes, compiled)

		for _, name := range matcher.Names() {
			if captures == nil {
				captures = make(map[string]struct{})
			}
			captures[name] = struct{}{}
		}
	}
	return routes, captures, nil
}

func kind(t v1alpha1.PathMatchType) route.Kind {
	switch t {
	case v1alpha1.PathMatchExact:
		return route.Exact
	case v1alpha1.PathMatchTemplate:
		return route.Template
	default:
		return route.Prefix
	}
}

// checkReplaces stands in for the CEL rule the cost estimator would not accept:
// a name in replaces has to be a rule of the same block. A dangling name is a
// typo that would otherwise silence nothing while looking like it silenced
// something.
func checkReplaces(block *v1alpha1.LimitBlock) error {
	names := make(map[string]struct{}, len(block.Rules))
	for i := range block.Rules {
		names[block.Rules[i].Name] = struct{}{}
	}
	for i := range block.Rules {
		for _, replaced := range block.Rules[i].Replaces {
			if _, ok := names[replaced]; !ok {
				return fmt.Errorf("rule %q replaces %q, which is not a rule of this block",
					block.Rules[i].Name, replaced)
			}
		}
	}
	return nil
}

// compileRule compiles one rule and reports its problems.
func compileRule(
	source *v1alpha1.Rule,
	env *environment,
	captures map[string]struct{},
	groups map[string]map[string]struct{},
) (*Rule, []v1alpha1.RuleProblem, error) {
	rule := &Rule{
		Name:     source.Name,
		Counters: append([]string(nil), source.Counters...),
		Behavior: behavior(source.Behavior),
	}
	if len(source.Replaces) > 0 {
		rule.Replaces = make(map[string]struct{}, len(source.Replaces))
		for _, replaced := range source.Replaces {
			rule.Replaces[replaced] = struct{}{}
		}
	}

	var problems []v1alpha1.RuleProblem
	problem := func(reason, format string, args ...any) {
		problems = append(problems, v1alpha1.RuleProblem{
			Rule:    source.Name,
			Reason:  reason,
			Message: fmt.Sprintf(format, args...),
		})
		// Dead is defense in depth. A blocking problem already keeps the whole
		// generation out of the snapshot, so this flag decides nothing today — and
		// if a future path ever lets such a rule through, it matches nothing
		// rather than trapping traffic.
		rule.Dead = true
	}

	for i := range source.When {
		predicate := &source.When[i]
		kind, known := keyKind(predicate.Key, env, captures)
		if !known {
			problem(v1alpha1.ProblemUnresolvedKeyReference,
				"key %q is not in the effective set: %s", predicate.Key, keyList(env, captures))
			continue
		}
		if kind == KeyArray && predicate.Operator == v1alpha1.OperatorEquals {
			problem(v1alpha1.ProblemIncompatibleOperator,
				"operator Equals cannot apply to array key %q; use Contains or In", predicate.Key)
			continue
		}

		compiled := Predicate{Key: predicate.Key, Operator: predicate.Operator, Value: predicate.Value}
		switch predicate.Operator {
		case v1alpha1.OperatorIn:
			compiled.Set = make(map[string]struct{}, len(predicate.Values))
			for _, value := range predicate.Values {
				compiled.Set[value] = struct{}{}
			}
		case v1alpha1.OperatorInGroup:
			members, ok := groups[predicate.Value]
			if !ok {
				problem(v1alpha1.ProblemUnresolvedGroupReference,
					"group %q is defined by neither the policy nor the mapping of the domain",
					predicate.Value)
				continue
			}
			compiled.Set = members
			compiled.Fold = true
		}
		rule.Predicates = append(rule.Predicates, compiled)
	}

	for _, axis := range source.Counters {
		kind, known := keyKind(axis, env, captures)
		switch {
		case !known:
			problem(v1alpha1.ProblemUnresolvedKeyReference,
				"counter axis %q is not in the effective set: %s", axis, keyList(env, captures))
		case kind == KeyArray:
			problem(v1alpha1.ProblemInvalidCounterAxis,
				"counter axis %q is an array key, which cannot key a bucket", axis)
		}
	}

	for i := range source.Rates {
		rate, err := compileRate(&source.Rates[i])
		if err != nil {
			return nil, nil, err
		}
		rule.Rates = append(rule.Rates, rate)
	}
	return rule, problems, nil
}

func behavior(b v1alpha1.RuleBehavior) v1alpha1.RuleBehavior {
	if b == "" {
		return v1alpha1.RuleBehaviorEnforce
	}
	return b
}

// keyKind resolves a key name against the block. A capture wins over a mapped
// key of the same name, which is what makes the shadowing problem informational
// rather than an error.
func keyKind(name string, env *environment, captures map[string]struct{}) (KeyKind, bool) {
	if _, ok := captures[name]; ok {
		return KeyScalar, true
	}
	kind, ok := env.keys[name]
	return kind, ok
}

func keyList(env *environment, captures map[string]struct{}) string {
	names := make([]string, 0, len(env.keys)+len(captures))
	for name := range env.keys {
		names = append(names, name)
	}
	names = append(names, sortedKeys(captures)...)
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func compileRate(source *v1alpha1.Rate) (Rate, error) {
	period, err := ParsePeriod(source.Period)
	if err != nil {
		return Rate{}, err
	}
	rate := Rate{
		Requests:  int64(source.Requests),
		Period:    period,
		Algorithm: v1alpha1.AlgorithmGCRA,
	}
	if source.Algorithm == v1alpha1.AlgorithmFixedWindow {
		rate.Algorithm = v1alpha1.AlgorithmFixedWindow
	}
	if source.Burst != nil {
		rate.Burst = int64(*source.Burst)
	} else {
		// A full bucket is the default: a limit of 100 per minute with no burst
		// set admits 100 back to back and then meters.
		rate.Burst = rate.Requests
	}
	return rate, nil
}

// ParsePeriod reads a period written as one unit. time.ParseDuration is no help
// here: it rejects the d suffix the schema accepts and it accepts the compound
// forms the schema does not.
func ParsePeriod(period string) (time.Duration, error) {
	if len(period) < 2 {
		return 0, fmt.Errorf("period %q is not <number><s|m|h|d>", period)
	}
	count, err := strconv.ParseInt(period[:len(period)-1], 10, 32)
	if err != nil || count < 1 {
		return 0, fmt.Errorf("period %q is not <number><s|m|h|d>", period)
	}

	var unit time.Duration
	switch period[len(period)-1] {
	case 's':
		unit = time.Second
	case 'm':
		unit = time.Minute
	case 'h':
		unit = time.Hour
	case 'd':
		unit = 24 * time.Hour
	default:
		return 0, fmt.Errorf("period %q has no unit of s, m, h or d", period)
	}

	total := time.Duration(count) * unit
	if total < minPeriod || total > maxPeriod {
		return 0, fmt.Errorf("period %q is outside the range 1s to 1d", period)
	}
	return total, nil
}

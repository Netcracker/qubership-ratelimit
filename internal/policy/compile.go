// Package policy decides which generation of each policy the engine is given,
// and turns what the engine says back into object status.
//
// The rules themselves are compiled by the engine module, which knows nothing of
// Kubernetes. What lives here is the part that does: an invalid edit falls back
// to the last-good generation rather than taking the working rules down with it.
//
// A domain is one object, so there is nothing to arbitrate. The compilation of a
// domain is a pure function of its policy spec, and the only decision this
// package makes is which spec that is — the latest one, or the last good one.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	enginecompile "github.com/netcracker/qubership-ratelimit/engine/compile"
)

// Input is the set of objects one compilation reads, plus the last-good state of
// each domain.
type Input struct {
	// Namespace is the component's own, a segment of every counter key.
	Namespace string

	Policies []v1alpha1.RateLimitPolicy

	// State is the persisted last-good state, keyed by domain. An empty map is a
	// cold start: the latest specs are validated, and there is nothing to fall
	// back to.
	State map[string]Bundle
}

// Outcome is what compilation has to say about one policy: which generation it
// read, which one ended up in effect, and what the compiler found.
type Outcome struct {
	// UID identifies the object across recreations of the same name, which is
	// what makes a replica's report of an enforced generation comparable with
	// the leader's view of it.
	UID string

	// Generation is the latest generation, the one the problems are about.
	Generation int64

	// ActiveGeneration is the generation in effect. It differs from Generation
	// when the latest one does not compile and the last-good one keeps running;
	// zero means the domain is unprotected.
	ActiveGeneration int64

	// Problems describes the latest generation. A single blocking entry keeps it
	// out of the snapshot entirely.
	Problems []v1alpha1.RuleProblem

	// Err summarizes the blocking problems of the latest generation, and is nil
	// when it compiles.
	Err error

	// EffectiveKeys is the key set of the active generation, not of the
	// candidate: a rule author has to read what is in effect.
	EffectiveKeys []string

	// Blocks and Rules are what the active generation contributes.
	Blocks int
	Rules  int
}

// Compiled reports whether the latest generation compiles.
func (o Outcome) Compiled() bool { return o.Err == nil }

// Enforced reports whether the latest generation is the one in effect.
func (o Outcome) Enforced() bool {
	return o.Err == nil && o.ActiveGeneration == o.Generation
}

// Result is one compilation.
type Result struct {
	// Snapshots is what the engine evaluates, one per domain.
	Snapshots map[string]*enginecompile.Snapshot

	// Policies carries the per-object status, keyed by object.
	Policies map[client.ObjectKey]Outcome

	// State is the last-good state to persist, keyed by domain. It describes the
	// generations these snapshots were built from, so writing it before swapping
	// them leaves a crash in between recoverable.
	State map[string]Bundle
}

// Compile turns the policies of a namespace into one snapshot per domain.
//
// Compilation never fails as a whole: a policy it rejects is reported through
// its own outcome and falls back to its last-good generation, and the rest of
// the namespace keeps working. A single bad policy must not be able to turn the
// limits of another gateway off.
func Compile(in Input) *Result {
	result := &Result{
		Snapshots: make(map[string]*enginecompile.Snapshot),
		Policies:  make(map[client.ObjectKey]Outcome, len(in.Policies)),
		State:     make(map[string]Bundle),
	}

	for _, object := range sortedPolicies(in.Policies) {
		key := client.ObjectKeyFromObject(object)
		if object.Name != object.Spec.Domain {
			// The API server rejects such an object, so it can only arrive from
			// a client that bypassed validation. Taking it would make the
			// singleton a lie: two names could claim one domain.
			result.Policies[key] = Outcome{
				UID:        string(object.UID),
				Generation: object.Generation,
				Err: fmt.Errorf("metadata.name %q does not equal spec.domain %q",
					object.Name, object.Spec.Domain),
			}
			continue
		}
		outcome, snapshot, bundle := compileDomain(in.Namespace, object, in.State[object.Spec.Domain])
		result.Policies[key] = outcome
		result.Snapshots[object.Spec.Domain] = snapshot
		result.State[object.Spec.Domain] = bundle
	}
	return result
}

// compileDomain settles which generation of one policy is in effect.
//
// The latest generation runs when it compiles. When it does not, the last-good
// one does, and the status shows the divergence. When there is neither, the
// domain is claimed but empty: requests are allowed, which is different from
// the domain being unknown, and the snapshot has to say so.
func compileDomain(
	namespace string,
	object *v1alpha1.RateLimitPolicy,
	previous Bundle,
) (Outcome, *enginecompile.Snapshot, Bundle) {
	domain := object.Spec.Domain

	snapshot, problems := enginecompile.Compile(namespace, domain, modelPolicy(&object.Spec))
	outcome := Outcome{
		UID:        string(object.UID),
		Generation: object.Generation,
		Problems:   ruleProblems(problems),
		Err:        blockingError(problems),
	}

	if outcome.Compiled() {
		outcome.ActiveGeneration = object.Generation
		bundle := Bundle{
			UID:            string(object.UID),
			GoodGeneration: object.Generation,
			GoodSpec:       *object.Spec.DeepCopy(),
		}
		return withContribution(outcome, snapshot), snapshot, bundle
	}

	// The latest generation is invalid as a whole. Whatever was good last keeps
	// serving; the problems above still describe the latest one, because that
	// is the spec whose author is waiting for an answer.
	good := previous.good(string(object.UID))
	if good == nil {
		return outcome, snapshot, Bundle{}
	}

	fallback, fallbackProblems := enginecompile.Compile(namespace, domain, modelPolicy(&good.GoodSpec))
	if blockingError(fallbackProblems) != nil {
		// A persisted spec that no longer compiles means the component's own
		// rules changed under it. There is nothing left to fall back to.
		return outcome, snapshot, Bundle{}
	}
	outcome.ActiveGeneration = good.GoodGeneration
	return withContribution(outcome, fallback), fallback, *good
}

// withContribution records what the active generation put into the snapshot,
// and the key set it resolves against.
func withContribution(outcome Outcome, snapshot *enginecompile.Snapshot) Outcome {
	outcome.EffectiveKeys = snapshot.EffectiveKeys
	outcome.Blocks = len(snapshot.Blocks)
	for i := range snapshot.Blocks {
		outcome.Rules += len(snapshot.Blocks[i].Rules)
	}
	return outcome
}

// sortedPolicies orders the objects so that a compilation is a function of the
// set rather than of the order events arrived in.
func sortedPolicies(policies []v1alpha1.RateLimitPolicy) []*v1alpha1.RateLimitPolicy {
	out := make([]*v1alpha1.RateLimitPolicy, len(policies))
	for i := range policies {
		out[i] = &policies[i]
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Namespace != out[b].Namespace {
			return out[a].Namespace < out[b].Namespace
		}
		return out[a].Name < out[b].Name
	})
	return out
}

// ruleProblems renders the compiler's findings for the status.
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

// blockingError summarizes why a generation does not compile. The individual
// reasons stay in RuleProblems: conditions are a map by type, and a generation
// can break in several places at once.
func blockingError(problems []enginecompile.Problem) error {
	var reasons []string
	count := 0
	seen := map[enginecompile.Reason]struct{}{}
	for _, problem := range problems {
		if !problem.Blocking {
			continue
		}
		count++
		if _, dup := seen[problem.Reason]; dup {
			continue
		}
		seen[problem.Reason] = struct{}{}
		reasons = append(reasons, string(problem.Reason))
	}
	if count == 0 {
		return nil
	}
	return fmt.Errorf("%d blocking %s (%s)",
		count, plural(count, "problem"), strings.Join(reasons, ", "))
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// ErrNoGeneration is what a policy reports when neither its latest generation
// nor a last-good one is in effect: the domain is claimed but unprotected.
var ErrNoGeneration = errors.New("no generation is enforced: domain is unprotected")

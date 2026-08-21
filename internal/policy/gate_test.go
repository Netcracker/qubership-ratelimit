package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The domain gate: a candidate that would push the whole domain over its
// reference bounds yields to its own last-good generation, and a neighbor is
// never evicted for somebody else's edit.

// createdAt stamps a policy with a creation time, the causal order of the
// cold-start admission.
func createdAt(object v1alpha1.RateLimitPolicy, offset time.Duration) v1alpha1.RateLimitPolicy {
	object.CreationTimestamp = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(offset))
	return object
}

func TestGate_aCandidateEditYieldsToItsOwnLastGood(t *testing.T) {
	// Two seated neighbors fill the domain to its bound. The third policy's new
	// generation would overflow it, so the edit is refused and its previous
	// generation keeps running - the neighbors never notice.
	seatedA, seatedB := widePolicy64("a"), widePolicy64("b")

	small := policyObject("c", v1alpha1.LimitBlock{
		Name: "lift", Mode: v1alpha1.BlockModeFirstMatch,
		Rules: []v1alpha1.Rule{{Name: "all", Behavior: v1alpha1.RuleBehaviorBypass}},
	})
	edited := widePolicy64("c")
	edited.Generation = 2

	state := seatedBundle(seatedA, seatedB, small)
	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{seatedA, seatedB, edited},
		State:    map[string]Bundle{testDomain: state},
	})

	outcome := result.Policies[key("c")]
	assert.False(t, outcome.Ready())
	assert.Equal(t, v1alpha1.ReasonRejectedByDomainBudget, outcome.Reason)
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "the last-good generation keeps running")
	assert.NoError(t, outcome.Err, "the spec is structurally fine on its own")

	for _, name := range []string{"a", "b"} {
		assert.True(t, result.Policies[key(name)].Ready(), "a neighbor is never evicted")
	}
	assert.Empty(t, result.Warnings[testDomain], "the enforced set fits the bounds")
}

func TestGate_aSeatlessCandidateOverTheBoundRunsNothing(t *testing.T) {
	seatedA, seatedB := widePolicy64("a"), widePolicy64("b")
	fresh := widePolicy64("c")

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{seatedA, seatedB, fresh},
		State:    map[string]Bundle{testDomain: seatedBundle(seatedA, seatedB)},
	})

	outcome := result.Policies[key("c")]
	assert.False(t, outcome.Ready())
	assert.Equal(t, v1alpha1.ReasonRejectedByDomainBudget, outcome.Reason)
	assert.Zero(t, outcome.ActiveGeneration, "nothing of the newcomer is in effect")
	assert.Len(t, result.Snapshots[testDomain].Blocks, 2)
}

func TestGate_coldStartAdmitsInCreationOrder(t *testing.T) {
	// With no seats at all, the causal order decides who fits: the two oldest
	// objects are admitted and the newest yields, whatever the input order.
	oldest := createdAt(widePolicy64("zulu"), 0)
	middle := createdAt(widePolicy64("alpha"), time.Hour)
	newest := createdAt(widePolicy64("mike"), 2*time.Hour)

	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{middle, newest, oldest}})

	assert.True(t, result.Policies[key("zulu")].Ready())
	assert.True(t, result.Policies[key("alpha")].Ready())
	rejected := result.Policies[key("mike")]
	assert.False(t, rejected.Ready())
	assert.Equal(t, v1alpha1.ReasonRejectedByDomainBudget, rejected.Reason)
}

func TestGate_theBoundItselfStillFits(t *testing.T) {
	result := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{
		widePolicy64("a"), widePolicy64("b"),
	}})

	for name, outcome := range result.Policies {
		assert.True(t, outcome.Ready(), "policy %s: %+v", name, outcome)
	}
	assert.Empty(t, result.Warnings[testDomain])
}

func TestGate_isAFunctionOfTheSet(t *testing.T) {
	oldest := createdAt(widePolicy64("a"), 0)
	middle := createdAt(widePolicy64("b"), time.Hour)
	newest := createdAt(widePolicy64("c"), 2*time.Hour)

	first := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{oldest, middle, newest}})
	second := Compile(Input{Policies: []v1alpha1.RateLimitPolicy{newest, oldest, middle}})

	for _, name := range []string{"a", "b", "c"} {
		assert.Equal(t,
			first.Policies[key(name)].Ready(), second.Policies[key(name)].Ready(),
			"policy %s must not depend on input order", name)
	}
}

func TestGate_guardsTheBlockBoundToo(t *testing.T) {
	// Bypass-only FirstMatch blocks carry no buckets, so only the block bound
	// can refuse them: four seated policies fill it, the fifth yields.
	bypassBlocks := func(name string) v1alpha1.RateLimitPolicy {
		blocks := make([]v1alpha1.LimitBlock, 0, 64)
		for i := range 64 {
			blocks = append(blocks, v1alpha1.LimitBlock{
				Name: names("b", i), Mode: v1alpha1.BlockModeFirstMatch,
				Rules: []v1alpha1.Rule{{Name: "lift", Behavior: v1alpha1.RuleBehaviorBypass}},
			})
		}
		return policyObject(name, blocks...)
	}
	seated := []v1alpha1.RateLimitPolicy{
		bypassBlocks("a"), bypassBlocks("b"), bypassBlocks("c"), bypassBlocks("d"),
	}
	fifth := bypassBlocks("e")

	result := Compile(Input{
		Policies: append(append([]v1alpha1.RateLimitPolicy{}, seated...), fifth),
		State:    map[string]Bundle{testDomain: seatedBundle(seated...)},
	})

	outcome := result.Policies[key("e")]
	require.False(t, outcome.Ready())
	assert.Equal(t, v1alpha1.ReasonRejectedByDomainBudget, outcome.Reason)
	assert.Len(t, result.Snapshots[testDomain].Blocks, 256)
}

func names(prefix string, i int) string {
	return prefix + string(rune('a'+i/26)) + string(rune('a'+i%26))
}

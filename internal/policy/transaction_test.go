package policy

import (
	"encoding/base64"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The two specs a stuck object has — the latest one in etcd and the last-good one
// still running — are what these tests are about. A policy that references a
// mapped key is the smallest thing that can be broken by a mapping and fixed by
// one, so it is the fixture throughout.

func tenantPolicy(name string, generation int64, key string) v1alpha1.RateLimitPolicy {
	object := policyObject(name, v1alpha1.LimitBlock{
		Name: "api",
		Rules: []v1alpha1.Rule{
			simpleRule("per-tenant", v1alpha1.Predicate{Key: key, Operator: v1alpha1.OperatorExists}),
		},
	})
	object.Generation = generation
	object.UID = types.UID("uid-" + name)
	return object
}

func tenantMapping(generation int64, keys ...string) v1alpha1.RateLimitMapping {
	entries := make([]v1alpha1.ClaimMapping, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, v1alpha1.ClaimMapping{Key: key, Claim: "org_id"})
	}
	mapping := mappingObject(entries...)
	mapping.Generation = generation
	mapping.UID = "uid-mapping"
	return mapping
}

// bundleOf compiles once and returns the state that compilation would persist,
// which is how a test gets a realistic last-good bundle rather than a hand-built
// one.
func bundleOf(t *testing.T, in Input) Bundle {
	t.Helper()
	result := Compile(in)
	return result.State[testDomain]
}

func TestCompile_aLastGoodGenerationKeepsRunning(t *testing.T) {
	// The point of persisting it: an edit that does not compile must not take the
	// previous, working rules down with it.
	mapping := tenantMapping(1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 1, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})
	require.Len(t, good.Policies, 1)

	// Generation 2 references a key nothing produces.
	broken := tenantPolicy("orders", 2, "plan")

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{broken},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
		State:    map[string]Bundle{testDomain: good},
	})

	outcome := result.Policies[key("orders")]
	assert.Equal(t, int64(2), outcome.Generation)
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "generation 1 has to keep running")
	assert.False(t, outcome.Ready())
	assert.Len(t, result.Snapshots[testDomain].Blocks, 1)
}

func TestCompile_aLastGoodGenerationIsDroppedOnceTheLatestOneWorks(t *testing.T) {
	mapping := tenantMapping(1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 1, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	fixed := tenantPolicy("orders", 3, "tenant")
	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{fixed},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
		State:    map[string]Bundle{testDomain: good},
	})

	outcome := result.Policies[key("orders")]
	assert.Equal(t, int64(3), outcome.ActiveGeneration)
	assert.True(t, outcome.Ready())
	require.Len(t, result.State[testDomain].Policies, 1)
	assert.Equal(t, int64(3), result.State[testDomain].Policies[0].GoodGeneration,
		"the persisted state has to follow the generation that runs")
}

func TestCompile_aRecreatedObjectDoesNotInheritStateOfItsNamesake(t *testing.T) {
	// A different UID is a different object, and reviving the state of its
	// namesake would enforce a spec nobody wrote.
	mapping := tenantMapping(1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 1, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
	})

	recreated := tenantPolicy("orders", 1, "plan")
	recreated.UID = "a-different-object"

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{recreated},
		Mappings: []v1alpha1.RateLimitMapping{mapping},
		State:    map[string]Bundle{testDomain: good},
	})

	assert.Zero(t, result.Policies[key("orders")].ActiveGeneration)
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
}

func TestCompile_theGateVetoesAMappingThatWouldStopRunningRules(t *testing.T) {
	// The classic regression: the candidate drops a key a running policy depends
	// on.
	live := tenantPolicy("orders", 1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(1, "tenant")},
	})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		// Generation 2 renames tenant to org, which no policy references.
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "org")},
		State:    map[string]Bundle{testDomain: good},
	})

	outcome := result.Mappings[key(testDomain)]
	assert.Equal(t, int64(2), outcome.Generation)
	assert.Equal(t, int64(1), outcome.ActiveGeneration, "the running generation has to stay")
	assert.False(t, outcome.Ready())
	require.Len(t, outcome.RejectedBy, 1)
	assert.Equal(t, "orders", outcome.RejectedBy[0].Policy)
	assert.Equal(t, int64(1), outcome.RejectedBy[0].Generation)
	assert.Equal(t, "per-tenant", outcome.RejectedBy[0].Rule)
	assert.Equal(t, v1alpha1.ProblemUnresolvedKeyReference, outcome.RejectedBy[0].Reason)

	assert.Contains(t, outcome.EffectiveKeys, "tenant",
		"the effective keys report the active generation, not the candidate")
	assert.True(t, result.Policies[key("orders")].Ready(),
		"a vetoed candidate leaves the policies exactly as they were")
}

func TestCompile_theGateAcceptsAMappingThatOnlyAddsKeys(t *testing.T) {
	live := tenantPolicy("orders", 1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(1, "tenant")},
	})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "tenant", "region")},
		State:    map[string]Bundle{testDomain: good},
	})

	outcome := result.Mappings[key(testDomain)]
	assert.Equal(t, int64(2), outcome.ActiveGeneration)
	assert.True(t, outcome.Ready())
	assert.Empty(t, outcome.RejectedBy)
	assert.Contains(t, outcome.EffectiveKeys, "region")
}

func TestCompile_anAlreadyBrokenPolicyHasNoVote(t *testing.T) {
	// A vote is a veto, and only the policies a candidate makes worse get one. If
	// the gate demanded validity of every policy it would jam forever: one team's
	// typo would freeze a platform resource for the whole domain.
	live := tenantPolicy("orders", 1, "tenant")
	typo := tenantPolicy("quotes", 1, "plann")

	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{live, typo},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(1, "tenant")},
	})
	require.Len(t, good.Policies, 1, "only the healthy policy is running")

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live, typo},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "tenant", "region")},
		State:    map[string]Bundle{testDomain: good},
	})

	assert.Empty(t, result.Mappings[key(testDomain)].RejectedBy)
	assert.Equal(t, int64(2), result.Mappings[key(testDomain)].ActiveGeneration)
	assert.False(t, result.Policies[key("quotes")].Ready(),
		"the broken policy is not forgotten, it is just not consulted")
}

func TestCompile_theGateLetsAMappingFixAStuckPolicy(t *testing.T) {
	// The priority inside "what would run after" is what makes this work: as soon
	// as the desired spec is valid under the candidate, it is the one that would
	// run. Without it a stale last-good spec would demand compatibility with
	// itself forever.
	mappingV1 := tenantMapping(1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 1, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{mappingV1},
	})

	// Generation 2 of the policy references a key the mapping does not declare
	// yet, so it is stuck on generation 1.
	stuck := tenantPolicy("orders", 2, "region")
	stuckResult := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{stuck},
		Mappings: []v1alpha1.RateLimitMapping{mappingV1},
		State:    map[string]Bundle{testDomain: good},
	})
	require.Equal(t, int64(1), stuckResult.Policies[key("orders")].ActiveGeneration)

	// The mapping now declares region, and drops tenant along the way. The stuck
	// policy converges rather than vetoing: its own latest spec becomes valid.
	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{stuck},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "region")},
		State:    map[string]Bundle{testDomain: stuckResult.State[testDomain]},
	})

	assert.Empty(t, result.Mappings[key(testDomain)].RejectedBy)
	assert.Equal(t, int64(2), result.Mappings[key(testDomain)].ActiveGeneration)

	outcome := result.Policies[key("orders")]
	assert.Equal(t, int64(2), outcome.ActiveGeneration)
	assert.True(t, outcome.Ready(), "the policy converges on its own latest generation")
}

func TestCompile_theGateReportsTheGenerationThatWasRunning(t *testing.T) {
	// The veto can come from a spec that no longer exists in etcd. Reporting the
	// latest generation instead would name a spec that does not explain the veto.
	mappingV1 := tenantMapping(1, "tenant")
	good := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 1, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{mappingV1},
	})

	// Generation 2 is broken by its own spec, so generation 1 keeps running.
	stuck := tenantPolicy("orders", 2, "plan")
	stuckResult := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{stuck},
		Mappings: []v1alpha1.RateLimitMapping{mappingV1},
		State:    map[string]Bundle{testDomain: good},
	})
	require.Equal(t, int64(1), stuckResult.Policies[key("orders")].ActiveGeneration)

	// A candidate dropping tenant would leave the policy with nothing at all:
	// neither its latest spec nor the one that is running would be valid.
	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{stuck},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "org")},
		State:    map[string]Bundle{testDomain: stuckResult.State[testDomain]},
	})

	rejectedBy := result.Mappings[key(testDomain)].RejectedBy
	require.Len(t, rejectedBy, 1)
	assert.Equal(t, int64(1), rejectedBy[0].Generation,
		"the vetoing generation is the one that was running, not the latest in etcd")
}

func TestCompile_expandThenContractIsHowAKeyIsRenamed(t *testing.T) {
	// A deliberately breaking change goes in two steps, and the gate is what says
	// when the second one is safe.
	live := tenantPolicy("orders", 1, "tenant")
	state := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(1, "tenant")},
	})

	// Expand: both names, so nothing regresses.
	expanded := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "tenant", "org")},
		State:    map[string]Bundle{testDomain: state},
	})
	require.Empty(t, expanded.Mappings[key(testDomain)].RejectedBy)

	// Contract too early: the policy still uses the old name.
	tooEarly := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(3, "org")},
		State:    map[string]Bundle{testDomain: expanded.State[testDomain]},
	})
	require.Len(t, tooEarly.Mappings[key(testDomain)].RejectedBy, 1,
		"the gate names who has not migrated yet")

	// Migrate the policy, then contract.
	migrated := tenantPolicy("orders", 2, "org")
	afterMigration := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{migrated},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "tenant", "org")},
		State:    map[string]Bundle{testDomain: expanded.State[testDomain]},
	})
	require.True(t, afterMigration.Policies[key("orders")].Ready())

	contracted := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{migrated},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(3, "org")},
		State:    map[string]Bundle{testDomain: afterMigration.State[testDomain]},
	})

	assert.Empty(t, contracted.Mappings[key(testDomain)].RejectedBy)
	assert.Equal(t, int64(3), contracted.Mappings[key(testDomain)].ActiveGeneration)
}

func TestCompile_theGateRunsOnTheFirstMappingToo(t *testing.T) {
	// A first mapping usually only adds keys, but it can also redefine client as
	// an array — and that invalidates every rule counting by client.
	live := policyObject("orders", v1alpha1.LimitBlock{
		Name: "api",
		Rules: []v1alpha1.Rule{{
			Name:     "per-user",
			Counters: []string{"client"},
			Rates:    []v1alpha1.Rate{minuteRate(100)},
		}},
	})
	live.Generation, live.UID = 1, "uid-orders"

	state := bundleOf(t, Input{Policies: []v1alpha1.RateLimitPolicy{live}})
	require.Len(t, state.Policies, 1)

	arrayClient := mappingObject(v1alpha1.ClaimMapping{
		Key: "client", Claim: "groups", Type: v1alpha1.ClaimTypeStringArray,
	})
	arrayClient.Generation, arrayClient.UID = 1, "uid-mapping"

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{arrayClient},
		State:    map[string]Bundle{testDomain: state},
	})

	outcome := result.Mappings[key(testDomain)]
	require.Len(t, outcome.RejectedBy, 1)
	assert.Equal(t, v1alpha1.ProblemInvalidCounterAxis, outcome.RejectedBy[0].Reason)
	assert.Zero(t, outcome.ActiveGeneration, "with nothing to fall back to the domain keeps its built-ins")
	assert.True(t, result.Policies[key("orders")].Ready())
}

func TestCompile_deletingAMappingIsOutsideTheGate(t *testing.T) {
	// A deliberate administrative act: the domain falls back to its built-in keys
	// and the policies depending on the mapping lose validity. RBAC is the guard
	// against doing it by accident, not the controller.
	live := tenantPolicy("orders", 1, "tenant")
	state := bundleOf(t, Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(1, "tenant")},
	})

	result := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{live},
		State:    map[string]Bundle{testDomain: state},
	})

	assert.Zero(t, result.Policies[key("orders")].ActiveGeneration)
	assert.Equal(t, v1alpha1.ReasonMappingRequired, result.Policies[key("orders")].Reason)
	assert.Empty(t, result.Snapshots[testDomain].Blocks)
	assert.Nil(t, result.State[testDomain].Mapping, "the last-good mapping goes with the object")
}

func TestCompile_stateOfAnUnchangedDomainIsStable(t *testing.T) {
	// The bundle is compared by its encoding before being written, so an unchanged
	// domain must encode the same way twice.
	in := Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 1, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(1, "tenant")},
	}

	first, err := EncodeBundle(Compile(in).State[testDomain])
	require.NoError(t, err)
	second, err := EncodeBundle(Compile(in).State[testDomain])
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

func TestBundle_roundTripsThroughItsEncoding(t *testing.T) {
	original := Compile(Input{
		Policies: []v1alpha1.RateLimitPolicy{tenantPolicy("orders", 4, "tenant")},
		Mappings: []v1alpha1.RateLimitMapping{tenantMapping(2, "tenant")},
	}).State[testDomain]

	encoded, err := EncodeBundle(original)
	require.NoError(t, err)

	decoded, err := DecodeBundle(encoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
	require.NotNil(t, decoded.Mapping)
	assert.Equal(t, int64(2), decoded.Mapping.GoodGeneration)
	require.Len(t, decoded.Policies, 1)
	assert.Equal(t, int64(4), decoded.Policies[0].GoodGeneration)
}

func TestEncodeBundle_refusesToWriteMoreThanAConfigMapHolds(t *testing.T) {
	// The object would lose its last-good spec across a restart, which is worth an
	// error rather than a write the API server rejects.
	object := tenantPolicy("orders", 1, "tenant")
	// Random values, because a group of repeated strings compresses away and would
	// never reach the limit however long the list got.
	random := rand.New(rand.NewPCG(1, 2))
	group := v1alpha1.ClientGroup{Name: "big"}
	for range 8000 {
		value := make([]byte, 190)
		for i := range value {
			value[i] = byte(random.UintN(256))
		}
		group.Clients = append(group.Clients, base64.RawStdEncoding.EncodeToString(value))
	}
	object.Spec.Groups = []v1alpha1.ClientGroup{group}

	bundle := Bundle{Policies: []PolicyState{{
		Name: "orders", UID: "uid", GoodGeneration: 1, GoodSpec: object.Spec,
	}}}

	_, err := EncodeBundle(bundle)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "over the")
}

func TestDecodeBundle_reportsSomethingThatIsNotABundle(t *testing.T) {
	_, err := DecodeBundle([]byte("not gzip at all"))

	require.Error(t, err)
}

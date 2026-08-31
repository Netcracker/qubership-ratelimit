package management

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/internal/ruleview"
)

// The property the evaluator has to hold: always means every completion of the
// unknown identity applies the rule, never means no completion does, and
// conditional is everything between with its gates named. The tests below work
// the cascade fixture, where "everyone" is reachable only when neither the
// bypass nor the premium rule matched first.

// annotationsFor runs the analysis over the fixture and returns the annotation
// of every rule, by id.
func annotationsFor(t *testing.T, query string) map[string]ruleview.RuleView {
	t.Helper()

	snapshot := compileSnapshot(t, quotePolicy(), orderPolicy())
	values, err := url.ParseQuery(query)
	require.NoError(t, err)

	sc, apiErr := parseScope(snapshot, values)
	require.Nil(t, apiErr, "scope: %+v", apiErr)
	require.True(t, sc.present)

	out := map[string]ruleview.RuleView{}
	for i := range snapshot.Blocks {
		block := &snapshot.Blocks[i]
		view := ruleview.Block(block)
		annotate(block, &view, sc)
		for _, rule := range view.Rules {
			out[rule.ID] = rule
		}
	}
	return out
}

func gateReasons(rule ruleview.RuleView) []string {
	out := make([]string, 0, len(rule.ConditionalOn))
	for _, gate := range rule.ConditionalOn {
		out = append(out, gate.Reason)
	}
	return out
}

func TestApplicability_clientAloneLeavesThePlanUndecided(t *testing.T) {
	rules := annotationsFor(t, "axis.client=alice")

	// The bypass names another client, so it is out for every completion.
	require.Equal(t, ruleview.ApplicabilityNever, rules["quote-api/cascade/internal"].Applicability)

	// Premium turns on a claim the caller did not supply.
	premium := rules["quote-api/cascade/premium"]
	require.Equal(t, ruleview.ApplicabilityConditional, premium.Applicability)
	require.Equal(t, []string{ruleview.GateUndecidedCondition}, gateReasons(premium))
	require.Equal(t, "plan", premium.ConditionalOn[0].Key)

	// And everyone is behind premium in the cascade.
	everyone := rules["quote-api/cascade/everyone"]
	require.Equal(t, ruleview.ApplicabilityConditional, everyone.Applicability)
	require.Equal(t, []string{ruleview.GateMayBePreempted}, gateReasons(everyone))
	require.Equal(t, "quote-api/cascade/premium", everyone.ConditionalOn[0].Rule)
}

func TestApplicability_decidingThePlanDecidesTheCascade(t *testing.T) {
	rules := annotationsFor(t, "axis.client=alice&axis.plan=premium")

	require.Equal(t, ruleview.ApplicabilityAlways, rules["quote-api/cascade/premium"].Applicability)
	// Premium matches for every completion now, so everyone is unreachable.
	require.Equal(t, ruleview.ApplicabilityNever, rules["quote-api/cascade/everyone"].Applicability)
}

func TestApplicability_aFailedConditionEndsTheCascadeAhead(t *testing.T) {
	rules := annotationsFor(t, "axis.client=alice&axis.plan=free")

	require.Equal(t, ruleview.ApplicabilityNever, rules["quote-api/cascade/premium"].Applicability)
	// Nothing ahead of everyone can match any more, and its own axis is named.
	require.Equal(t, ruleview.ApplicabilityAlways, rules["quote-api/cascade/everyone"].Applicability)
}

func TestApplicability_theExemptClientSilencesEverythingBehindIt(t *testing.T) {
	rules := annotationsFor(t, "axis.client=prometheus")

	require.Equal(t, ruleview.ApplicabilityAlways, rules["quote-api/cascade/internal"].Applicability)
	require.Equal(t, ruleview.ApplicabilityNever, rules["quote-api/cascade/premium"].Applicability)
	require.Equal(t, ruleview.ApplicabilityNever, rules["quote-api/cascade/everyone"].Applicability)
}

func TestApplicability_replacesPreemptsInsideAnAllBlock(t *testing.T) {
	// The support rule replaces per-client, and whether it matches turns on a
	// role the caller did not name.
	rules := annotationsFor(t, "axis.client=alice")

	support := rules["api/orders/support"]
	require.Equal(t, ruleview.ApplicabilityConditional, support.Applicability)
	require.Equal(t, []string{ruleview.GateUndecidedCondition}, gateReasons(support))

	perClient := rules["api/orders/per-client"]
	require.Equal(t, ruleview.ApplicabilityConditional, perClient.Applicability)
	require.Equal(t, []string{ruleview.GateMayBePreempted}, gateReasons(perClient))
	require.Equal(t, "api/orders/support", perClient.ConditionalOn[0].Rule)
}

func TestApplicability_aCompleteRoleSetDecidesContains(t *testing.T) {
	// roles is list-valued, so the supplied values are the whole set: support
	// is not in it, which settles the condition rather than leaving it open.
	rules := annotationsFor(t, "axis.client=alice&axis.roles=billing&axis.roles=readonly")

	require.Equal(t, ruleview.ApplicabilityNever, rules["api/orders/support"].Applicability)
	require.Equal(t, ruleview.ApplicabilityAlways, rules["api/orders/per-client"].Applicability)
}

func TestApplicability_anAbsentKeyVoidsTheRulesReadingIt(t *testing.T) {
	rules := annotationsFor(t, "axis.client=alice&absent=roles&absent=plan")

	require.Equal(t, ruleview.ApplicabilityNever, rules["api/orders/support"].Applicability)
	require.Equal(t, ruleview.ApplicabilityNever, rules["quote-api/cascade/premium"].Applicability)
	require.Equal(t, ruleview.ApplicabilityAlways, rules["quote-api/cascade/everyone"].Applicability)
}

// A block's captures are produced by any request that reaches its template
// route, so an axis over one is available even though its value is unknown.
func TestApplicability_captureAxesCountAsAvailable(t *testing.T) {
	rules := annotationsFor(t, "axis.client=alice")
	require.Equal(t, ruleview.ApplicabilityAlways, rules["api/by-order/each"].Applicability)
}

// An unnamed counter axis keeps a rule conditional: the rule applies only to
// requests that produce a value for it.
func TestApplicability_anUnnamedAxisIsAGate(t *testing.T) {
	rules := annotationsFor(t, "absent=plan")

	everyone := rules["quote-api/cascade/everyone"]
	require.Equal(t, ruleview.ApplicabilityConditional, everyone.Applicability)
	// Its own axis is unnamed, and the bypass ahead of it turns on the same
	// unnamed client — two independent gates, both reported.
	require.Equal(t,
		[]string{ruleview.GateMissingAxis, ruleview.GateMayBePreempted}, gateReasons(everyone))
	require.Equal(t, "client", everyone.ConditionalOn[0].Key)
	require.Equal(t, "quote-api/cascade/internal", everyone.ConditionalOn[1].Rule)
}

// Deciding a condition decides the axis it reads too, so the gates say each
// thing once: no missing_axis beside an undecided_condition on the same key.
func TestApplicability_gatesAreMinimal(t *testing.T) {
	snapshot := compileSnapshot(t, quotePolicy())
	sc, apiErr := parseScope(snapshot, url.Values{"absent": {"plan"}})
	require.Nil(t, apiErr)

	block := findBlock(t, snapshot, "quote-api", "cascade")
	view := ruleview.Block(block)
	annotate(block, &view, sc)

	// The bypass rule reads client and counts by nothing; everyone counts by
	// client and reads nothing. Neither can report the same key twice.
	for _, rule := range view.Rules {
		seen := map[string]struct{}{}
		for _, gate := range rule.ConditionalOn {
			if gate.Key == "" {
				continue
			}
			_, duplicate := seen[gate.Key]
			require.False(t, duplicate, "rule %s reports key %s twice", rule.ID, gate.Key)
			seen[gate.Key] = struct{}{}
		}
	}
}

// Adding an axis may only sharpen the answer: a rule never moves back from
// never or always into conditional.
func TestApplicability_sharpensMonotonically(t *testing.T) {
	broad := annotationsFor(t, "axis.client=alice")
	narrow := annotationsFor(t, "axis.client=alice&axis.plan=premium")

	for id, before := range broad {
		after, ok := narrow[id]
		require.True(t, ok)
		if before.Applicability == ruleview.ApplicabilityConditional {
			continue
		}
		require.Equal(t, before.Applicability, after.Applicability,
			"rule %s moved from %s to %s", id, before.Applicability, after.Applicability)
	}
}

func TestParseScope_refusesWhatItCannotAnswer(t *testing.T) {
	snapshot := compileSnapshot(t, quotePolicy(), orderPolicy())

	cases := map[string]url.Values{
		"an unknown axis name":        {"axis.tenant": {"acme"}},
		"an unknown absent name":      {"absent": {"tenant"}},
		"a repeated scalar key":       {"axis.client": {"alice", "bob"}},
		"an empty axis value":         {"axis.client": {""}},
		"a key both given and absent": {"axis.plan": {"premium"}, "absent": {"plan"}},
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			_, apiErr := parseScope(snapshot, query)
			require.NotNil(t, apiErr)
			require.Equal(t, CodeInvalidRequest, apiErr.GetErrorCode())
		})
	}
}

func TestParseScope_isAbsentWithoutIdentityParameters(t *testing.T) {
	snapshot := compileSnapshot(t, quotePolicy())
	sc, apiErr := parseScope(snapshot, url.Values{"path": {"/api/quotes/1"}})
	require.Nil(t, apiErr)
	require.False(t, sc.present)
}

func findBlock(t *testing.T, snapshot *compile.Snapshot, policy, name string) *compile.Block {
	t.Helper()
	for i := range snapshot.Blocks {
		if snapshot.Blocks[i].Policy == policy && snapshot.Blocks[i].Name == name {
			return &snapshot.Blocks[i]
		}
	}
	t.Fatalf("no block %s/%s in the snapshot", policy, name)
	return nil
}

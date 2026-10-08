package management

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
)

// The property the evaluator has to hold: always means every completion of the
// unknown identity applies the rule, never means no completion does, and
// conditional is everything between with its gates named. Unless a test names
// other blocks, the tests in this file work the cascade fixture, where
// "everyone" is reachable only when neither the bypass nor the premium rule
// matched first.

// annotationsFor runs the analysis of query over blocks, or over the cascade
// and the orders fixtures when no block is given, and returns the annotation
// of every rule, by id.
func annotationsFor(t *testing.T, query string, blocks ...model.Block) map[string]annotation {
	t.Helper()

	if len(blocks) == 0 {
		blocks = append(cascadeBlocks(), orderBlocks()...)
	}
	snapshot := compileSnapshot(t, blocks)
	values, err := url.ParseQuery(query)
	require.NoError(t, err)

	sc, apiErr := parseScope(snapshot, values)
	require.Nil(t, apiErr, "parseScope(%q)", query)
	require.True(t, sc.present, "parseScope(%q) found no identity to annotate for", query)

	var view ruleview.RuleSetView
	for i := range snapshot.Blocks {
		block := &snapshot.Blocks[i]
		rendered := ruleview.Block(block)
		annotate(block, &rendered, sc)
		view.Blocks = append(view.Blocks, rendered)
	}
	return annotationsByID(view)
}

func TestApplicability_subAloneLeavesThePlanUndecided(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice")

	// The bypass names another client, so it is out for every completion.
	assert.Equal(t, annotation{Applicability: ruleview.ApplicabilityNever}, rules["cascade/internal"],
		"cascade/internal")

	// Premium turns on a claim the caller did not supply.
	assert.Equal(t, annotation{
		Applicability: ruleview.ApplicabilityConditional,
		ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "plan"}},
	}, rules["cascade/premium"], "cascade/premium")

	// And everyone is behind premium in the cascade.
	assert.Equal(t, annotation{
		Applicability: ruleview.ApplicabilityConditional,
		ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateMayBePreempted, Rule: "cascade/premium"}},
	}, rules["cascade/everyone"], "cascade/everyone")
}

func TestApplicability_decidingThePlanDecidesTheCascade(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice&axis.plan=premium")

	assert.Equal(t, ruleview.ApplicabilityAlways, rules["cascade/premium"].Applicability, "cascade/premium")
	// Premium matches for every completion now, so everyone is unreachable.
	assert.Equal(t, ruleview.ApplicabilityNever, rules["cascade/everyone"].Applicability, "cascade/everyone")
}

func TestApplicability_aFailedConditionEndsTheCascadeAhead(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice&axis.plan=free")

	assert.Equal(t, ruleview.ApplicabilityNever, rules["cascade/premium"].Applicability, "cascade/premium")
	// Nothing ahead of everyone can match any more, and its own axis is named.
	assert.Equal(t, ruleview.ApplicabilityAlways, rules["cascade/everyone"].Applicability, "cascade/everyone")
}

func TestApplicability_theExemptClientSilencesEverythingBehindIt(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=prometheus")

	assert.Equal(t, ruleview.ApplicabilityAlways, rules["cascade/internal"].Applicability, "cascade/internal")
	assert.Equal(t, ruleview.ApplicabilityNever, rules["cascade/premium"].Applicability, "cascade/premium")
	assert.Equal(t, ruleview.ApplicabilityNever, rules["cascade/everyone"].Applicability, "cascade/everyone")
}

// The support rule replaces per-client, and whether it matches turns on a role
// the caller did not name.
func TestApplicability_replacesPreemptsInsideAnAllBlock(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice")

	assert.Equal(t, annotation{
		Applicability: ruleview.ApplicabilityConditional,
		ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "roles"}},
	}, rules["orders/support"], "orders/support")
	assert.Equal(t, annotation{
		Applicability: ruleview.ApplicabilityConditional,
		ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateMayBePreempted, Rule: "orders/support"}},
	}, rules["orders/per-client"], "orders/per-client")
}

// A Shadow rule's replaces suppress nothing, so the rule it names applies to
// a request the Shadow rule matches. The listing used to report it never
// applying, while the decision path enforced it.
func TestApplicability_aShadowRuleReplacesNothing(t *testing.T) {
	blocks := orderBlocks()
	blocks[0].Rules[1].Behavior = model.BehaviorShadow

	rules := annotationsFor(t, "axis.sub=alice&axis.roles=support", append(cascadeBlocks(), blocks...)...)

	assert.Equal(t, ruleview.ApplicabilityAlways, rules["orders/per-client"].Applicability,
		"orders/per-client, which the Shadow rule orders/support names")
}

// roles is list-valued, so the supplied values are the whole set: support is
// not in it, which settles the condition rather than leaving it open.
func TestApplicability_aCompleteRoleSetDecidesContains(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice&axis.roles=billing&axis.roles=readonly")

	assert.Equal(t, ruleview.ApplicabilityNever, rules["orders/support"].Applicability, "orders/support")
	assert.Equal(t, ruleview.ApplicabilityAlways, rules["orders/per-client"].Applicability, "orders/per-client")
}

func TestApplicability_anAbsentKeyVoidsTheRulesReadingIt(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice&absent=roles&absent=plan")

	assert.Equal(t, ruleview.ApplicabilityNever, rules["orders/support"].Applicability, "orders/support")
	assert.Equal(t, ruleview.ApplicabilityNever, rules["cascade/premium"].Applicability, "cascade/premium")
	assert.Equal(t, ruleview.ApplicabilityAlways, rules["cascade/everyone"].Applicability, "cascade/everyone")
}

// A capture every route of a block produces is carried by any request that
// reaches the block, so an axis over one is available even though its value
// is unknown; by-order has one template route and nothing else.
func TestApplicability_captureAxesCountAsAvailable(t *testing.T) {
	rules := annotationsFor(t, "axis.sub=alice")
	assert.Equal(t, ruleview.ApplicabilityAlways, rules["by-order/each"].Applicability, "by-order/each")
}

// An unnamed counter axis keeps a rule conditional: the rule applies only to
// requests that produce a value for it. Its own axis is unnamed, and the bypass
// ahead of it turns on the same unnamed client: two independent gates, both
// reported.
func TestApplicability_anUnnamedAxisIsAGate(t *testing.T) {
	rules := annotationsFor(t, "absent=plan")

	assert.Equal(t, annotation{
		Applicability: ruleview.ApplicabilityConditional,
		ConditionalOn: []ruleview.ApplicabilityGate{
			{Reason: ruleview.GateMissingAxis, Key: "sub"},
			{Reason: ruleview.GateMayBePreempted, Rule: "cascade/internal"},
		},
	}, rules["cascade/everyone"], "cascade/everyone")
}

// Deciding a condition decides the axis it reads too, so the gates say each
// thing once: no missing_axis beside an undecided_condition on the same key.
func TestApplicability_namesEachUndecidedKeyOnce(t *testing.T) {
	t.Run("a rule that reads and counts by one key", func(t *testing.T) {
		// items-per-order requires order_id and counts by it; without a path
		// the capture is open.
		rules := annotationsFor(t, "axis.sub=dave", orderCascadeBlocks()...)

		assert.Equal(t, []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "order_id"}},
			rules["order-ops/items-per-order"].ConditionalOn, "order-ops/items-per-order")
	})

	t.Run("a cascade whose rules read and count by different keys", func(t *testing.T) {
		// The bypass rule reads sub and counts by nothing; everyone counts by
		// sub and reads nothing.
		rules := annotationsFor(t, "absent=plan", cascadeBlocks()...)

		assert.Equal(t, map[string]annotation{
			"cascade/internal": {
				Applicability: ruleview.ApplicabilityConditional,
				ConditionalOn: []ruleview.ApplicabilityGate{{Reason: ruleview.GateUndecidedCondition, Key: "sub"}},
			},
			"cascade/premium": {Applicability: ruleview.ApplicabilityNever},
			"cascade/everyone": {
				Applicability: ruleview.ApplicabilityConditional,
				ConditionalOn: []ruleview.ApplicabilityGate{
					{Reason: ruleview.GateMissingAxis, Key: "sub"},
					{Reason: ruleview.GateMayBePreempted, Rule: "cascade/internal"},
				},
			},
		}, rules)
	})
}

// Adding an axis may only sharpen the answer: a rule the broader scope decides
// keeps that decision, and never moves back into conditional.
func TestApplicability_namingAnotherKeyKeepsEveryDecidedRule(t *testing.T) {
	broad := annotationsFor(t, "axis.sub=alice")
	narrow := annotationsFor(t, "axis.sub=alice&axis.plan=premium")

	decided := map[string]string{}
	for id, rule := range broad {
		if rule.Applicability != ruleview.ApplicabilityConditional {
			decided[id] = rule.Applicability
		}
	}
	require.NotEmpty(t, decided, "axis.sub=alice decides no rule, so nothing can be kept")

	kept := map[string]string{}
	for id := range decided {
		kept[id] = narrow[id].Applicability
	}
	assert.Equal(t, decided, kept, "the decisions of axis.sub=alice under axis.sub=alice&axis.plan=premium")
}

func TestParseScope_refusesWhatItCannotAnswer(t *testing.T) {
	snapshot := compileSnapshot(t, append(cascadeBlocks(), orderBlocks()...))

	cases := []struct {
		name  string
		query url.Values
		field string
	}{
		{name: "an unknown axis name", query: url.Values{"axis.tenant": {"acme"}}, field: "axis.tenant"},
		{name: "an unknown absent name", query: url.Values{"absent": {"tenant"}}, field: "absent"},
		{name: "a repeated scalar key", query: url.Values{"axis.sub": {"alice", "bob"}}, field: "axis.sub"},
		{name: "an empty axis value", query: url.Values{"axis.sub": {""}}, field: "axis.sub"},
		{
			name:  "a key both given and absent",
			query: url.Values{"axis.plan": {"premium"}, "absent": {"plan"}},
			field: "absent",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, apiErr := parseScope(snapshot, tc.query)
			require.NotNil(t, apiErr, "parseScope(%v)", tc.query)
			assert.Equal(t, CodeInvalidRequest, apiErr.GetErrorCode(), "parseScope(%v)", tc.query)
			assert.Equal(t, []string{tc.field}, apiErr.fields, "parseScope(%v)", tc.query)
		})
	}
}

func TestParseScope_isAbsentWithoutIdentityParameters(t *testing.T) {
	snapshot := compileSnapshot(t, cascadeBlocks())
	sc, apiErr := parseScope(snapshot, url.Values{"path": {"/api/invoices/1"}})
	require.Nil(t, apiErr, "parseScope(path=/api/invoices/1)")
	assert.False(t, sc.present, "parseScope(path=/api/invoices/1) found an identity")
}

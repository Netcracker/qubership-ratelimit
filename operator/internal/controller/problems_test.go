package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	ratelimitv1 "github.com/netcracker/qubership-ratelimit/api/v1"
)

// A message past the CRD's bound makes the API server refuse the whole
// status write, so the author sees nothing at all. A long Template route with
// a structural mistake produces exactly such a message: the template is
// quoted whole.
func TestBoundedProblems_cutsAMessageToTheCRDBound(t *testing.T) {
	long := `template "/` + strings.Repeat("segment/", 200) + `" has an empty segment`
	require.Greater(t, utf8.RuneCountInString(long), ratelimitv1.MaxRuleProblemMessage)

	got := boundedProblems([]ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemInvalidSpec, Message: long}})
	require.Len(t, got, 1)
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, utf8.RuneCountInString(got[0].Message))
	assert.True(t, strings.HasSuffix(got[0].Message, "..."))

	short := boundedProblems([]ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemInvalidSpec, Message: "short"}})
	assert.Equal(t, "short", short[0].Message)
}

// The cut counts characters, as the API server does, and never splits one.
func TestBoundedProblems_cutsOnACharacterBoundary(t *testing.T) {
	long := strings.Repeat("я", ratelimitv1.MaxRuleProblemMessage+10)
	got := boundedProblems([]ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemInvalidSpec, Message: long}})
	assert.True(t, utf8.ValidString(got[0].Message))
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, utf8.RuneCountInString(got[0].Message))
}

// Past the list bound the blocking entries come first: they are why the
// generation is not enforced, and an informational note must not push one
// out.
func TestBoundedProblems_keepsTheBlockingEntriesPastTheListBound(t *testing.T) {
	problems := make([]ratelimitv1.RuleProblem, 0, ratelimitv1.MaxRuleProblems+2)
	for range ratelimitv1.MaxRuleProblems {
		problems = append(problems, ratelimitv1.RuleProblem{Reason: ratelimitv1.ProblemCaptureShadowsMappedKey})
	}
	problems = append(problems,
		ratelimitv1.RuleProblem{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "late"},
		ratelimitv1.RuleProblem{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "later"})
	require.False(t, ratelimitv1.BlockingProblem(ratelimitv1.ProblemCaptureShadowsMappedKey))
	require.True(t, ratelimitv1.BlockingProblem(ratelimitv1.ProblemInvalidSpec))

	got := boundedProblems(problems)
	require.Len(t, got, ratelimitv1.MaxRuleProblems)
	assert.Equal(t, "late", got[0].Rule)
	assert.Equal(t, "later", got[1].Rule)

	// Within the bound the order is the compiler's, untouched.
	few := problems[len(problems)-3:]
	assert.Equal(t, few, boundedProblems(few))
}

// The constants the operator bounds the list by are the numbers the CRD
// enforces. The markers cannot name a constant, so the generated schema is
// read back and compared.
func TestRuleProblemBounds_matchTheGeneratedCRD(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "bases",
		"ratelimit.netcracker.com_ratelimitpolicies.yaml"))
	require.NoError(t, err)
	var crd map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &crd))

	at := func(v any, path ...string) any {
		for _, key := range path {
			m, ok := v.(map[string]any)
			require.True(t, ok, "no %s in %v", key, path)
			v = m[key]
		}
		return v
	}
	versions := at(crd, "spec", "versions").([]any)
	require.Len(t, versions, 1)
	list := at(versions[0], "schema", "openAPIV3Schema", "properties", "status", "properties", "ruleProblems")
	assert.EqualValues(t, ratelimitv1.MaxRuleProblems, at(list, "maxItems"))
	assert.EqualValues(t, ratelimitv1.MaxRuleProblemMessage, at(list, "items", "properties", "message", "maxLength"))
}

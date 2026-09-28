package controller

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
// The euro sign takes three bytes, so a byte count and a character count
// part ways at once.
func TestBoundedProblems_cutsOnACharacterBoundary(t *testing.T) {
	long := strings.Repeat("\u20ac", ratelimitv1.MaxRuleProblemMessage+10)
	got := boundedProblems([]ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemInvalidSpec, Message: long}})
	assert.True(t, utf8.ValidString(got[0].Message))
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, utf8.RuneCountInString(got[0].Message))
}

// At the bounds exactly, nothing changes: a message of MaxRuleProblemMessage
// characters comes back whole, and a list of MaxRuleProblems entries keeps
// the compiler's order.
func TestBoundedProblems_leavesWhatSitsExactlyAtTheBounds(t *testing.T) {
	exact := strings.Repeat("\u20ac", ratelimitv1.MaxRuleProblemMessage)
	got := boundedProblems([]ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemInvalidSpec, Message: exact}})
	assert.Equal(t, exact, got[0].Message, "a message at the bound was cut")

	full := make([]ratelimitv1.RuleProblem, 0, ratelimitv1.MaxRuleProblems)
	for i := range ratelimitv1.MaxRuleProblems {
		reason := ratelimitv1.ProblemCaptureShadowsMappedKey
		if i == ratelimitv1.MaxRuleProblems-1 {
			reason = ratelimitv1.ProblemInvalidSpec
		}
		full = append(full, ratelimitv1.RuleProblem{Reason: reason, Rule: fmt.Sprintf("r%d", i)})
	}
	assert.Equal(t, full, boundedProblems(full), "a list at the bound was reordered")
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

// The description kubectl explain prints for ruleProblems[].reason lists every
// reason, because its reader cannot look the constants up. A Problem constant
// added to the API without a regenerated description fails here: add the
// value to the comment on RuleProblem.Reason and run make manifests
// sync-helm-crds.
func TestRuleProblemReasons_areListedInTheCRDDescription(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "..", "api", "v1", "common_types.go"), nil, 0)
	require.NoError(t, err)
	var reasons []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if strings.HasPrefix(name.Name, "Problem") && i < len(value.Values) {
					literal := value.Values[i].(*ast.BasicLit)
					reasons = append(reasons, strings.Trim(literal.Value, `"`))
				}
			}
		}
	}
	require.NotEmpty(t, reasons, "no Problem constant found in api/v1/common_types.go")

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "bases",
		"ratelimit.netcracker.com_ratelimitpolicies.yaml"))
	require.NoError(t, err)
	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Status struct {
								Properties struct {
									RuleProblems struct {
										Items struct {
											Properties struct {
												Reason struct {
													Description string `json:"description"`
												} `json:"reason"`
											} `json:"properties"`
										} `json:"items"`
									} `json:"ruleProblems"`
								} `json:"properties"`
							} `json:"status"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	require.Len(t, crd.Spec.Versions, 1)
	description := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Status.Properties.
		RuleProblems.Items.Properties.Reason.Description
	for _, reason := range reasons {
		assert.Contains(t, description, reason, "the ruleProblems[].reason description does not list %s", reason)
	}
}

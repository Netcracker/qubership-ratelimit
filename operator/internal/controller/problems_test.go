package controller

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
// quoted whole. A message within the bound stays as the compiler wrote it.
func TestBoundedProblems_cutsOnlyAMessagePastTheCRDBound(t *testing.T) {
	long := `template "/` + strings.Repeat("segment/", 200) + `" has an empty segment`
	require.Greater(t, utf8.RuneCountInString(long), ratelimitv1.MaxRuleProblemMessage, "characters in the long message")

	got := boundedProblems([]ratelimitv1.RuleProblem{
		{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "long", Message: long},
		{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "short", Message: "short"},
	})

	require.Len(t, got, 2)
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, utf8.RuneCountInString(got[0].Message),
		"characters in the cut message")
	assert.Equal(t, long[:ratelimitv1.MaxRuleProblemMessage-3]+"...", got[0].Message, "the cut message")
	assert.Equal(t, "short", got[1].Message, "the message within the bound")
}

// The cut counts characters, as the API server does, and never splits one.
// The euro sign takes three bytes, so a byte count and a character count
// part ways at once.
func TestBoundedProblems_cutsOnACharacterBoundary(t *testing.T) {
	long := strings.Repeat("€", ratelimitv1.MaxRuleProblemMessage+10)

	got := boundedProblems([]ratelimitv1.RuleProblem{{Reason: ratelimitv1.ProblemInvalidSpec, Message: long}})

	require.Len(t, got, 1)
	assert.True(t, utf8.ValidString(got[0].Message), "utf8.ValidString(%q)", got[0].Message)
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, utf8.RuneCountInString(got[0].Message),
		"characters in the cut message")
}

// The message bound is inclusive: a message of exactly MaxRuleProblemMessage
// characters comes back whole, and one character more is cut.
func TestBoundedProblems_keepsAMessageOfExactlyTheBoundWhole(t *testing.T) {
	exact := strings.Repeat("€", ratelimitv1.MaxRuleProblemMessage)
	over := strings.Repeat("€", ratelimitv1.MaxRuleProblemMessage+1)

	got := boundedProblems([]ratelimitv1.RuleProblem{
		{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "exact", Message: exact},
		{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "over", Message: over},
	})

	require.Len(t, got, 2)
	assert.Equal(t, exact, got[0].Message, "a message of exactly the bound")
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, utf8.RuneCountInString(got[1].Message),
		"characters in a message one past the bound")
}

// A list of up to MaxRuleProblems entries keeps the compiler's order. The list
// at the bound ends with a blocking entry, which a list past the bound would
// move to the front.
func TestBoundedProblems_keepsTheCompilerOrderWithinTheListBound(t *testing.T) {
	requireSeverities(t)
	cases := []struct {
		name     string
		problems []ratelimitv1.RuleProblem
	}{
		{
			name: "a list of exactly MaxRuleProblems entries",
			problems: append(infoProblems(ratelimitv1.MaxRuleProblems-1),
				ratelimitv1.RuleProblem{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "blocking"}),
		},
		{
			name: "a list of three entries",
			problems: []ratelimitv1.RuleProblem{
				{Reason: ratelimitv1.ProblemCaptureShadowsMappedKey},
				{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "late"},
				{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "later"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := slices.Clone(tc.problems)

			assert.Equal(t, want, boundedProblems(tc.problems))
		})
	}
}

// Past the list bound the blocking entries come first: they are why the
// generation is not enforced, and an informational note must not push one
// out.
func TestBoundedProblems_putsTheBlockingEntriesFirstPastTheListBound(t *testing.T) {
	requireSeverities(t)
	problems := append(infoProblems(ratelimitv1.MaxRuleProblems),
		ratelimitv1.RuleProblem{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "late"},
		ratelimitv1.RuleProblem{Reason: ratelimitv1.ProblemInvalidSpec, Rule: "later"})

	got := boundedProblems(problems)

	require.Len(t, got, ratelimitv1.MaxRuleProblems)
	assert.Equal(t, []string{"late", "later"}, []string{got[0].Rule, got[1].Rule}, "the rules of the first two entries")
}

// infoProblems returns n informational problems, named r0, r1, and so on.
func infoProblems(n int) []ratelimitv1.RuleProblem {
	problems := make([]ratelimitv1.RuleProblem, 0, n)
	for i := range n {
		problems = append(problems, ratelimitv1.RuleProblem{
			Reason: ratelimitv1.ProblemCaptureShadowsMappedKey,
			Rule:   fmt.Sprintf("r%d", i),
		})
	}
	return problems
}

// requireSeverities guards the fixtures of the list tests, which take
// CaptureShadowsMappedKey for informational and InvalidSpec for blocking.
func requireSeverities(t *testing.T) {
	t.Helper()
	require.False(t, ratelimitv1.BlockingProblem(ratelimitv1.ProblemCaptureShadowsMappedKey),
		"BlockingProblem(%s)", ratelimitv1.ProblemCaptureShadowsMappedKey)
	require.True(t, ratelimitv1.BlockingProblem(ratelimitv1.ProblemInvalidSpec),
		"BlockingProblem(%s)", ratelimitv1.ProblemInvalidSpec)
}

// The constants the operator bounds the list by are the numbers the CRD
// enforces. The markers cannot name a constant, so the generated schema is
// read back and compared.
func TestRuleProblemBounds_matchTheGeneratedCRD(t *testing.T) {
	schema := readRuleProblemsSchema(t)

	assert.Equal(t, ratelimitv1.MaxRuleProblems, schema.MaxItems, "maxItems of status.ruleProblems")
	assert.Equal(t, ratelimitv1.MaxRuleProblemMessage, schema.Items.Properties.Message.MaxLength,
		"maxLength of status.ruleProblems[].message")
}

// The description kubectl explain prints for ruleProblems[].reason lists every
// reason the operator can write, because its reader cannot look the constants
// up. A reason missing from the description fails here: add the value to the
// comment on RuleProblem.Reason and run make manifests sync-helm-crds.
func TestRuleProblemReasons_areListedInTheCRDDescription(t *testing.T) {
	description := readRuleProblemsSchema(t).Items.Properties.Reason.Description

	for _, reason := range stringConstants(t, filepath.Join("..", "..", "..", "api", "v1"), "Problem") {
		assert.Contains(t, description, reason, "the description of status.ruleProblems[].reason")
	}
}

// The operator writes the compiler's reason as it is, so every Reason constant
// of the compiler has a Problem constant of the same value in api/v1. A
// compiler reason without one fails here: add the constant to api/v1.
func TestCompileReasons_haveAProblemConstantInTheAPI(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	problems := stringConstants(t, filepath.Join(root, "api", "v1"), "Problem")

	for _, reason := range stringConstants(t, filepath.Join(root, "engine", "compile"), "Reason") {
		assert.Contains(t, problems, reason, "the values of the Problem constants of api/v1")
	}
}

// ruleProblemsSchema is the part of the generated CRD that bounds and
// documents status.ruleProblems.
type ruleProblemsSchema struct {
	MaxItems int `json:"maxItems"`
	Items    struct {
		Properties struct {
			Message struct {
				MaxLength int `json:"maxLength"`
			} `json:"message"`
			Reason struct {
				Description string `json:"description"`
			} `json:"reason"`
		} `json:"properties"`
	} `json:"items"`
}

// readRuleProblemsSchema reads the schema of status.ruleProblems from the
// generated CRD, which serves a single version.
func readRuleProblemsSchema(t *testing.T) ruleProblemsSchema {
	t.Helper()
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
									RuleProblems ruleProblemsSchema `json:"ruleProblems"`
								} `json:"properties"`
							} `json:"status"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	require.Len(t, crd.Spec.Versions, 1, "the versions of the RateLimitPolicy CRD")
	return crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Status.Properties.RuleProblems
}

// stringConstants returns the values of the string constants whose names
// start with prefix, declared in the non-test files of dir.
func stringConstants(t *testing.T, dir, prefix string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	require.NoError(t, err)
	fset := token.NewFileSet()
	var values []string
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				for i, name := range value.Names {
					if !strings.HasPrefix(name.Name, prefix) || i >= len(value.Values) {
						continue
					}
					literal, ok := value.Values[i].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						continue
					}
					unquoted, err := strconv.Unquote(literal.Value)
					require.NoError(t, err)
					values = append(values, unquoted)
				}
			}
		}
	}
	require.NotEmpty(t, values, "no %s constant in %s", prefix, dir)
	return values
}

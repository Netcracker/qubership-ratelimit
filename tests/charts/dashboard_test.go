package charts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// "Policies not ready" reads 0 only while an operator pod holds the Lease
// and judges the policies. An operator that is scraped with no Lease holder
// judges nothing, and a green 0 there would read as a healthy fleet; the
// panel shows no data instead. The expression is evaluated with promtool over
// series a scrape of each case would hold.
func TestServiceChart_dashboardCountsNotReadyPoliciesOnlyUnderALeader(t *testing.T) {
	promtool := findPromtool()
	if promtool == "" {
		if os.Getenv("CHARTS_TEST_REQUIRE_PROMTOOL") != "" {
			t.Fatal("promtool is not available and CHARTS_TEST_REQUIRE_PROMTOOL is set")
		}
		t.Skip("promtool is not available")
	}

	expr := panelExpr(t, "Policies not ready")
	expr = strings.NewReplacer(`"$cluster"`, `".*"`, `"$namespace"`, `".*"`).Replace(expr)

	cases := map[string]any{
		"rule_files":          []string{},
		"evaluation_interval": "1m",
		"tests": []any{
			promqlCase(expr, []string{`ratelimit_leader{pod="a"} 0x5`}, nil),
			promqlCase(expr, []string{`ratelimit_leader{pod="a"} 1x5`}, []any{map[string]any{"labels": "{}", "value": 0}}),
			promqlCase(expr, []string{
				`ratelimit_leader{pod="a"} 1x5`,
				`ratelimit_policy_ready{domain="gateway.public",reason="ProbeFailed"} 0x5`,
			}, []any{map[string]any{"labels": "{}", "value": 1}}),
		},
	}
	raw, err := json.Marshal(cases)
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dashboard.test.yaml"), raw, 0o600))

	cmd := exec.Command(promtool, "test", "rules", "dashboard.test.yaml")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "promtool test rules: %s", out)
	assert.Contains(t, string(out), "SUCCESS", "the panel's expression did not pass: %s", out)
}

// promqlCase is one promtool test group: the series a scrape held for five
// minutes, and the samples the expression returns at minute two. No samples
// is no data on the panel.
func promqlCase(expr string, series []string, samples []any) map[string]any {
	input := make([]any, 0, len(series))
	for _, s := range series {
		name, values, _ := strings.Cut(s, " ")
		input = append(input, map[string]any{"series": name, "values": values})
	}
	if samples == nil {
		samples = []any{}
	}
	return map[string]any{
		"interval":     "1m",
		"input_series": input,
		"promql_expr_test": []any{map[string]any{
			"expr": expr, "eval_time": "2m", "exp_samples": samples,
		}},
	}
}

// panelExpr is the first query of the dashboard panel with the given title.
func panelExpr(t *testing.T, title string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "helm-templates", serviceChart, "dashboards",
		"ratelimit-dashboard.json"))
	require.NoError(t, err)
	type panel struct {
		Title   string  `json:"title"`
		Panels  []panel `json:"panels"`
		Targets []struct {
			Expr string `json:"expr"`
		} `json:"targets"`
	}
	var dashboard struct {
		Panels []panel `json:"panels"`
	}
	require.NoError(t, json.Unmarshal(raw, &dashboard))
	var find func([]panel) string
	find = func(panels []panel) string {
		for _, p := range panels {
			if p.Title == title && len(p.Targets) > 0 {
				return p.Targets[0].Expr
			}
			if expr := find(p.Panels); expr != "" {
				return expr
			}
		}
		return ""
	}
	expr := find(dashboard.Panels)
	require.NotEmpty(t, expr, "the dashboard has no panel %q", title)
	return expr
}

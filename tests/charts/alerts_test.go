package charts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// The alert rules each chart ships behind MONITORING_ENABLED: the set of
// alerts, every rule scoped to the release namespace and carrying a
// severity and both annotations, and the rendered groups accepted by
// promtool check rules. promtool is looked up in PROMTOOL, then in bin/,
// then on PATH; without it the syntax check is skipped, unless
// CHARTS_TEST_REQUIRE_PROMTOOL is set, which the CI helm job does.
var alertsOf = map[string][]string{
	serviceChart: {
		"RatelimitUnknownDomain",
		"RatelimitStoreErrors",
		"RatelimitDecisionLatencyHigh",
		"RatelimitKeyDeclaredNotExtracted",
		"RatelimitDomainBudgetNearLimit",
	},
	operatorChart: {
		"RatelimitStalled",
		"RatelimitNotReadyLong",
		"RatelimitRuleProblems",
		"RatelimitConfigWriteErrors",
		"RatelimitNoOperatorLeader",
	},
}

func TestCharts_shipTheAlertRulesBehindMonitoring(t *testing.T) {
	for chart, wanted := range alertsOf {
		t.Run(chart, func(t *testing.T) {
			rule := only(t, render(t, chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")
			assert.Equal(t, "biz", rule.at("metadata", "namespace").str2())

			names := make([]string, 0, len(wanted))
			for _, group := range rule.at("spec", "groups").list() {
				for _, r := range group.at("rules").list() {
					name := r.at("alert").str2()
					names = append(names, name)
					assert.Contains(t, r.at("expr").str2(), `namespace="biz"`,
						"%s is not scoped to the release namespace", name)
					assert.NotEmpty(t, r.at("labels", "severity").str2(), "%s carries no severity", name)
					assert.NotEmpty(t, r.at("annotations", "summary").str2(), "%s carries no summary", name)
					assert.NotEmpty(t, r.at("annotations", "description").str2(), "%s carries no description", name)
				}
			}
			assert.ElementsMatch(t, wanted, names)

			checkRules(t, rule)
		})
	}
}

// The rules are off with the platform parameter, and off on their own
// switch with the PodMonitor still on.
func TestCharts_renderNoAlertRulesWhenOff(t *testing.T) {
	for chart := range alertsOf {
		assert.NotContains(t, kinds(render(t, chart, "biz")), "PrometheusRule", "%s without MONITORING_ENABLED", chart)
		objects := render(t, chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", "alerts.enabled=false")
		assert.NotContains(t, kinds(objects), "PrometheusRule", "%s with alerts.enabled=false", chart)
		assert.Contains(t, kinds(objects), "PodMonitor", "%s keeps its scrape with the alerts off", chart)
	}
}

// checkRules writes the rendered groups as a rule file and runs promtool
// check rules over it, the check the ticket asks of CI.
func checkRules(t *testing.T, rule object) {
	t.Helper()
	promtool := findPromtool()
	if promtool == "" {
		if os.Getenv("CHARTS_TEST_REQUIRE_PROMTOOL") != "" {
			t.Fatal("promtool is not available and CHARTS_TEST_REQUIRE_PROMTOOL is set")
		}
		t.Log("promtool is not available; the rule syntax check is skipped")
		return
	}
	groups, err := yaml.Marshal(map[string]any{"groups": rule.at("spec", "groups").v})
	require.NoError(t, err)
	file := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(file, groups, 0o600))

	out, err := exec.Command(promtool, "check", "rules", file).CombinedOutput()
	require.NoError(t, err, "promtool check rules: %s", out)
	assert.Contains(t, string(out), "SUCCESS", "promtool did not report success: %s", out)
}

func findPromtool() string {
	if p := os.Getenv("PROMTOOL"); p != "" {
		return p
	}
	if p, err := filepath.Abs(filepath.Join("..", "..", "bin", "promtool")); err == nil {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("promtool"); err == nil {
		return p
	}
	return ""
}

// The rendered expressions are what the runbook and the dashboard quote;
// a change to a metric name shows up here before it shows up on a stand.
func TestCharts_alertExpressionsReadTheSeriesTheCodeDefines(t *testing.T) {
	defined := []string{
		"ratelimit_unknown_domain_checks_total", "ratelimit_store_errors_total",
		"ratelimit_check_duration_seconds_bucket", "ratelimit_extractions_total", "ratelimit_tokens_seen_total",
		"ratelimit_domain_decision_buckets", "ratelimit_policy_stalled", "ratelimit_policy_ready",
		"ratelimit_policy_rule_problems", "ratelimit_config_write_errors_total", "ratelimit_leader",
	}
	for chart := range alertsOf {
		rule := only(t, render(t, chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")
		for _, group := range rule.at("spec", "groups").list() {
			for _, r := range group.at("rules").list() {
				expr := r.at("expr").str2()
				for _, word := range strings.FieldsFunc(expr, func(c rune) bool {
					return c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9')
				}) {
					if strings.HasPrefix(word, "ratelimit_") {
						assert.Contains(t, defined, word, "%s reads a series the code does not define", r.at("alert").str2())
					}
				}
			}
		}
	}
}

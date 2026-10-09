package charts

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/netcracker/qubership-ratelimit/internal/metrics"
)

// alertsOf lists the alerts each chart ships behind MONITORING_ENABLED.
var alertsOf = map[string][]string{
	serviceChart: {
		"RatelimitUnknownDomain",
		"RatelimitStoreErrors",
		"RatelimitDecisionLatencyHigh",
		"RatelimitKeyDeclaredNotExtracted",
		"RatelimitDomainBudgetNearLimit",
		"RatelimitConfigurationAbsent",
	},
	operatorChart: {
		"RatelimitStalled",
		"RatelimitNotEnforced",
		"RatelimitNotReadyLong",
		"RatelimitNoReplicas",
		"RatelimitChecksStopped",
		"RatelimitRuleProblems",
		"RatelimitConfigWriteErrors",
		"RatelimitOperatorReconcileFailing",
		"RatelimitNoOperatorLeader",
	},
}

// alertRules lists the rules of every group of a PrometheusRule.
func alertRules(rule object) []node {
	groups := rule.at("spec", "groups").list()
	rules := make([]node, 0, len(groups))
	for _, group := range groups {
		rules = append(rules, group.at("rules").list()...)
	}
	return rules
}

// With MONITORING_ENABLED each chart renders its PrometheusRule in NAMESPACE,
// holding exactly its own alerts, each scoped to NAMESPACE and carrying a
// severity, a summary, and a description.
func TestCharts_shipTheAlertRulesBehindMonitoring(t *testing.T) {
	for chart, wanted := range alertsOf {
		t.Run(chart, func(t *testing.T) {
			rule := only(t, render(t, chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")

			assert.Equal(t, "biz", rule.at("metadata", "namespace").str2(), "metadata.namespace of the PrometheusRule")
			rules := alertRules(rule)
			names := make([]string, 0, len(rules))
			for _, r := range rules {
				name := r.at("alert").str2()
				names = append(names, name)
				assert.Contains(t, r.at("expr").str2(), `namespace="biz"`, "expr of %s", name)
				assert.NotEmpty(t, r.at("labels", "severity").str2(), "severity label of %s", name)
				assert.NotEmpty(t, r.at("annotations", "summary").str2(), "summary annotation of %s", name)
				assert.NotEmpty(t, r.at("annotations", "description").str2(), "description annotation of %s", name)
			}
			assert.ElementsMatch(t, wanted, names, "alerts of the PrometheusRule")
		})
	}
}

// severitiesOf maps each alert of a PrometheusRule to its severity label.
func severitiesOf(rule object) map[string]string {
	out := map[string]string{}
	for _, r := range alertRules(rule) {
		out[r.at("alert").str2()] = r.at("labels", "severity").str2()
	}
	return out
}

// Each alert carries the severity that the tables under "Alerts" in
// docs/helm-chart.md list for it, so a change of severity updates the chart,
// that table, and this test together. The rule tests under testdata check the
// severity only of an alert they see fire, and only where promtool runs.
func TestCharts_labelEachAlertWithItsSeverity(t *testing.T) {
	for _, c := range []struct {
		chart      string
		severities map[string]string
	}{
		{serviceChart, map[string]string{
			"RatelimitUnknownDomain":           "warning",
			"RatelimitStoreErrors":             "critical",
			"RatelimitDecisionLatencyHigh":     "warning",
			"RatelimitKeyDeclaredNotExtracted": "warning",
			"RatelimitDomainBudgetNearLimit":   "warning",
			"RatelimitConfigurationAbsent":     "warning",
		}},
		{operatorChart, map[string]string{
			"RatelimitStalled":                  "critical",
			"RatelimitNotReadyLong":             "warning",
			"RatelimitNoReplicas":               "critical",
			"RatelimitChecksStopped":            "warning",
			"RatelimitRuleProblems":             "warning",
			"RatelimitConfigWriteErrors":        "critical",
			"RatelimitNoOperatorLeader":         "critical",
			"RatelimitNotEnforced":              "critical",
			"RatelimitOperatorReconcileFailing": "critical",
		}},
	} {
		t.Run(c.chart, func(t *testing.T) {
			rule := only(t, render(t, c.chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")

			assert.Equal(t, c.severities, severitiesOf(rule), "severity label of each alert")
		})
	}
}

// promtool accepts the groups each chart renders with MONITORING_ENABLED, and
// the chart's rule tests under testdata pass against them. Most rule tests
// are negative cases (a lone error, a stray check, an idle domain, a Lease
// changing hands), because an alert set that pages when nothing is wrong is
// the failure they guard against.
func TestCharts_alertRulesPassPromtool(t *testing.T) {
	promtool := promtoolOrSkip(t)
	for chart := range alertsOf {
		t.Run(chart, func(t *testing.T) {
			dir := writeRenderedRules(t, chart)

			t.Run("check rules accepts the groups", func(t *testing.T) {
				out, err := exec.Command(promtool, "check", "rules", filepath.Join(dir, "rules.yaml")).CombinedOutput()

				require.NoError(t, err, "promtool check rules: %s", out)
				assert.Contains(t, string(out), "SUCCESS", "output of promtool check rules")
			})
			t.Run("the rule tests pass", func(t *testing.T) {
				cmd := exec.Command(promtool, "test", "rules", chart+".rules.test.yaml")
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()

				require.NoError(t, err, "promtool test rules: %s", out)
				assert.Contains(t, string(out), "SUCCESS", "output of promtool test rules")
			})
		})
	}
}

// writeRenderedRules renders the chart with MONITORING_ENABLED, writes its
// alert groups as rules.yaml into a new directory, copies the chart's rule
// tests from testdata beside it, since they name rules.yaml relative to
// themselves, and returns the directory.
func writeRenderedRules(t *testing.T, chart string) string {
	t.Helper()
	rule := only(t, render(t, chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")
	groups, err := yaml.Marshal(map[string]any{"groups": rule.at("spec", "groups").v})
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yaml"), groups, 0o600))

	cases, err := os.ReadFile(filepath.Join("testdata", chart+".rules.test.yaml"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, chart+".rules.test.yaml"), cases, 0o600))
	return dir
}

// promtoolOrSkip returns the path of promtool, looked up in PROMTOOL, then in
// the repository's bin/, then on PATH. Without one it skips the test, unless
// CHARTS_TEST_REQUIRE_PROMTOOL is set, which the CI helm job does; then it
// fails the test.
func promtoolOrSkip(t *testing.T) string {
	t.Helper()
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
	if os.Getenv("CHARTS_TEST_REQUIRE_PROMTOOL") != "" {
		t.Fatal("promtool is not available and CHARTS_TEST_REQUIRE_PROMTOOL is set")
	}
	t.Skip("promtool is not available")
	return ""
}

// Each chart's rules stay on when the other chart's switch is off: the
// platform passes both switches to both charts, and each chart reads its own.
func TestCharts_keepTheirAlertRulesWhenTheOtherChartsSwitchIsOff(t *testing.T) {
	for _, c := range []struct{ chart, otherOff string }{
		{operatorChart, "alerts.enabled=false"},
		{serviceChart, "policyAlerts.enabled=false"},
	} {
		t.Run(c.chart, func(t *testing.T) {
			objects := render(t, c.chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", c.otherOff)

			assert.Contains(t, kinds(objects), "PrometheusRule", "objects rendered with %s", c.otherOff)
		})
	}
}

// Without MONITORING_ENABLED, the platform parameter, neither chart renders
// its rules.
func TestCharts_renderNoAlertRulesWithoutMonitoring(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			assert.NotContains(t, kinds(render(t, chart, "biz")), "PrometheusRule")
		})
	}
}

// Each chart's own switch turns its rules off and leaves its PodMonitor on.
func TestCharts_renderNoAlertRulesWithTheirOwnSwitchOff(t *testing.T) {
	for _, c := range []struct{ chart, off string }{
		{operatorChart, "policyAlerts.enabled=false"},
		{serviceChart, "alerts.enabled=false"},
	} {
		t.Run(c.chart, func(t *testing.T) {
			objects := render(t, c.chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", c.off)

			assert.NotContains(t, kinds(objects), "PrometheusRule", "objects rendered with %s", c.off)
			assert.Contains(t, kinds(objects), "PodMonitor", "objects rendered with %s", c.off)
		})
	}
}

// seriesName matches the name of a series the binaries publish, all of which
// start with ratelimit_ or, for the operator's controllers, with the
// controller_runtime_ of the library, as a whole word of a PromQL expression.
var seriesName = regexp.MustCompile(`(?:^|[^a-z0-9_])((?:ratelimit|controller_runtime)_[a-z0-9_]*)`)

// controllerRuntimeSeries are the series of controller-runtime the alerts
// read. The library registers them on the operator's registry itself, from a
// package this module cannot import, so they are named here.
var controllerRuntimeSeries = []string{
	"controller_runtime_reconcile_errors_total",
	"controller_runtime_reconcile_total",
}

// seriesReadBy lists the series a PromQL expression names.
func seriesReadBy(expr string) []string {
	matches := seriesName.FindAllStringSubmatch(expr, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, match[1])
	}
	return names
}

// The rendered expressions are what the runbook and the dashboard quote, so
// every series one reads has to be a series a binary publishes. The set
// comes from the registrations themselves rather than from a list kept by
// hand: a series renamed in internal/metrics fails here instead of leaving
// a rule that matches nothing and a test that still passes.
func TestCharts_alertExpressionsReadTheSeriesTheCodeDefines(t *testing.T) {
	defined := append(registeredSeries(), controllerRuntimeSeries...)
	for chart := range alertsOf {
		t.Run(chart, func(t *testing.T) {
			rule := only(t, render(t, chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")

			for _, r := range alertRules(rule) {
				read := seriesReadBy(r.at("expr").str2())
				assert.NotEmpty(t, read, "series the alert %s reads", r.at("alert").str2())
				assert.Subset(t, defined, read, "the alert %s reads a series no binary publishes", r.at("alert").str2())
			}
		})
	}
}

// fqName reads the metric name out of a Desc, which prints as
// Desc{fqName: "...", help: ...}.
var fqName = regexp.MustCompile(`fqName: "([^"]+)"`)

// registeredSeries lists what the two registrations put on a registry, each
// histogram and summary also under the suffixed names a query reads.
func registeredSeries() []string {
	collectors := &collecting{}
	metrics.RegisterService(collectors, "test")
	metrics.RegisterOperator(collectors, "test")

	descs := make(chan *prometheus.Desc, 256)
	go func() {
		for _, c := range collectors.collectors {
			c.Describe(descs)
		}
		close(descs)
	}()
	var names []string
	for desc := range descs {
		match := fqName.FindStringSubmatch(desc.String())
		if match == nil {
			continue
		}
		names = append(names, match[1])
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			names = append(names, match[1]+suffix)
		}
	}
	return names
}

// collecting is a Registerer that keeps what it is handed instead of
// registering it: the registrations are the source of the names, and a real
// registry would reject the collectors the two share.
type collecting struct{ collectors []prometheus.Collector }

func (c *collecting) Register(collector prometheus.Collector) error {
	c.collectors = append(c.collectors, collector)
	return nil
}
func (c *collecting) MustRegister(collectors ...prometheus.Collector) {
	c.collectors = append(c.collectors, collectors...)
}
func (c *collecting) Unregister(prometheus.Collector) bool { return false }

// The schema refuses the values that would render a rule which never fires,
// or a group Prometheus will not load: one bad duration takes every rule of
// the chart with it. The refusal names the key it refused.
func TestCharts_refuseAlertValuesThatBreakTheRules(t *testing.T) {
	for _, c := range []struct{ chart, set, key string }{
		{serviceChart, "alerts.latencyBudgetSeconds=0", "latencyBudgetSeconds"},
		{serviceChart, "alerts.latencyBudgetSeconds=-1", "latencyBudgetSeconds"},
		{serviceChart, "alerts.latencyBudgetSeconds=abc", "latencyBudgetSeconds"},
		{serviceChart, "alerts.latencyBudgetSeconds=0.0", "latencyBudgetSeconds"},
		{serviceChart, "alerts.latencyBudgetSeconds=1e-3", "latencyBudgetSeconds"},
		{serviceChart, "alerts.keyNotExtractedWindow=0m", "keyNotExtractedWindow"},
		{serviceChart, "alerts.storeErrorsFor=abc", "storeErrorsFor"},
		{serviceChart, "alerts.configAbsentFor=5", "configAbsentFor"},
		{operatorChart, "policyAlerts.stalledFor=0s", "stalledFor"},
		{operatorChart, "policyAlerts.configWriteFailingFor=0m", "configWriteFailingFor"},
		{operatorChart, "policyAlerts.checksStoppedWindow=10", "checksStoppedWindow"},
	} {
		t.Run(c.set, func(t *testing.T) {
			out, err := renderErr(c.chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", c.set)

			require.Error(t, err, "%s rendered with %s", c.chart, c.set)
			assert.Contains(t, string(out), c.key, "the refusal names the key it refused")
		})
	}
}

// alertNamed returns the rule of the alert name in a PrometheusRule, and
// stops the test where the rule holds no such alert.
func alertNamed(t *testing.T, rule object, name string) node {
	t.Helper()
	rules := alertRules(rule)
	i := slices.IndexFunc(rules, func(r node) bool { return r.at("alert").str2() == name })
	require.NotEqual(t, -1, i, "the PrometheusRule has no alert %s", name)
	return rules[i]
}

// The schema admits the values just inside the bounds that
// TestCharts_refuseAlertValuesThatBreakTheRules refuses at, a latency budget
// just above zero and a duration that starts with 1, and each reaches the
// rule it sets. The budget goes in both as a number, with --set-json, and as
// the string --set makes of a decimal fraction.
func TestCharts_acceptAlertValuesJustInsideTheirBounds(t *testing.T) {
	for _, c := range []struct {
		name, chart string
		args        []string
		alert       string
		field, want string
	}{
		{"latencyBudgetSeconds=0.001", serviceChart, []string{"--set-json", "alerts.latencyBudgetSeconds=0.001"},
			"RatelimitDecisionLatencyHigh", "expr", "> 0.001"},
		{"latencyBudgetSeconds=0.005 through --set", serviceChart, []string{"--set", "alerts.latencyBudgetSeconds=0.005"},
			"RatelimitDecisionLatencyHigh", "expr", "> 0.005"},
		{"keyNotExtractedWindow=1m", serviceChart, []string{"--set", "alerts.keyNotExtractedWindow=1m"},
			"RatelimitKeyDeclaredNotExtracted", "expr", "[1m]"},
		{"stalledFor=1s", operatorChart, []string{"--set", "policyAlerts.stalledFor=1s"},
			"RatelimitStalled", "for", "1s"},
		{"configWriteFailingFor=1m", operatorChart, []string{"--set", "policyAlerts.configWriteFailingFor=1m"},
			"RatelimitConfigWriteErrors", "for", "1m"},
	} {
		t.Run(c.name, func(t *testing.T) {
			objects := render(t, c.chart, "biz", append([]string{"--set", "MONITORING_ENABLED=true"}, c.args...)...)

			rule := alertNamed(t, only(t, objects, "PrometheusRule"), c.alert)
			assert.Contains(t, rule.at(c.field).str2(), c.want, "%s of %s", c.field, c.alert)
		})
	}
}

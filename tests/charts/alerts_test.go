package charts

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/netcracker/qubership-ratelimit/internal/metrics"
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

			checkRules(t, chart, rule)
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

// checkRules writes the rendered groups as a rule file, runs promtool check
// rules over it, and replays the chart's rule tests against it: the drill of
// the ticket's definition of done, reproduced by CI instead of by a stand.
// The cases that matter are the negative ones — a lone error, a stray check,
// an idle domain, a Lease changing hands — since an alert set that pages
// when nothing is wrong is the failure this pins.
func checkRules(t *testing.T, chart string, rule object) {
	t.Helper()
	promtool := findPromtool()
	if promtool == "" {
		if os.Getenv("CHARTS_TEST_REQUIRE_PROMTOOL") != "" {
			t.Fatal("promtool is not available and CHARTS_TEST_REQUIRE_PROMTOOL is set")
		}
		t.Log("promtool is not available; the rule syntax check and the rule tests are skipped")
		return
	}
	groups, err := yaml.Marshal(map[string]any{"groups": rule.at("spec", "groups").v})
	require.NoError(t, err)
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rules, groups, 0o600))

	out, err := exec.Command(promtool, "check", "rules", rules).CombinedOutput()
	require.NoError(t, err, "promtool check rules: %s", out)
	assert.Contains(t, string(out), "SUCCESS", "promtool did not report success: %s", out)

	// The rule test file names rules.yaml beside itself, so it is copied
	// into the directory the rendering was written to.
	cases, err := os.ReadFile(filepath.Join("testdata", chart+".rules.test.yaml"))
	require.NoError(t, err)
	test := filepath.Join(dir, chart+".rules.test.yaml")
	require.NoError(t, os.WriteFile(test, cases, 0o600))

	cmd := exec.Command(promtool, "test", "rules", filepath.Base(test))
	cmd.Dir = dir
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "promtool test rules: %s", out)
	assert.Contains(t, string(out), "SUCCESS", "the rule tests did not pass: %s", out)
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

// The rendered expressions are what the runbook and the dashboard quote, so
// every series one reads has to be a series a binary publishes. The set
// comes from the registrations themselves rather than from a list kept by
// hand: a series renamed in internal/metrics fails here instead of leaving
// a rule that matches nothing and a test that still passes.
func TestCharts_alertExpressionsReadTheSeriesTheCodeDefines(t *testing.T) {
	defined := registeredSeries()
	for chart := range alertsOf {
		rule := only(t, render(t, chart, "biz", "--set", "MONITORING_ENABLED=true"), "PrometheusRule")
		for _, group := range rule.at("spec", "groups").list() {
			for _, r := range group.at("rules").list() {
				expr := r.at("expr").str2()
				for _, word := range strings.FieldsFunc(expr, func(c rune) bool {
					return c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9')
				}) {
					if strings.HasPrefix(word, "ratelimit_") {
						assert.Contains(t, defined, word,
							"%s reads %s, which no binary publishes", r.at("alert").str2(), word)
					}
				}
			}
		}
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
// the chart with it.
func TestCharts_refuseAlertValuesThatBreakTheRules(t *testing.T) {
	for _, bad := range []struct{ chart, set string }{
		{serviceChart, "alerts.latencyBudgetSeconds=0"},
		{serviceChart, "alerts.latencyBudgetSeconds=-1"},
		{serviceChart, "alerts.latencyBudgetSeconds=abc"},
		{serviceChart, "alerts.keyNotExtractedWindow=0m"},
		{serviceChart, "alerts.storeErrorsFor=abc"},
		{operatorChart, "alerts.stalledFor=0s"},
		{operatorChart, "alerts.configWriteErrorsWindow=0m"},
	} {
		_, err := renderErr(bad.chart, "biz", "--set", "MONITORING_ENABLED=true", "--set", bad.set)
		assert.Error(t, err, "%s accepts %s", bad.chart, bad.set)
	}
}

package charts

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadtestChart is the chart of the load test kit, which lives beside the
// kit rather than under helm-templates.
var loadtestChart = filepath.Join("..", "load", "chart")

// renderLoadtest renders the load test chart with self-signed tokens, which
// need no Keycloak values, and the given extra arguments.
func renderLoadtest(t *testing.T, extra ...string) []object {
	t.Helper()
	args := append([]string{"template", "t", loadtestChart, "-n", "load",
		"--set", "image.tag=" + imageTag, "--set", "tokens.source=self-signed"}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	require.NoError(t, err, "%s", out)
	return parse(t, out)
}

// generatorEnv returns the environment of the generator container.
func generatorEnv(t *testing.T, objects []object) map[string]string {
	t.Helper()
	containers := only(t, objects, "Job").at("spec", "template", "spec", "containers").list()
	require.Len(t, containers, 1, "containers of the generator Job")
	env := map[string]string{}
	for _, e := range containers[0].at("env").list() {
		env[e.at("name").str2()] = e.at("value").str2()
	}
	return env
}

// The multiplier reaches the policy and the windows the generator checks
// alike, so a capacity run that still checks its limits checks the limits
// the policy enforces.
func TestLoadtestChart_multipliesThePolicyAndTheCheckedWindowsAlike(t *testing.T) {
	objects := renderLoadtest(t, "--set", "policy.multiplier=1000")

	first := only(t, objects, "RateLimitPolicy").at("spec", "limits").list()[0]
	windows := first.at("rules").list()[0].at("rates").list()
	rates := make([]float64, 0, len(windows))
	for _, rate := range windows {
		rates = append(rates, rate.at("requests").num())
	}
	assert.Equal(t, []float64{50000, 1000000, 5000000}, rates, "requests of the windows of the first block")
	assert.Equal(t, "50000/60s,1000000/3600s,5000000/86400s", generatorEnv(t, objects)["LT_WINDOWS"])
}

// The generator checks the limits only for fixed windows, and only while
// load.checkLimits is on; an empty LT_WINDOWS skips the check.
func TestLoadtestChart_checksTheLimitsOfFixedWindowsOnly(t *testing.T) {
	tests := []struct {
		name, algorithm, checkLimits, want string
	}{
		{"fixed windows checked", "FixedWindow", "true", "50/60s,1000/3600s,5000/86400s"},
		{"GCRA windows", "GCRA", "true", ""},
		{"the check turned off", "FixedWindow", "false", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := renderLoadtest(t, "--set", "policy.algorithm="+tt.algorithm, "--set", "load.checkLimits="+tt.checkLimits)
			assert.Equal(t, tt.want, generatorEnv(t, objects)["LT_WINDOWS"])
		})
	}
}

// The steps reach the generator as rate:seconds pairs, the form run.sh reads.
func TestLoadtestChart_passesTheStepsAsRateSecondsPairs(t *testing.T) {
	objects := renderLoadtest(t, "--set", "load.steps[0].rate=0", "--set", "load.steps[0].seconds=60",
		"--set", "load.steps[1].rate=12.5", "--set", "load.steps[1].seconds=600")
	assert.Equal(t, "0:60,12.5:600", generatorEnv(t, objects)["LT_STEPS"])
}

// A value the run cannot do without fails the render, with the value named.
func TestLoadtestChart_refusesARenderWithoutARequiredValue(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no image tag", []string{"--set", "tokens.source=self-signed"}, "image.tag is required"},
		{"Keycloak without its server", []string{"--set", "image.tag=t"}, "tokens.keycloak.url"},
		{"an unknown token source", []string{"--set", "image.tag=t", "--set", "tokens.source=static"},
			`tokens.source is "static"`},
		{"an unknown algorithm", []string{"--set", "image.tag=t", "--set", "tokens.source=self-signed",
			"--set", "policy.algorithm=Sliding"}, `policy.algorithm is "Sliding"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"template", "t", loadtestChart, "-n", "load"}, tt.args...)
			out, err := exec.Command("helm", args...).CombinedOutput()
			require.Error(t, err, "helm template %v", tt.args)
			assert.Contains(t, string(out), tt.want)
		})
	}
}

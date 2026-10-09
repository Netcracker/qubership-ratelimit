package charts

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The schemas refuse a value that renders and then breaks the installation
// later: in Envoy, in the platform, or in the operator that reconciles the
// rendered objects. Each case names the value; the refusal is helm's exit
// code.
func TestCharts_refuseValuesThatBreakTheInstallationLater(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chart string
		set   []string
	}{
		{"a refusal status outside Envoy's StatusCode enumeration", serviceChart,
			[]string{"--set", "filter.rateLimitedStatus=418"}},
		{"a per-gateway refusal status outside Envoy's StatusCode enumeration", serviceChart,
			[]string{"--set", "gateways.public.rateLimitedStatus=451"}},
		{"a check timeout of zero", serviceChart, []string{"--set", "filter.timeout=0s"}},
		{"a check timeout of zero with a fraction", serviceChart, []string{"--set", "filter.timeout=0.0s"}},
		{"a near-limit ratio of one", serviceChart, []string{"--set", "metrics.nearLimitRatio=1"}},
		{"a near-limit ratio above one, quoted", serviceChart, []string{"--set-string", "metrics.nearLimitRatio=1.5"}},
		{"a near-limit ratio of zero", serviceChart, []string{"--set", "metrics.nearLimitRatio=0"}},
		{"a baseline namespace in capitals, service", serviceChart, []string{"--set", "BASELINE_ORIGIN=Biz"}},
		{"a baseline namespace in capitals, operator", operatorChart, []string{"--set", "BASELINE_ORIGIN=Biz"}},
		{"a baseline namespace with a trailing space", serviceChart, []string{"--set", "BASELINE_ORIGIN=biz "}},
		{"a baseline namespace with a DNS suffix", operatorChart, []string{"--set", "BASELINE_ORIGIN=biz.svc"}},
		{"a baseline controller in capitals", serviceChart, []string{"--set", "BASELINE_CONTROLLER=Biz"}},
		{"a DBaaS address whose host is an IP address", serviceChart,
			[]string{"--set", "API_DBAAS_ADDRESS=http://10.0.0.1:8080"}},
		{"a DBaaS address whose host is an external name", serviceChart,
			[]string{"--set", "API_DBAAS_ADDRESS=https://dbaas.apps.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := renderErr(tc.chart, "biz", tc.set...)
			assert.Error(t, err)
		})
	}
}

// The values the tightened schemas still accept render.
func TestCharts_acceptTheValuesTheSchemasAllow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chart string
		set   []string
	}{
		{"a refusal status of 503", serviceChart, []string{"--set", "filter.rateLimitedStatus=503"}},
		{"a check timeout of one second", serviceChart, []string{"--set", "filter.timeout=1s"}},
		{"a check timeout of half a second", serviceChart, []string{"--set", "filter.timeout=0.5s"}},
		{"a near-limit ratio as a number", serviceChart, []string{"--set", "metrics.nearLimitRatio=0.75"}},
		{"a near-limit ratio as a string without the zero", serviceChart,
			[]string{"--set-string", "metrics.nearLimitRatio=.8"}},
		{"a DBaaS address with the cluster suffix", serviceChart,
			[]string{"--set", "API_DBAAS_ADDRESS=http://dbaas-aggregator.dbaas.svc.cluster.local:8080"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderErr(tc.chart, "biz", tc.set...)
			assert.NoError(t, err, "%s", out)
		})
	}
}

// The namespace of dbaas-operator is read from the host of API_DBAAS_ADDRESS,
// and redis.dbaas.operatorNamespace overrides it for a host of another form.
func TestServiceChart_assignsTheDBaaSObjectsToTheOperatorNamespace(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "API_DBAAS_ADDRESS=http://dbaas-aggregator.platform-dbaas:8080")
	assert.Equal(t, "platform-dbaas", only(t, objects, "DatabaseSecretClaim").at("spec", "operatorNamespace").str2())

	objects = render(t, serviceChart, "biz", "--set", "API_DBAAS_ADDRESS=http://10.0.0.1:8080",
		"--set", "redis.dbaas.operatorNamespace=dbaas")
	assert.Equal(t, "dbaas", only(t, objects, "DatabaseSecretClaim").at("spec", "operatorNamespace").str2())
	assert.Equal(t, "dbaas", only(t, objects, "InternalDatabase").at("spec", "operatorNamespace").str2())
}

// A numeric zero is a value, not an absence: maxSurge and maxUnavailable of
// zero render as zero, and so do the operator's replica count and the
// autoscaler's scale-down window. Helm's default used to replace each of them,
// rendering 25%, one replica, and 300 seconds.
func TestCharts_renderANumericZeroAsZero(t *testing.T) {
	for _, chart := range namespaceCharts {
		t.Run(chart, func(t *testing.T) {
			objects := render(t, chart, "biz", "--set", "DEPLOYMENT_STRATEGY_TYPE=custom_rollout",
				"--set", "DEPLOYMENT_STRATEGY_MAXSURGE=0", "--set", "DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=1")
			rolling := only(t, objects, "Deployment").at("spec", "strategy", "rollingUpdate")
			assert.InDelta(t, 0, rolling.at("maxSurge").num(), 0, "maxSurge")
			assert.InDelta(t, 1, rolling.at("maxUnavailable").num(), 0, "maxUnavailable")

			objects = render(t, chart, "biz", "--set", "DEPLOYMENT_STRATEGY_TYPE=custom_rollout")
			rolling = only(t, objects, "Deployment").at("spec", "strategy", "rollingUpdate")
			assert.Equal(t, "25%", rolling.at("maxSurge").str2(), "maxSurge left unset")
		})
	}

	objects := render(t, operatorChart, "biz", "--set", "REPLICAS=0")
	assert.InDelta(t, 0, only(t, objects, "Deployment").at("spec", "replicas").num(), 0, "replicas of the operator")

	objects = render(t, serviceChart, "biz", "--set", "HPA_ENABLED=true", "--set", "HPA_MAX_REPLICAS=4",
		"--set", "HPA_SCALING_DOWN_STABILIZATION_WINDOW_SECONDS=0")
	window := only(t, objects, "HorizontalPodAutoscaler").at("spec", "behavior", "scaleDown", "stabilizationWindowSeconds")
	require.NotNil(t, window.v, "stabilizationWindowSeconds")
	assert.InDelta(t, 0, window.num(), 0, "the scale-down window")
}

// A custom rollout with both maxSurge and maxUnavailable at zero cannot make
// progress, and the API server refuses the Deployment; both charts refuse it
// at render instead, in either spelling of zero.
func TestCharts_refuseACustomRolloutThatCanMakeNoProgress(t *testing.T) {
	for _, chart := range namespaceCharts {
		for _, zeros := range [][]string{
			{"--set", "DEPLOYMENT_STRATEGY_MAXSURGE=0", "--set", "DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=0"},
			{"--set", "DEPLOYMENT_STRATEGY_MAXSURGE=0%", "--set-string", "DEPLOYMENT_STRATEGY_MAXUNAVAILABLE=0"},
		} {
			t.Run(chart, func(t *testing.T) {
				out, err := renderErr(chart, "biz", append([]string{"--set", "DEPLOYMENT_STRATEGY_TYPE=custom_rollout"},
					zeros...)...)

				require.Error(t, err)
				assert.Contains(t, string(out), "both zero")
			})
		}
	}
}

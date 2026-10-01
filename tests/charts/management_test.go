package charts

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatewayDomainsEnv is the variable the service reads the exempt domains
// from; service/internal/settings reads it as management.gateway.domains.
const gatewayDomainsEnv = "MANAGEMENT_GATEWAY_DOMAINS"

// gatewayDomainsOf reads gatewayDomainsEnv from the service chart's one
// container. ok is false where the chart did not render the variable.
func gatewayDomainsOf(t *testing.T, objects []object) (value string, ok bool) {
	t.Helper()
	containers := only(t, objects, "Deployment").at("spec", "template", "spec", "containers").list()
	require.Len(t, containers, 1)
	for _, env := range containers[0].at("env").list() {
		if env.at("name").str2() == gatewayDomainsEnv {
			return env.at("value").str2(), true
		}
	}
	return "", false
}

// The service chart hands management.gatewayDomains to the service as one
// comma-separated variable, and only while the management API is on: with the
// API off nothing serves its paths, and no path is exempt.
func TestServiceChart_handsTheGatewayDomainsToTheService(t *testing.T) {
	t.Run("the default is the private gateway's default domain", func(t *testing.T) {
		value, ok := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true"))

		require.True(t, ok, "%s is rendered with management.enabled=true", gatewayDomainsEnv)
		assert.Equal(t, "gateway.private", value, gatewayDomainsEnv)
	})
	t.Run("several domains are joined with commas", func(t *testing.T) {
		value, _ := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.gatewayDomains={gateway.internal,gateway.ops}"))

		assert.Equal(t, "gateway.internal,gateway.ops", value, gatewayDomainsEnv)
	})
	t.Run("an empty list renders an empty value", func(t *testing.T) {
		value, ok := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set-json", "management.gatewayDomains=[]"))

		require.True(t, ok, "%s is rendered with management.enabled=true", gatewayDomainsEnv)
		assert.Empty(t, value, gatewayDomainsEnv)
	})
	t.Run("the variable is absent with the management API off", func(t *testing.T) {
		_, ok := gatewayDomainsOf(t, render(t, serviceChart, "biz"))

		assert.False(t, ok, "%s is rendered with management.enabled=false", gatewayDomainsEnv)
	})
}

// A gateway domain the CRD's spec.domain pattern cannot carry is no gateway's
// domain, and the schema refuses it at install time.
func TestServiceChart_refusesAGatewayDomainOffTheDomainPattern(t *testing.T) {
	out, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.gatewayDomains={Gateway_Private}")

	require.Error(t, err, "helm template with management.gatewayDomains={Gateway_Private}")
	assert.Contains(t, string(out), "gatewayDomains")
}

// The two charts are installed side by side with their defaults, and the
// service exempts the API's paths only in a domain a gateway's filter sends.
// So the default of management.gatewayDomains has to be the domain the
// operator chart gives the private gateway's filter.
func TestCharts_theDefaultGatewayDomainIsThePrivateGatewaysDomain(t *testing.T) {
	var filterDomain string
	for _, o := range render(t, operatorChart, "biz") {
		if o.kind() != "EnvoyFilter" {
			continue
		}
		targets := o.at("spec", "targetRefs").list()
		require.Len(t, targets, 1)
		if targets[0].at("name").str2() != "private-gateway" {
			continue
		}
		for _, patch := range o.at("spec", "configPatches").list() {
			if patch.at("applyTo").str2() == "HTTP_FILTER" {
				filterDomain = patch.at("patch", "value", "typed_config", "domain").str2()
			}
		}
	}
	require.NotEmpty(t, filterDomain, "the operator chart renders a filter for private-gateway with a domain")

	value, _ := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true"))

	assert.Equal(t, filterDomain, value, gatewayDomainsEnv)
}

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
	return envOf(t, objects, gatewayDomainsEnv)
}

// envOf reads the variable name off the container of the rendered Deployment,
// and reports whether the chart renders it at all.
func envOf(t *testing.T, objects []object, name string) (value string, ok bool) {
	t.Helper()
	containers := only(t, objects, "Deployment").at("spec", "template", "spec", "containers").list()
	require.Len(t, containers, 1)
	for _, env := range containers[0].at("env").list() {
		if env.at("name").str2() == name {
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
		value, ok := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}"))

		require.True(t, ok, "%s is rendered with management.enabled=true", gatewayDomainsEnv)
		assert.Equal(t, "gateway.private", value, gatewayDomainsEnv)
	})
	t.Run("several domains are joined with commas", func(t *testing.T) {
		value, _ := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}",
			"--set", "management.gatewayDomains={gateway.internal,gateway.ops}"))

		assert.Equal(t, "gateway.internal,gateway.ops", value, gatewayDomainsEnv)
	})
	t.Run("an empty list renders an empty value", func(t *testing.T) {
		value, ok := gatewayDomainsOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}",
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
		"--set", "management.callers={ui-backend}",
		"--set", "management.gatewayDomains={Gateway_Private}")

	require.Error(t, err, "helm template with management.gatewayDomains={Gateway_Private}")
	assert.Contains(t, string(out), "gatewayDomains")
}

// The service exempts the API's paths only in a domain a gateway's filter
// sends, so the default of management.gatewayDomains has to be the domain the
// chart gives the private gateway's filter.
func TestServiceChart_theDefaultGatewayDomainIsThePrivateGatewaysDomain(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}")
	var filterDomain string
	for _, o := range objects {
		if o.kind() != envoyFilterKind {
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
	require.NotEmpty(t, filterDomain, "the chart renders a filter for private-gateway with a domain")

	value, _ := gatewayDomainsOf(t, objects)

	assert.Equal(t, filterDomain, value, gatewayDomainsEnv)
}

// The management API verifies callers' tokens with the pod's own
// ServiceAccount token, so the chart mounts it, in the layout the API server's
// automount gives, only while the API is on. Automounting stays off and the
// chart binds the ServiceAccount to no Role, so the token reads nothing but the
// cluster's OIDC discovery.
func TestServiceChart_mountsTheServiceAccountTokenForTheManagementAPIAlone(t *testing.T) {
	const path = "/var/run/secrets/kubernetes.io/serviceaccount"
	mounted := func(objects []object) (sources []string, at string) {
		spec := only(t, objects, "Deployment").at("spec", "template", "spec")
		for _, volume := range spec.at("volumes").list() {
			if volume.at("name").str2() != "serviceaccount" {
				continue
			}
			for _, source := range volume.at("projected", "sources").list() {
				for kind := range source.v.(map[string]any) {
					sources = append(sources, kind)
				}
			}
		}
		for _, mount := range spec.at("containers").list()[0].at("volumeMounts").list() {
			if mount.at("name").str2() == "serviceaccount" {
				at = mount.at("mountPath").str2()
			}
		}
		return sources, at
	}

	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}")
	sources, at := mounted(objects)
	assert.Equal(t, []string{"serviceAccountToken", "configMap", "downwardAPI"}, sources)
	assert.Equal(t, path, at)
	assert.Equal(t, false, only(t, objects, "Deployment").
		at("spec", "template", "spec", "automountServiceAccountToken").v)
	assert.NotContains(t, kinds(objects), "Role")
	assert.NotContains(t, kinds(objects), "RoleBinding")

	sources, at = mounted(render(t, serviceChart, "biz"))
	assert.Empty(t, sources, "the token is mounted with the management API off")
	assert.Empty(t, at)
}

// The identity values of the unverified-token model are gone, and the schema
// refuses them rather than ignoring them: an install that still sets them
// expects a model the service no longer has.
func TestServiceChart_refusesTheRemovedIdentityValues(t *testing.T) {
	for _, value := range []string{"management.claims.roles=realm_access.roles", "management.roles.operator={admin}"} {
		_, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}", "--set", value)
		assert.Error(t, err, "the schema accepts %s", value)
	}
}

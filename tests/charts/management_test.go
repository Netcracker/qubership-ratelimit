package charts

import (
	"strings"
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
	variable, ok := keyed(containerOf(t, objects).at("env"), "name")[name]
	return variable.at("value").str2(), ok
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

// The service chart hands management.callers to the service as one
// comma-separated MANAGEMENT_CALLERS, each entry as it was given, so a
// <namespace>/<name> caller keeps its namespace.
func TestServiceChart_handsTheCallersToTheService(t *testing.T) {
	value, ok := envOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend,platform/ops-backend}"), "MANAGEMENT_CALLERS")

	require.True(t, ok, "MANAGEMENT_CALLERS is rendered with management.enabled=true")
	assert.Equal(t, "ui-backend,platform/ops-backend", value, "MANAGEMENT_CALLERS")
}

// The service chart hands management.m2m.audience to the service as
// MANAGEMENT_M2M_AUDIENCE: netcracker, the audience of the platform's
// machine-to-machine tokens, by default, and a set audience as it was given,
// including one of a single character, the shortest the schema admits.
func TestServiceChart_handsTheTokenAudienceToTheService(t *testing.T) {
	t.Run("the default is netcracker", func(t *testing.T) {
		value, ok := envOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}"), "MANAGEMENT_M2M_AUDIENCE")

		require.True(t, ok, "MANAGEMENT_M2M_AUDIENCE is rendered with management.enabled=true")
		assert.Equal(t, "netcracker", value, "MANAGEMENT_M2M_AUDIENCE")
	})
	t.Run("an audience of one character is handed over", func(t *testing.T) {
		value, _ := envOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}", "--set", "management.m2m.audience=a"), "MANAGEMENT_M2M_AUDIENCE")

		assert.Equal(t, "a", value, "MANAGEMENT_M2M_AUDIENCE")
	})
}

// A gateway domain the CRD's spec.domain pattern cannot carry is no gateway's
// domain, and the schema refuses it at install time.
func TestServiceChart_refusesAGatewayDomainOffTheDomainPattern(t *testing.T) {
	out, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}",
		"--set", "management.gatewayDomains={Gateway_Private}")

	require.Error(t, err, "helm template with management.gatewayDomains={Gateway_Private}")
	assert.Contains(t, string(out), "gatewayDomains", "the refusal names the key it refused")
}

// The schema refuses an empty management.m2m.audience at install time, and
// the refusal names it.
func TestServiceChart_refusesAnEmptyTokenAudience(t *testing.T) {
	out, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}", "--set", "management.m2m.audience=")

	require.Error(t, err, "helm template with management.m2m.audience=")
	assert.Contains(t, string(out), "audience", "the refusal names the key it refused")
}

// The schema admits a caller whose namespace and name are as long as
// Kubernetes allows, a 63-character DNS label and a 253-character DNS
// subdomain, and the service gets the entry whole.
func TestServiceChart_acceptsACallerWithTheLongestServiceAccountNames(t *testing.T) {
	caller := strings.Repeat("s", 63) + "/" + strings.Repeat("n", 253)
	value, _ := envOf(t, render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={"+caller+"}"), "MANAGEMENT_CALLERS")

	assert.Equal(t, caller, value, "MANAGEMENT_CALLERS")
}

// The schema refuses a caller that names no possible ServiceAccount: one with
// an uppercase letter, a namespace past the 63 characters of a DNS label, or
// a name past the 253 characters of a DNS subdomain. The refusal names
// callers.
func TestServiceChart_refusesACallerThatNoServiceAccountCanHave(t *testing.T) {
	for _, c := range []struct{ name, caller string }{
		{"an uppercase letter", "UI-backend"},
		{"a namespace of 64 characters", strings.Repeat("s", 64) + "/ops-backend"},
		{"a name of 254 characters", strings.Repeat("n", 254)},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true",
				"--set", "management.callers={"+c.caller+"}")

			require.Error(t, err, "helm template with management.callers={%s}", c.caller)
			assert.Contains(t, string(out), "callers", "the refusal names the key it refused")
		})
	}
}

// The pod's projected ServiceAccount token names no audience, so the kubelet
// requests it for the API server, as it does the token it automounts: the
// service authenticates its OIDC discovery and key-set requests to the API
// server with it.
func TestServiceChart_projectsTheTokenForTheAPIServer(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}")

	volumes := keyed(only(t, objects, "Deployment").at("spec", "template", "spec", "volumes"), "name")
	require.Contains(t, volumes, "serviceaccount", "volumes of the pod")
	sources := keyed(volumes["serviceaccount"].at("projected", "sources"), "serviceAccountToken", "path")
	require.Contains(t, sources, "token", "projected sources of the serviceaccount volume")
	assert.NotContains(t, sources["token"].at("serviceAccountToken").v, "audience",
		"the serviceAccountToken source of the serviceaccount volume")
}

// The service exempts the API's paths only in a domain a gateway's filter
// sends, so the default of management.gatewayDomains has to be the domain the
// chart gives the private gateway's filter.
func TestServiceChart_theDefaultGatewayDomainIsThePrivateGatewaysDomain(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
		"--set", "management.callers={ui-backend}")

	filterDomain := httpFilterDomainFor(t, objects, "private-gateway")
	value, _ := gatewayDomainsOf(t, objects)
	assert.Equal(t, filterDomain, value, gatewayDomainsEnv)
}

// httpFilterDomainFor returns the domain the HTTP filter of the EnvoyFilter
// that targets gateway sends, and stops the test where no such filter or
// domain is rendered, or several are.
func httpFilterDomainFor(t *testing.T, objects []object, gateway string) string {
	t.Helper()
	var domains []string
	for _, filter := range ofKind(objects, envoyFilterKind) {
		targets := filter.at("spec", "targetRefs").list()
		require.Len(t, targets, 1, "spec.targetRefs of %s", filter.name())
		if targets[0].at("name").str2() != gateway {
			continue
		}
		for _, patch := range filter.at("spec", "configPatches").list() {
			if patch.at("applyTo").str2() == "HTTP_FILTER" {
				domains = append(domains, patch.at("patch", "value", "typed_config", "domain").str2())
			}
		}
	}
	require.Len(t, domains, 1, "HTTP filters of the EnvoyFilters that target %s", gateway)
	require.NotEmpty(t, domains[0], "domain of the HTTP filter that targets %s", gateway)
	return domains[0]
}

// tokenVolume is the volume the service chart projects the pod's
// ServiceAccount token into for the management API.
const tokenVolume = "serviceaccount"

// The management API verifies callers' tokens with the pod's own
// ServiceAccount token, so the chart mounts it only while the API is on, in
// the layout the API server's automount gives: the token, the cluster's CA,
// and the namespace, at the automount's path. The ServiceAccount has no Role,
// so the token reads nothing but the cluster's OIDC discovery;
// TestServiceChart_reachesNoAPIServerObject covers that.
func TestServiceChart_mountsTheServiceAccountTokenForTheManagementAPIAlone(t *testing.T) {
	t.Run("the token, the CA, and the namespace are mounted with the API on", func(t *testing.T) {
		objects := render(t, serviceChart, "biz", "--set", "management.enabled=true",
			"--set", "management.callers={ui-backend}")

		mounts := keyed(containerOf(t, objects).at("volumeMounts"), "name")
		require.Contains(t, mounts, tokenVolume, "volume mounts of the container")
		assert.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount", mounts[tokenVolume].at("mountPath").str2(),
			"mountPath of the %s volume", tokenVolume)
		assert.Equal(t, map[string]string{
			"token":     "serviceAccountToken",
			"ca.crt":    "configMap kube-root-ca.crt key ca.crt",
			"namespace": "downwardAPI metadata.namespace",
		}, projectedFiles(only(t, objects, "Deployment").at("spec", "template", "spec"), tokenVolume),
			"files of the %s volume", tokenVolume)
	})
	t.Run("the token is not mounted with the API off", func(t *testing.T) {
		objects := render(t, serviceChart, "biz")

		assert.NotContains(t, keyed(containerOf(t, objects).at("volumeMounts"), "name"), tokenVolume,
			"volume mounts of the container")
		assert.Empty(t, projectedFiles(only(t, objects, "Deployment").at("spec", "template", "spec"), tokenVolume),
			"files of the %s volume", tokenVolume)
	})
}

// The schema refuses management.claims and management.roles rather than
// ignoring them: an installation that sets them expects roles read out of the
// token, and the service grants operator to management.callers instead. The
// service read the subject and the roles out of an unverified token, from the
// claims management.claims named and under the names management.roles mapped,
// until it verified tokens itself.
func TestServiceChart_refusesTheRemovedIdentityValues(t *testing.T) {
	for _, c := range []struct{ key, set string }{
		{"claims", "management.claims.roles=realm_access.roles"},
		{"roles", "management.roles.operator={admin}"},
	} {
		t.Run(c.key, func(t *testing.T) {
			out, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true",
				"--set", "management.callers={ui-backend}", "--set", c.set)

			require.Error(t, err, "helm template --set %s", c.set)
			assert.Contains(t, string(out), c.key, "the refusal names the key it refused")
		})
	}
}

// The schema requires at least one entry in management.callers while
// management.enabled is true, and refuses the empty list at install time.
func TestServiceChart_refusesTheManagementAPIWithoutACaller(t *testing.T) {
	out, err := renderErr(serviceChart, "biz", "--set", "management.enabled=true")

	require.Error(t, err, "helm template with management.enabled=true and no management.callers")
	assert.Contains(t, string(out), "callers", "the refusal names the key it refused")
}

// projectedFiles maps each file of the projected volume name in a pod spec to
// its source: serviceAccountToken, configMap <name> key <key>, or downwardAPI
// <field path>. A source of any other kind is recorded as one entry,
// <kind> mapped to "unread source", so it fails a comparison with the
// expected files. The map is empty when the spec has no such volume.
func projectedFiles(spec node, name string) map[string]string {
	files := map[string]string{}
	for _, volume := range spec.at("volumes").list() {
		if volume.at("name").str2() != name {
			continue
		}
		for _, source := range volume.at("projected", "sources").list() {
			addSourceFiles(files, source)
		}
	}
	return files
}

// addSourceFiles adds the files of one projected source to files, in the form
// projectedFiles describes.
func addSourceFiles(files map[string]string, source node) {
	kinds, _ := source.v.(map[string]any)
	for kind := range kinds {
		switch kind {
		case "serviceAccountToken":
			files[source.at(kind, "path").str2()] = "serviceAccountToken"
		case "configMap":
			for _, item := range source.at(kind, "items").list() {
				files[item.at("path").str2()] = "configMap " + source.at(kind, "name").str2() + " key " +
					item.at("key").str2()
			}
		case "downwardAPI":
			for _, item := range source.at(kind, "items").list() {
				files[item.at("path").str2()] = "downwardAPI " + item.at("fieldRef", "fieldPath").str2()
			}
		default:
			files["<"+kind+">"] = "unread source"
		}
	}
}

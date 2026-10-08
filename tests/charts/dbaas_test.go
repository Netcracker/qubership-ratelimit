package charts

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The counter store comes from DBaaS: the service chart declares the database
// and the claim, and the Deployment mounts the Secret the claim names. The
// three have to agree, or dbaas-operator writes a Secret nobody mounts and the
// pod waits forever for one that never comes.
func TestServiceChart_declaresItsCounterStoreInDBaaS(t *testing.T) {
	objects := render(t, serviceChart, "biz")
	database := only(t, objects, "InternalDatabase")
	claim := only(t, objects, "DatabaseSecretClaim")
	pod := only(t, objects, "Deployment").at("spec", "template", "spec")
	container := containerOf(t, objects)

	for _, o := range []object{database, claim} {
		assert.Equal(t, "dbaas.netcracker.com/v1", o.str("apiVersion"), "apiVersion of the %s", o.kind())
		assert.Equal(t, "redis", o.at("spec", "type").str2(), "spec.type of the %s", o.kind())
		assert.Equal(t, "ratelimit-service", o.at("spec", "classifier", "microserviceName").str2(),
			"spec.classifier.microserviceName of the %s", o.kind())
		assert.Equal(t, "service", o.at("spec", "classifier", "scope").str2(), "spec.classifier.scope of the %s", o.kind())
		assert.Equal(t, "biz", o.at("spec", "classifier", "namespace").str2(),
			"spec.classifier.namespace of the %s", o.kind())
		// Assigned to the dbaas-operator beside the aggregator the platform
		// parameter names; an operator ignores a CR naming another namespace.
		assert.Equal(t, "dbaas", o.at("spec", "operatorNamespace").str2(), "spec.operatorNamespace of the %s", o.kind())
	}
	// dbaas-operator sends the label as the originService of the lookup, and
	// the database's owner is the microservice of the classifier: they are
	// the same name, or the service is not the owner of its own database.
	assert.Equal(t, claim.at("spec", "classifier", "microserviceName").str2(),
		claim.at("metadata", "labels", "app.kubernetes.io/name").str2(),
		"app.kubernetes.io/name label of the DatabaseSecretClaim")

	assert.Contains(t, argsOf(container), "--redis-dbaas-microservice=ratelimit-service",
		"the service asks for the database the claim names")
	env := keyed(container.at("env"), "name")
	assert.Equal(t, "metadata.namespace", env["MICROSERVICE_NAMESPACE"].at("valueFrom", "fieldRef", "fieldPath").str2(),
		"the DBaaS client refuses to start without MICROSERVICE_NAMESPACE")
	for name := range env {
		assert.NotContains(t, name, "REDIS_", "a static Redis setting is still rendered")
	}

	secret := claim.at("spec", "secretName").str2()
	require.NotEmpty(t, secret, "spec.secretName of the DatabaseSecretClaim")
	volumes := keyed(pod.at("volumes"), "secret", "secretName")
	require.Contains(t, volumes, secret, "the Deployment does not mount the claim's Secret")
	assert.NotEqual(t, true, volumes[secret].at("secret", "optional").v,
		"a replica must not start without its counter store")
	mounts := keyed(container.at("volumeMounts"), "name")
	assert.Equal(t, "/etc/secrets/dbaas-secrets/"+secret, mounts[volumes[secret].at("name").str2()].at("mountPath").str2(),
		"the Secret is not mounted where the platform's DBaaS client scans")
}

// Without DBaaS the chart declares nothing and still mounts the Secret, which
// something else provides in the same format.
func TestServiceChart_leavesTheSecretToSomeoneElseWithDBaaSOff(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "redis.dbaas.enabled=false")

	assert.NotContains(t, kinds(objects), "InternalDatabase")
	assert.NotContains(t, kinds(objects), "DatabaseSecretClaim")
	assert.Contains(t, secretsMountedBy(only(t, objects, "Deployment").at("spec", "template", "spec")),
		"ratelimit-service-redis", "the Secret is mounted whoever writes it")
}

// The DBaaS objects go to the operator in the aggregator's namespace, read
// off the API_DBAAS_ADDRESS platform parameter.
func TestServiceChart_assignsItsDBaaSObjectsToTheAggregatorsNamespace(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "API_DBAAS_ADDRESS=http://dbaas-aggregator.team-a:8080")

	assert.Equal(t, "team-a", only(t, objects, "InternalDatabase").at("spec", "operatorNamespace").str2(),
		"spec.operatorNamespace of the InternalDatabase")
	assert.Equal(t, "team-a", only(t, objects, "DatabaseSecretClaim").at("spec", "operatorNamespace").str2(),
		"spec.operatorNamespace of the DatabaseSecretClaim")
}

// An API_DBAAS_ADDRESS without a namespace is refused rather than rendered
// into CRs no operator ever reconciles.
func TestServiceChart_refusesADBaaSAddressWithoutANamespace(t *testing.T) {
	out, err := renderErr(serviceChart, "biz", "--set", "API_DBAAS_ADDRESS=http://dbaas-aggregator:8080")

	require.Error(t, err, "helm template with API_DBAAS_ADDRESS=http://dbaas-aggregator:8080")
	assert.Contains(t, string(out), "API_DBAAS_ADDRESS", "the refusal names the parameter it refused")
}

// Every profile renders without store values: the counter store does not
// depend on the replica count, so dev-ha and prod, which run two replicas,
// need nothing more.
func TestServiceChart_rendersEveryProfileWithoutStoreValues(t *testing.T) {
	for _, profile := range []string{"dev", "dev-ha", "prod", "prod-nonha"} {
		t.Run(profile, func(t *testing.T) {
			_, err := renderErr(serviceChart, "biz", "-f", profileFile(serviceChart, profile))

			assert.NoError(t, err)
		})
	}
}

package charts

import (
	"slices"
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
	for _, o := range []object{database, claim} {
		assert.Equal(t, "dbaas.netcracker.com/v1", o.str("apiVersion"))
		assert.Equal(t, "redis", o.at("spec", "type").str2(), o.kind())
		assert.Equal(t, "ratelimit-service", o.at("spec", "classifier", "microserviceName").str2(), o.kind())
		assert.Equal(t, "service", o.at("spec", "classifier", "scope").str2(), o.kind())
		assert.Equal(t, "biz", o.at("spec", "classifier", "namespace").str2(), o.kind())
		// Assigned to the dbaas-operator beside the aggregator the platform
		// parameter names; an operator ignores a CR naming another namespace.
		assert.Equal(t, "dbaas", o.at("spec", "operatorNamespace").str2(), o.kind())
	}

	// dbaas-operator sends the label as the originService of the lookup, and
	// the database's owner is the microservice of the classifier: they are
	// the same name, or the service is not the owner of its own database.
	assert.Equal(t, claim.at("spec", "classifier", "microserviceName").str2(),
		claim.at("metadata", "labels", "app.kubernetes.io/name").str2())

	secret := claim.at("spec", "secretName").str2()
	require.NotEmpty(t, secret)

	deployment := only(t, objects, "Deployment")
	container := deployment.at("spec", "template", "spec", "containers").list()[0]
	assert.Contains(t, argsOf(container), "--redis-dbaas-microservice=ratelimit-service",
		"the service asks for the database the claim names")
	var namespaced bool
	for _, env := range container.at("env").list() {
		namespaced = namespaced || (env.at("name").str2() == "MICROSERVICE_NAMESPACE" &&
			env.at("valueFrom", "fieldRef", "fieldPath").str2() == "metadata.namespace")
	}
	assert.True(t, namespaced, "the DBaaS client refuses to start without MICROSERVICE_NAMESPACE")

	var mounted, optional bool
	for _, volume := range deployment.at("spec", "template", "spec", "volumes").list() {
		if volume.at("secret", "secretName").str2() == secret {
			mounted = true
			optional = volume.at("secret", "optional").v == true
			name := volume.at("name").str2()
			var path string
			for _, mount := range container.at("volumeMounts").list() {
				if mount.at("name").str2() == name {
					path = mount.at("mountPath").str2()
				}
			}
			assert.Equal(t, "/etc/secrets/dbaas-secrets/"+secret, path,
				"the Secret is not mounted where the platform's DBaaS client scans")
		}
	}
	assert.True(t, mounted, "the Deployment does not mount the claim's Secret %s", secret)
	assert.False(t, optional, "a replica must not start without its counter store")

	for _, env := range container.at("env").list() {
		assert.NotContains(t, env.at("name").str2(), "REDIS_", "a static Redis setting is still rendered")
	}
}

// Without DBaaS the chart declares nothing and still mounts the Secret, which
// something else provides in the same format; a satellite renders neither.
func TestServiceChart_leavesTheSecretToSomeoneElseWithDBaaSOff(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "redis.dbaas.enabled=false")
	assert.False(t, slices.Contains(kinds(objects), "InternalDatabase"))
	assert.False(t, slices.Contains(kinds(objects), "DatabaseSecretClaim"))

	deployment := only(t, objects, "Deployment")
	var mounted bool
	for _, volume := range deployment.at("spec", "template", "spec", "volumes").list() {
		mounted = mounted || volume.at("secret", "secretName").str2() == "ratelimit-service-redis"
	}
	assert.True(t, mounted, "the Secret is mounted whoever writes it")
}

// The operator is the one in the aggregator's namespace, read off the
// platform parameter; an address without a namespace is refused rather than
// rendered into CRs no operator ever reconciles.
func TestServiceChart_assignsItsDBaaSObjectsToTheAggregatorsNamespace(t *testing.T) {
	objects := render(t, serviceChart, "biz", "--set", "API_DBAAS_ADDRESS=http://dbaas-aggregator.team-a:8080")
	assert.Equal(t, "team-a", only(t, objects, "DatabaseSecretClaim").at("spec", "operatorNamespace").str2())

	_, err := renderErr(serviceChart, "biz", "--set", "API_DBAAS_ADDRESS=http://dbaas-aggregator:8080")
	assert.Error(t, err, "an address without a namespace rendered")
}

// Every profile renders: the counter store no longer depends on a replica
// count, so the prod profiles with two replicas need no extra values.
func TestServiceChart_rendersEveryProfileWithoutStoreValues(t *testing.T) {
	for _, profile := range []string{"dev", "dev-ha", "prod", "prod-nonha"} {
		_, err := renderErr(serviceChart, "biz", "-f",
			"../../helm-templates/ratelimit-service/resource-profiles/"+profile+".yaml")
		assert.NoError(t, err, profile)
	}
}

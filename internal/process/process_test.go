package process

import (
	"errors"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespace_isTheCloudNamespaceAndNothingElse(t *testing.T) {
	// The namespace is the installation's scope, and the one thing that keeps
	// the RBAC a Role. Unset is a startup error, never a fallback to the
	// whole cluster.
	// The env source alone: the YAML source waits on an application.yaml
	// this package does not ship, and the property under test is an
	// environment variable.
	t.Setenv("CLOUD_NAMESPACE", "")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	_, err := Namespace()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CLOUD_NAMESPACE")

	t.Setenv("CLOUD_NAMESPACE", "biz")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	namespace, err := Namespace()
	require.NoError(t, err)
	assert.Equal(t, "biz", namespace)
}

// The logr bridge. controller-runtime and client-go log through logr, and
// the platform logs through its own logger; what is pinned is that levels,
// names, and key-value pairs survive the crossing.
func TestLogrAdapter_carriesNamesValuesAndLevels(t *testing.T) {
	root := NewLogrLogger("test")
	sink := root.GetSink().(*logrAdapter)
	assert.Equal(t, "test", sink.name)

	named := root.WithName("store").WithValues("domain", "gateway.public")
	child := named.GetSink().(*logrAdapter)
	assert.Equal(t, "test/store", child.name, "sub-loggers are named under the root, e.g. ratelimit/rls")
	assert.Equal(t, []any{"domain", "gateway.public"}, child.kvs)

	// The parent is untouched by the child's values: WithValues copies.
	assert.Empty(t, sink.kvs)

	// Verbosity: level 0 is info and always enabled; higher levels are debug
	// and enabled by the platform logger's own level.
	assert.True(t, sink.Enabled(0))

	// These exercise the write paths; the platform logger's output is not
	// captured here, and what matters is that neither panics on a nil error
	// or an odd number of values.
	named.Info("rebuilt", "domains", 3)
	named.V(1).Info("detail")
	named.Error(errors.New("boom"), "failed", "domain", "gateway.public")
	named.Error(nil, "no error value")
}

func TestFormatMessage(t *testing.T) {
	assert.Equal(t, "plain", formatMessage("plain", nil))
	assert.Equal(t, "rebuilt domains=3 took=1s", formatMessage("rebuilt", []any{"domains", 3, "took", "1s"}))
	// An odd trailing key is a caller's mistake; it is dropped rather than
	// paired with a missing value.
	assert.Equal(t, "odd a=1", formatMessage("odd", []any{"a", 1, "dangling"}))
}

func TestPodName_isTheDownwardAPIValueOrEmpty(t *testing.T) {
	t.Setenv("POD_NAME", "ratelimit-abc12")
	assert.Equal(t, "ratelimit-abc12", PodName())
	t.Setenv("POD_NAME", "")
	assert.Empty(t, PodName(), "outside a pod there is no name to borrow")
}

package process

import (
	"errors"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
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
// the platform logs through its own logger; what is pinned is that names and
// key-value pairs survive the crossing. The verbosity mapping is pinned in
// TestLogrAdapter_boundsVerbosityByThePlatformLevel.
func TestLogrAdapter_carriesNamesAndValues(t *testing.T) {
	root := NewLogrLogger("test")
	sink := root.GetSink().(*logrAdapter)
	assert.Equal(t, "test", sink.name)

	named := root.WithName("store").WithValues("domain", "gateway.public")
	child := named.GetSink().(*logrAdapter)
	assert.Equal(t, "test/store", child.name, "sub-loggers are named under the root, e.g. ratelimit/rls")
	assert.Equal(t, []any{"domain", "gateway.public"}, child.kvs)

	// The parent is untouched by the child's values: WithValues copies.
	assert.Empty(t, sink.kvs)

	// These exercise the write paths; the platform logger's output is not
	// captured here, and what matters is that neither panics on a nil error
	// or an odd number of values.
	named.Info("rebuilt", "domains", 3)
	named.V(1).Info("detail")
	named.Error(errors.New("boom"), "failed", "domain", "gateway.public")
	named.Error(nil, "no error value")
}

// The platform level bounds the verbosity the bridge enables: level 0 at
// every platform level, levels 1 to maxVerbosity at debug, and nothing above
// that at any level. The cap keeps the request and response bodies that
// client-go logs at verbosity 8 out of a debug log. A new case goes in the
// table, named by its verbosity and platform level.
func TestLogrAdapter_boundsVerbosityByThePlatformLevel(t *testing.T) {
	// One logger per platform level; the registry returns the same instance
	// to the adapter, so the level the test sets is the one Enabled reads.
	const atError, atInfo, atDebug = "test/verbosity/error", "test/verbosity/info", "test/verbosity/debug"
	logging.GetLogger(atError).SetLevel(logging.LvlError)
	logging.GetLogger(atInfo).SetLevel(logging.LvlInfo)
	logging.GetLogger(atDebug).SetLevel(logging.LvlDebug)
	cases := []struct {
		name    string
		logger  string
		level   int
		enabled bool
	}{
		{"level 0 is on at error", atError, 0, true},
		{"level 0 is on at info", atInfo, 0, true},
		{"level 1 is off at info", atInfo, 1, false},
		{"level 0 is on at debug", atDebug, 0, true},
		{"level 1 is on at debug", atDebug, 1, true},
		{"level 4, the cap, is on at debug", atDebug, 4, true},
		{"level 5, above the cap, is off at debug", atDebug, 5, false},
		{"level 8, the body dumps, is off at debug", atDebug, 8, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewLogrLogger(c.logger).V(c.level).Enabled()
			assert.Equal(t, c.enabled, got, "V(%d).Enabled() on %s", c.level, c.logger)
		})
	}
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

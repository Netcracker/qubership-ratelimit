package leader

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

// The leader a reader finds on the Lease is a pod they can look at, and the
// Lease is the one the manager elects on (LeaseName), in the namespace the
// caller passed. The config dials nothing: the lock is built lazily.
func TestLock_signsTheLeaseInTheGivenNamespaceWithThePodName(t *testing.T) {
	t.Setenv("POD_NAME", "ratelimit-operator-abc12")

	lock, err := Lock(&rest.Config{Host: "https://127.0.0.1:1"}, "biz")

	require.NoError(t, err)
	require.NotNil(t, lock, "Lock(namespace=biz) with POD_NAME=ratelimit-operator-abc12")
	assert.Equal(t, "ratelimit-operator-abc12", lock.Identity(), "Identity()")
	assert.Equal(t, "biz/"+LeaseName, lock.Describe(), "Describe()")
}

// No POD_NAME means no pod: a local run, an envtest. The choice of identity
// goes back to controller-runtime rather than refusing to start.
func TestLock_isNilOutsideAPod(t *testing.T) {
	t.Setenv("POD_NAME", "")

	lock, err := Lock(&rest.Config{Host: "https://127.0.0.1:1"}, "biz")

	assert.NoError(t, err)
	assert.Nil(t, lock, "Lock(namespace=biz) with POD_NAME empty")
}

package leader

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"

	"github.com/netcracker/qubership-ratelimit/internal/process"
)

func TestLock_signsTheLeaseWithThePodName(t *testing.T) {
	t.Setenv("POD_NAME", "ratelimit-operator-abc12")
	// A config that dials nothing: the lock is built lazily, and what is
	// asserted is who it says it is.
	lock, err := Lock(&rest.Config{Host: "https://127.0.0.1:1"}, "biz")
	require.NoError(t, err)
	require.NotNil(t, lock)
	assert.Equal(t, "ratelimit-operator-abc12", lock.Identity(),
		"the holder identity is the pod name, which is what the status messages name replicas by")
	assert.Equal(t, "biz/"+LeaseName, lock.Describe())
}

func TestLock_isNilOutsideAPod(t *testing.T) {
	// No POD_NAME means no pod: a local run, an envtest. The choice of
	// identity goes back to controller-runtime rather than refusing to start.
	t.Setenv("POD_NAME", "")
	lock, err := Lock(&rest.Config{Host: "https://127.0.0.1:1"}, "biz")
	require.NoError(t, err)
	assert.Nil(t, lock)
	assert.Empty(t, process.PodName())
}

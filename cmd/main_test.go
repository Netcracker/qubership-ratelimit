package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Without redis.addresses the process counts in its own memory, which is a
// permitted configuration: management.enabled does not require Redis. The
// records have to follow the counters there. Leaving them nil starts the
// management API with a nil store, and every mutation panics into an RLS-0500
// while the reads keep working, so nothing short of a reset reveals it.
func TestNewCounterStore_theInProcessBackendCarriesARecordsStore(t *testing.T) {
	backend := newCounterStore()

	require.NotNil(t, backend.store, "the in-process branch must still count somewhere")
	require.NotNil(t, backend.records,
		"a nil records store panics on the first DELETE /counters")
	require.False(t, backend.shared, "in-process counting is per replica, and says so")
	require.Nil(t, backend.closer, "nothing was dialed, so there is nothing to close")
}

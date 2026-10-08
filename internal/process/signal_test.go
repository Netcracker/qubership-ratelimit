package process

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignalContext_endsOnSIGTERM(t *testing.T) {
	ctx, stop := SignalContext()
	defer stop()
	require.NoError(t, ctx.Err(), "the context ended before any signal")

	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("waited 5s for the context to end on SIGTERM; it is still live")
	}
}

func TestSignalContext_endsOnStop(t *testing.T) {
	ctx, stop := SignalContext()

	stop()

	assert.ErrorIs(t, ctx.Err(), context.Canceled)
}

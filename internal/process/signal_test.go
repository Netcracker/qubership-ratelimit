package process

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSignalContext_endsOnSIGTERM(t *testing.T) {
	ctx, stop := SignalContext()
	defer stop()
	select {
	case <-ctx.Done():
		t.Fatal("the context ended before any signal")
	default:
	}
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the context did not end on SIGTERM")
	}
}

// stop ends the context without a signal.
func TestSignalContext_endsOnStop(t *testing.T) {
	ctx, stop := SignalContext()
	stop()
	require.ErrorIs(t, ctx.Err(), context.Canceled)
}

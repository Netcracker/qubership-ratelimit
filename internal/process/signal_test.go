package process

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSignalContext_endsOnSIGTERM(t *testing.T) {
	ctx := SignalContext()
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

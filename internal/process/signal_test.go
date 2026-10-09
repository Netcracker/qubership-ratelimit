package process

import (
	"context"
	"os"
	"os/exec"
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

// signalChild names the environment variable that marks the child process of
// TestSignalContext_exitsWithStatusOneOnASecondSignal.
const signalChild = "RATELIMIT_SIGNAL_CONTEXT_CHILD"

// A second SIGTERM exits the process with status 1, as controller-runtime's
// handler does, while the drain that the first one started still runs. The
// exit ends the process that receives the signal, so the test runs the drain
// in a child: the test binary, run again for this test alone.
func TestSignalContext_exitsWithStatusOneOnASecondSignal(t *testing.T) {
	if os.Getenv(signalChild) != "" {
		drainUntilASecondSignal()
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSignalContext_exitsWithStatusOneOnASecondSignal$")
	child.Env = append(os.Environ(), signalChild+"=1")

	output, err := child.CombinedOutput()

	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "the child's result; its output:\n%s", output)
	assert.Equal(t, 1, exit.ExitCode(), "the child's exit status; its output:\n%s", output)
}

// drainUntilASecondSignal is the child's side: the first SIGTERM ends the
// context, and a drain of ten seconds starts. The second SIGTERM, sent at
// once, ends the process before the drain does; a child that is still running
// after ten seconds exits with status 0.
func drainUntilASecondSignal() {
	ctx, stop := SignalContext()
	defer stop()
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	<-ctx.Done()
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	time.Sleep(10 * time.Second)
}

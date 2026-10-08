package management

import (
	"context"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The runner is what a rollout actually interacts with: it has to come up on a
// real socket, serve, and stop when the manager says so. These tests drive it
// over the loopback rather than mocking it away, because "it listens and then it
// stops" is the whole of its contract.

// The runner's lifecycle is one sequence: it answers on the socket it bound,
// Start returns without an error once its context ends, and the socket is
// closed after that.
func TestRunner_servesUntilTheContextEnds(t *testing.T) {
	h := newTestAPI(t)

	runner := &Runner{
		Addr:         "127.0.0.1:0",
		App:          h.app,
		API:          h.api,
		Log:          discardLogger{},
		DrainTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- runner.Start(ctx) }()

	addr := waitForListener(t, runner)
	target := "http://" + addr + BasePath + "/domains"
	response, err := http.Get(target) //nolint:noctx // the deadline is the test's
	require.NoError(t, err, "GET %s while the runner serves", target)
	defer func() { require.NoError(t, response.Body.Close()) }()

	// Unauthenticated, because the point here is that the socket answers at all.
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode, "GET %s while the runner serves", target)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), CodeUnauthorized.Code, "GET %s while the runner serves", target)

	cancel()
	select {
	case err := <-stopped:
		require.NoError(t, err, "Start after its context ended")
	case <-time.After(10 * time.Second):
		t.Fatal("timed out after 10s waiting for Start to return once its context ended")
	}

	_, err = http.Get(target) //nolint:noctx // the deadline is the test's
	assert.Error(t, err, "GET %s after the runner stopped", target)
}

func TestRunner_reportsAnAddressItCannotHave(t *testing.T) {
	h := newTestAPI(t)

	// Something else already holds the port.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { require.NoError(t, held.Close()) }()

	runner := &Runner{Addr: held.Addr().String(), App: h.app, Log: discardLogger{}}
	err = runner.Start(t.Context())

	assert.ErrorIs(t, err, syscall.EADDRINUSE, "Start on %s", held.Addr())
	assert.ErrorContains(t, err, held.Addr().String(), "Start on %s", held.Addr())
}

// waitForListener returns the address the runner bound, once it has one. The
// port is chosen by the kernel, so it can only be read after Start opened it.
func waitForListener(t *testing.T, runner *Runner) string {
	t.Helper()

	require.Eventually(t, func() bool { return runner.boundAddr() != "" }, 5*time.Second, 10*time.Millisecond,
		"timed out waiting for the runner on %s to bind a port", runner.Addr)

	addr := runner.boundAddr()
	require.Regexp(t, `^127\.0\.0\.1:\d+$`, addr, "the address the runner bound for %s", runner.Addr)
	return addr
}

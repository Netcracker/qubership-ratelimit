package management

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The runner is what a rollout actually interacts with: it has to come up on a
// real socket, serve, and stop when the manager says so. These tests drive it
// over the loopback rather than mocking it away, because "it listens and then it
// stops" is the whole of its contract.

func TestRunner_servesUntilTheContextEnds(t *testing.T) {
	h := newTestAPI(t)

	runner := &Runner{
		Addr:         "127.0.0.1:0",
		App:          h.app,
		API:          h.api,
		Log:          discardLogger{},
		DrainTimeout: time.Second,
	}
	require.False(t, runner.NeedLeaderElection(),
		"every replica serves this API, like every replica answers checks")

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- runner.Start(ctx) }()

	addr := waitForListener(t, runner)
	response, err := http.Get("http://" + addr + BasePath + "/domains") //nolint:noctx // the deadline is the test's
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()

	// Unauthenticated, because the point here is that the socket answers at all.
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), CodeUnauthorized.Code)

	cancel()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the runner did not stop when its context ended")
	}

	// And the socket is closed behind it.
	_, err = http.Get("http://" + addr + BasePath + "/domains") //nolint:noctx // the deadline is the test's
	require.Error(t, err)
}

func TestRunner_reportsAnAddressItCannotHave(t *testing.T) {
	h := newTestAPI(t)

	// Something else already holds the port.
	held, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { require.NoError(t, held.Close()) }()

	runner := &Runner{Addr: held.Addr().String(), App: h.app, Log: discardLogger{}}
	err = runner.Start(t.Context())

	require.Error(t, err)
	require.Contains(t, err.Error(), "listen on")
}

// waitForListener returns the address the runner bound, once it has one. The
// port is chosen by the kernel, so it can only be read after Start opened it.
func waitForListener(t *testing.T, runner *Runner) string {
	t.Helper()

	var addr string
	require.Eventually(t, func() bool {
		bound := runner.boundAddr()
		if bound == "" {
			return false
		}
		addr = bound
		return true
	}, 5*time.Second, 10*time.Millisecond, "the runner never bound a port")

	require.True(t, strings.HasPrefix(addr, "127.0.0.1:"))
	return addr
}

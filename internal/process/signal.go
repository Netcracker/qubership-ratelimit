package process

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// SignalContext is a context that ends on SIGTERM or SIGINT, for a process
// that runs no controller-runtime manager. A second signal exits at once,
// as controller-runtime's handler does, so a drain that hangs can still be
// interrupted from the terminal.
func SignalContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		cancel()
		<-signals
		os.Exit(1)
	}()
	return ctx
}

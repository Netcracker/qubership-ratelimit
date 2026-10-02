package process

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// SignalContext returns a context that ends on SIGTERM or SIGINT, for a
// process that runs no controller-runtime manager, and the function that
// releases it. A second signal exits at once, as controller-runtime's handler
// does, so a drain that hangs can still be interrupted from the terminal.
// The caller defers stop: it stops the signal delivery and ends the context.
func SignalContext() (ctx context.Context, stop context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-signals:
		case <-ctx.Done():
			return
		}
		cancel()
		<-signals
		os.Exit(1)
	}()
	return ctx, func() {
		signal.Stop(signals)
		cancel()
	}
}

package process

import (
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

// logrAdapter bridges logr.LogSink to the platform logger.
type logrAdapter struct {
	logger logging.Logger
	name   string
	kvs    []any
}

// NewLogrLogger returns the root logr sink backed by the platform logger,
// under the given name.
func NewLogrLogger(name string) logr.Logger {
	return logr.New(&logrAdapter{logger: logging.GetLogger(name), name: name})
}

// Init receives the call-depth information logr offers a sink.
func (a *logrAdapter) Init(_ logr.RuntimeInfo) {
	// Deliberately empty: the platform logger works out its own caller
	// information, so there is nothing here worth keeping.
}

// maxVerbosity is the highest logr verbosity the platform level debug
// enables. Verbosities up to 4 carry controller-runtime's own debug lines and
// the lines client-go writes about its lists, watches, and request retries;
// 5 adds two lines per reconcile and the work queue's contents every ten
// seconds, and 8 adds every request and response body.
const maxVerbosity = 4

// Enabled implements [logr.LogSink]: level 0 is always enabled, levels 1 to
// [maxVerbosity] only at the platform level debug, and higher levels never.
func (a *logrAdapter) Enabled(level int) bool {
	if level > 0 {
		return level <= maxVerbosity && a.logger.GetLevel() >= logging.LvlDebug
	}
	return true
}

func (a *logrAdapter) Info(level int, msg string, keysAndValues ...any) {
	full := formatMessage(msg, append(a.kvs, keysAndValues...))
	if level > 0 {
		a.logger.Debugf("%s", full)
	} else {
		a.logger.Infof("%s", full)
	}
}

func (a *logrAdapter) Error(err error, msg string, keysAndValues ...any) {
	full := formatMessage(msg, append(a.kvs, keysAndValues...))
	if err != nil {
		a.logger.Errorf("%s: %v", full, err)
	} else {
		a.logger.Errorf("%s", full)
	}
}

func (a *logrAdapter) WithValues(keysAndValues ...any) logr.LogSink {
	return &logrAdapter{logger: a.logger, name: a.name, kvs: append(append([]any{}, a.kvs...), keysAndValues...)}
}

func (a *logrAdapter) WithName(name string) logr.LogSink {
	fullName := name
	if a.name != "" {
		fullName = a.name + "/" + name
	}
	return &logrAdapter{
		logger: logging.GetLogger(fullName),
		name:   fullName,
		kvs:    a.kvs,
	}
}

// formatMessage flattens logr's key/value pairs into the message, because the
// platform logger takes a format string rather than structured fields.
func formatMessage(msg string, kvs []any) string {
	if len(kvs) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	for i := 0; i+1 < len(kvs); i += 2 {
		fmt.Fprintf(&b, " %v=%v", kvs[i], kvs[i+1])
	}
	return b.String()
}

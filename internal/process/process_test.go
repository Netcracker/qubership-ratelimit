package process

import (
	"errors"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readEnvironment points configloader at the environment alone: the YAML
// source waits on an application.yaml this package does not ship, and the
// properties under test are environment variables.
func readEnvironment() {
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
}

// The namespace is the installation's scope, and the one thing that keeps the
// RBAC a Role. Unset is a startup error, never a fallback to the whole
// cluster.
func TestNamespace_refusesAnUnsetCloudNamespace(t *testing.T) {
	t.Setenv("CLOUD_NAMESPACE", "")
	readEnvironment()

	_, err := Namespace()

	assert.ErrorContains(t, err, "CLOUD_NAMESPACE", "the startup error names the variable to set")
}

func TestNamespace_isTheCloudNamespace(t *testing.T) {
	t.Setenv("CLOUD_NAMESPACE", "biz")
	readEnvironment()

	namespace, err := Namespace()

	require.NoError(t, err)
	assert.Equal(t, "biz", namespace)
}

// line is one line the platform logger wrote: the logger's name, the level,
// and the message.
type line struct {
	Logger  string
	Level   logging.Lvl
	Message string
}

// capturedLines makes the platform logger of name keep its lines for the test
// instead of writing them, and returns them. The registry hands the adapter the
// same logger instance, so a logr logger under name writes here.
func capturedLines(t *testing.T, name string) *[]line {
	t.Helper()
	var lines []line
	logger := logging.GetLogger(name)
	logger.SetLogFormat(func(r *logging.Record) []byte {
		lines = append(lines, line{Logger: r.PackageName, Level: r.Lvl, Message: r.Message})
		return nil
	})
	t.Cleanup(func() { logger.SetLogFormat(nil) })
	return &lines
}

// NewLogrLogger connects logr, which controller-runtime and client-go log
// through, to the platform's own logger. The logger names and the key-value
// pairs appear in the lines the platform logger writes. The logr tests in this
// file write at the platform's default level, info.
func TestLogrAdapter_writesUnderTheParentAndChildNamesJoined(t *testing.T) {
	lines := capturedLines(t, "process-test-names/store")

	NewLogrLogger("process-test-names").WithName("store").Info("rebuilt")

	assert.Equal(t, []line{{Logger: "process-test-names/store", Level: logging.LvlInfo, Message: "rebuilt"}}, *lines)
}

func TestLogrAdapter_putsTheLoggersValuesBeforeTheCallsValues(t *testing.T) {
	lines := capturedLines(t, "process-test-values")

	NewLogrLogger("process-test-values").WithValues("domain", "gateway.public").Info("rebuilt", "domains", 3)

	assert.Equal(t, []line{{
		Logger: "process-test-values", Level: logging.LvlInfo, Message: "rebuilt domain=gateway.public domains=3",
	}}, *lines)
}

// WithValues copies: the logger it was called on keeps writing without the
// child's values. The child writing them is
// TestLogrAdapter_putsTheLoggersValuesBeforeTheCallsValues.
func TestLogrAdapter_leavesTheParentWithoutTheChildsValues(t *testing.T) {
	lines := capturedLines(t, "process-test-parent")
	parent := NewLogrLogger("process-test-parent")
	_ = parent.WithValues("domain", "gateway.public")

	parent.Info("rebuilt")

	assert.Equal(t, []line{{Logger: "process-test-parent", Level: logging.LvlInfo, Message: "rebuilt"}}, *lines)
}

// Goroutines that log through one logger with values of their own do not
// write into each other's lines. The calls used to append to the slice the
// logger shares, and two calls overwrote each other's pairs.
func TestLogrAdapter_keepsTheValuesOfConcurrentCallsApart(t *testing.T) {
	var mu sync.Mutex
	var messages []string
	logger := logging.GetLogger("process-test-concurrent")
	logger.SetLogFormat(func(r *logging.Record) []byte {
		mu.Lock()
		messages = append(messages, r.Message)
		mu.Unlock()
		return nil
	})
	t.Cleanup(func() { logger.SetLogFormat(nil) })
	// Nine pairs added in two calls leave the logger's slice at 18 entries
	// with room for 32, so a call that appends to it writes into the array
	// every call shares.
	shared := NewLogrLogger("process-test-concurrent").
		WithValues("k0", 0, "k1", 1, "k2", 2, "k3", 3, "k4", 4, "k5", 5, "k6", 6, "k7", 7).
		WithValues("k8", 8)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 200 {
				shared.Info("call", "i", i)
			}
		})
	}
	wg.Wait()

	// Each goroutine logs its own i 200 times, so a line that carries the pairs
	// of another call shows as one count too many and one too few.
	line := regexp.MustCompile(`^call k0=0 k1=1 k2=2 k3=3 k4=4 k5=5 k6=6 k7=7 k8=8 i=([0-7])$`)
	counts := map[string]int{}
	for _, message := range messages {
		m := line.FindStringSubmatch(message)
		if assert.NotNil(t, m, "a line of the shared logger: %q", message) {
			counts[m[1]]++
		}
	}
	for i := range 8 {
		assert.Equal(t, 200, counts[strconv.Itoa(i)], "the lines that carry i=%d", i)
	}
}

// The platform logger takes a format string rather than structured fields, so
// the pairs are flattened into the message as key=value. An odd trailing key
// is a caller's mistake; it is dropped rather than paired with a missing value.
func TestLogrAdapter_flattensThePairsIntoTheMessage(t *testing.T) {
	cases := []struct {
		name  string
		msg   string
		pairs []any
		want  string
	}{
		{"no pairs leave the message as it is", "plain", nil, "plain"},
		{"two pairs follow the message", "rebuilt", []any{"domains", 3, "took", "1s"}, "rebuilt domains=3 took=1s"},
		{"an odd trailing key is dropped", "odd", []any{"a", 1, "dangling"}, "odd a=1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := capturedLines(t, "process-test-pairs")

			NewLogrLogger("process-test-pairs").Info(c.msg, c.pairs...)

			assert.Equal(t, []line{{Logger: "process-test-pairs", Level: logging.LvlInfo, Message: c.want}}, *lines,
				"Info(%q, %v)", c.msg, c.pairs)
		})
	}
}

// An error follows the message and its pairs after a colon, and a nil error
// leaves the message as it is.
func TestLogrAdapter_writesAnErrorAtTheErrorLevel(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		msg   string
		pairs []any
		want  string
	}{
		{"an error follows the pairs", errors.New("boom"), "failed", []any{"domain", "gateway.public"},
			"failed domain=gateway.public: boom"},
		{"a nil error adds nothing", nil, "no error value", nil, "no error value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lines := capturedLines(t, "process-test-errors")

			NewLogrLogger("process-test-errors").Error(c.err, c.msg, c.pairs...)

			assert.Equal(t, []line{{Logger: "process-test-errors", Level: logging.LvlError, Message: c.want}}, *lines,
				"Error(%v, %q, %v)", c.err, c.msg, c.pairs)
		})
	}
}

// The platform level bounds the verbosity the bridge enables: level 0 at
// every platform level, levels 1 to maxVerbosity at debug, and nothing above
// that at any level. The cap keeps the request and response bodies that
// client-go logs at verbosity 8 out of a debug log. A new case goes in the
// table, named by its verbosity and platform level.
func TestLogrAdapter_boundsVerbosityByThePlatformLevel(t *testing.T) {
	// One logger per platform level, each configured the way a deployment
	// configures it, LOGGING_LEVEL_<name>. Setting the level on the logger
	// alone would race: configloader delivers its Inited events on a
	// goroutine, and the logging package handles each one by resetting every
	// registered logger to its configured level, so an Init from another test
	// could land after SetLevel and undo it. Configured, any reset lands on
	// the same level. The registry returns the same instance to the adapter,
	// so the level configured here is the one Enabled reads.
	const atError, atInfo, atDebug = "test.verbosity.error", "test.verbosity.info", "test.verbosity.debug"
	t.Setenv("LOGGING_LEVEL_TEST_VERBOSITY_ERROR", "error")
	t.Setenv("LOGGING_LEVEL_TEST_VERBOSITY_INFO", "info")
	t.Setenv("LOGGING_LEVEL_TEST_VERBOSITY_DEBUG", "debug")
	readEnvironment()
	logging.GetLogger(atError).SetLevel(logging.LvlError)
	logging.GetLogger(atInfo).SetLevel(logging.LvlInfo)
	logging.GetLogger(atDebug).SetLevel(logging.LvlDebug)
	cases := []struct {
		name    string
		logger  string
		level   int
		enabled bool
	}{
		{"level 0 is on at error", atError, 0, true},
		{"level 0 is on at info", atInfo, 0, true},
		{"level 1 is off at info", atInfo, 1, false},
		{"level 0 is on at debug", atDebug, 0, true},
		{"level 1 is on at debug", atDebug, 1, true},
		{"level 4, the cap, is on at debug", atDebug, 4, true},
		{"level 5, above the cap, is off at debug", atDebug, 5, false},
		{"level 8, the body dumps, is off at debug", atDebug, 8, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NewLogrLogger(c.logger).V(c.level).Enabled()
			assert.Equal(t, c.enabled, got, "V(%d).Enabled() on %s", c.level, c.logger)
		})
	}
}

func TestPodName_isTheDownwardAPIValue(t *testing.T) {
	t.Setenv("POD_NAME", "ratelimit-abc12")

	assert.Equal(t, "ratelimit-abc12", PodName())
}

// Outside a pod there is no pod name to borrow.
func TestPodName_isEmptyWithoutTheDownwardAPIValue(t *testing.T) {
	t.Setenv("POD_NAME", "")

	assert.Empty(t, PodName())
}

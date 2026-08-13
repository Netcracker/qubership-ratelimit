package rls

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFixedWindow_allowsUpToTheLimit(t *testing.T) {
	f := newFixedWindow(1, time.Minute)

	allowed, count := f.allow("gateway.public")

	assert.True(t, allowed)
	assert.Equal(t, 1, count)
}

func TestFixedWindow_deniesBeyondTheLimit(t *testing.T) {
	f := newFixedWindow(1, time.Minute)
	f.allow("gateway.public")

	allowed, count := f.allow("gateway.public")

	assert.False(t, allowed)
	assert.Equal(t, 2, count)
}

func TestFixedWindow_countsEachKeySeparately(t *testing.T) {
	// One bucket per domain, so one policy's traffic cannot exhaust another's.
	f := newFixedWindow(1, time.Minute)
	f.allow("gateway.public")

	allowed, _ := f.allow("gateway.private")

	assert.True(t, allowed)
}

func TestFixedWindow_reopensAfterTheWindow(t *testing.T) {
	f := newFixedWindow(1, 50*time.Millisecond)
	f.allow("gateway.public")

	time.Sleep(80 * time.Millisecond)
	allowed, count := f.allow("gateway.public")

	assert.True(t, allowed)
	assert.Equal(t, 1, count, "the counter restarts with the window")
}

func TestFixedWindow_zeroLimitAllowsEverything(t *testing.T) {
	f := newFixedWindow(0, time.Minute)

	for range 5 {
		allowed, _ := f.allow("gateway.public")
		assert.True(t, allowed)
	}
}

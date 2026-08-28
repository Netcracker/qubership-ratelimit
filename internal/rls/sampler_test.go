package rls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogSampler_capsOneSecond(t *testing.T) {
	sampler := logSampler{limit: 3}
	admitted := 0
	for range 10 {
		if ok, _ := sampler.admit(100); ok {
			admitted++
		}
	}
	assert.Equal(t, 3, admitted)
}

func TestLogSampler_reportsTheDroppedCountOnTheNextWindow(t *testing.T) {
	sampler := logSampler{limit: 1}
	for range 5 {
		sampler.admit(100)
	}

	ok, dropped := sampler.admit(101)
	assert.True(t, ok, "a new second admits again")
	assert.Equal(t, int64(4), dropped, "the suppressed lines of the previous second surface once")

	_, droppedAgain := sampler.admit(101)
	assert.Zero(t, droppedAgain, "the report is a one-shot, not a running total")
}

func TestLogSampler_aStaleTimestampCannotReopenTheWindow(t *testing.T) {
	// A goroutine that read the previous second and lost the race must spend
	// the open window's budget: flipping the window backward would mint a
	// fresh budget inside one real second.
	sampler := logSampler{limit: 1}
	sampler.admit(101)

	ok, _ := sampler.admit(100)
	assert.False(t, ok, "the stale event spends the open window, already exhausted")
	assert.Equal(t, int64(101), sampler.window.Load(), "the window never moves backward")

	ok, dropped := sampler.admit(102)
	assert.True(t, ok, "the next real second still opens normally")
	assert.Equal(t, int64(1), dropped)
}

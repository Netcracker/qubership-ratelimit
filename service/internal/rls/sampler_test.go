package rls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogSampler_admitsItsLimitWithinOneSecond(t *testing.T) {
	sampler := logSampler{limit: 3}

	admitted := make([]bool, 0, 10)
	for range 10 {
		ok, _ := sampler.admit(100)
		admitted = append(admitted, ok)
	}

	assert.Equal(t, []bool{true, true, true, false, false, false, false, false, false, false}, admitted,
		"admit(100) ten times at a limit of 3")
}

// The lines dropped in one second are reported once, by the first line admitted
// in the next second, and not again after it.
func TestLogSampler_reportsTheDroppedCountOnceInTheNextSecond(t *testing.T) {
	sampler := logSampler{limit: 1}
	for range 5 {
		sampler.admit(100)
	}

	ok, dropped := sampler.admit(101)
	_, droppedAgain := sampler.admit(101)

	assert.True(t, ok, "the first admit(101) after a full second 100")
	assert.Equal(t, int64(4), dropped, "the dropped count the first admit(101) reports")
	assert.Zero(t, droppedAgain, "the dropped count the second admit(101) reports")
}

// An event stamped with a second older than the open window spends that
// window's budget instead of reopening its own: moving the window backward
// would mint a fresh budget inside one real second. Here the window of 101 is
// spent, so the stale event and the next event of 101 are both dropped, and
// the first event of 102 reports the two.
func TestLogSampler_aStaleTimestampSpendsTheOpenWindow(t *testing.T) {
	sampler := logSampler{limit: 1}
	sampler.admit(101)

	staleOK, _ := sampler.admit(100)
	sameSecondOK, _ := sampler.admit(101)
	nextOK, dropped := sampler.admit(102)

	assert.False(t, staleOK, "admit(100) after the window of 101 is spent")
	assert.False(t, sameSecondOK, "admit(101) after the stale admit(100)")
	assert.True(t, nextOK, "admit(102)")
	assert.Equal(t, int64(2), dropped, "the dropped count admit(102) reports")
}

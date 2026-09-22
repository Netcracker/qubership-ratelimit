//go:build !race

package engine_test

import (
	"testing"

	"github.com/netcracker/qubership-ratelimit/engine/match"
)

// TestMatchManyBlocks_scanStaysLinear is the CI guard on the target scan.
// The scan is linear in the routes of the domain by design: the decision
// budget caps a domain at 128 single-rule blocks, a prefix comparison costs
// a few nanoseconds, and a route index would buy nothing for that. What the
// guard protects is the shape and the constant. An edit that makes the scan
// re-sort, re-compile, or allocate per block turns a linear walk into
// something worse, and an edit that makes a comparison expensive raises the
// constant; the load floor would show either only as a smaller throughput
// number nobody can attribute.
//
// The shape is a ratio, so the machine cancels out: eight times the blocks
// may cost at most eight times the nanoseconds, with headroom for the noise
// of a shared runner. The constant is an absolute ceiling per route, set an
// order of magnitude above what the scan costs, so a slow runner passes and
// a regression does not. The race detector multiplies every memory access
// and would measure itself, so the file is out of a -race build; the load
// floor job runs it without one.
func TestMatchManyBlocks_scanStaysLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("the scan guard is not a -short test")
	}
	const (
		// many is the budget's own cap: 128 blocks of one rule with one
		// window is the last domain that compiles.
		few  = 16
		many = 8 * few

		// routesPerBlock is what manyBlocksSnapshot builds.
		routesPerBlock = 4

		// ceilingPerRoute is nanoseconds; the scan costs about five.
		ceilingPerRoute = 100.0
	)

	cost := func(blocks int) float64 {
		snap := manyBlocksSnapshot(t, blocks)
		path := lastBlockPath(blocks)
		result := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				match.Match(snap, path, "GET")
			}
		})
		return float64(result.NsPerOp())
	}

	fewCost, manyCost := cost(few), cost(many)
	t.Logf("scan of %d blocks: %.0f ns; of %d blocks: %.0f ns", few, fewCost, many, manyCost)

	ratio := manyCost / fewCost
	if ratio > float64(many/few)*1.5 {
		t.Errorf("the target scan is no longer linear: %d blocks cost %.1fx what %d cost, want at most %dx",
			many, ratio, few, many/few)
	}
	if perRoute := manyCost / float64(many*routesPerBlock); perRoute > ceilingPerRoute {
		t.Errorf("the target scan costs %.1f ns per route, want under %.0f", perRoute, ceilingPerRoute)
	}
}

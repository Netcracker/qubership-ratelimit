package main

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redRun is a JUnit file of a red run: a failed setup node, a green reporting
// node, one passing spec, and two specs of one container under the redis
// label, one failed and one skipped.
const redRun = `<?xml version="1.0"?>
<testsuites>
  <testsuite name="ratelimit e2e" timestamp="2026-08-27T17:00:00">
    <testcase name="[BeforeSuite]" time="0.4">
      <failure message="preflight failed">no Deployment</failure>
    </testcase>
    <testcase name="[ReportAfterSuite] junit" time="0.001"/>
    <testcase name="[It] policy lifecycle accepts a policy [policy]" time="3.1"/>
    <testcase name="[It] the store enforces a limit [redis]" time="0.08">
      <failure message="request refused">429</failure>
    </testcase>
    <testcase name="[It] the store keeps the key [redis]" time="0.01">
      <skipped message="no redis-cli reachable"/>
    </testcase>
  </testsuite>
</testsuites>`

// buildRedRun parses redRun and builds the report of it.
func buildRedRun(t *testing.T) report {
	t.Helper()
	var file junitFile
	require.NoError(t, xml.Unmarshal([]byte(redRun), &file), "xml.Unmarshal of redRun")
	return build(file)
}

// groupLabeled returns the group of the report under the label, and stops the
// test when there is none.
func groupLabeled(t *testing.T, rep report, label string) group {
	t.Helper()
	labels := make([]string, 0, len(rep.Groups))
	for _, g := range rep.Groups {
		if g.Label == label {
			return g
		}
		labels = append(labels, g.Label)
	}
	require.FailNow(t, "no group labeled "+label, "the report holds the groups %v", labels)
	return group{}
}

// The red BeforeSuite counts as a failed spec, and the green ReportAfterSuite
// is not counted at all.
func TestBuildCountsSpecsByStateLeavingGreenSetupNodesOut(t *testing.T) {
	rep := buildRedRun(t)

	type counts struct{ Passed, Failed, Skipped int }
	assert.Equal(t, counts{Passed: 1, Failed: 2, Skipped: 1}, counts{rep.Passed, rep.Failed, rep.Skipped},
		"the counts of build(redRun)")
}

func TestBuildStatesTheShareOfFailedSpecsInTheVerdict(t *testing.T) {
	rep := buildRedRun(t)

	assert.Equal(t, "2 of 4 specs failed", rep.Verdict, "build(redRun).Verdict")
}

// The green ReportAfterSuite node stays out, the red BeforeSuite lands in
// setup, and the labeled groups keep their first-appearance order.
func TestBuildGroupsSpecsByTrailingLabelInFirstAppearanceOrder(t *testing.T) {
	rep := buildRedRun(t)

	labels := make([]string, 0, len(rep.Groups))
	for _, g := range rep.Groups {
		labels = append(labels, g.Label)
	}
	assert.Equal(t, []string{"setup", "policy", "redis"}, labels, "the group labels of build(redRun)")
}

func TestBuildLiftsTheSharedPrefixOfAGroupIntoItsTitle(t *testing.T) {
	rep := buildRedRun(t)

	redis := groupLabeled(t, rep, "redis")
	assert.Equal(t, "the store", redis.Title, "the title of the redis group")
	names := make([]string, 0, len(redis.Specs))
	for _, s := range redis.Specs {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"enforces a limit", "keeps the key"}, names,
		"the spec names of the redis group, with the shared prefix stripped")
}

// A group of one spec has no shared prefix to lift.
func TestBuildTitlesASingleSpecGroupByItsLabel(t *testing.T) {
	rep := buildRedRun(t)

	assert.Equal(t, "policy", groupLabeled(t, rep, "policy").Title, "the title of the policy group")
}

func TestBuildCarriesTheFailureOfARedSetupNode(t *testing.T) {
	rep := buildRedRun(t)

	setup := groupLabeled(t, rep, "setup")
	require.Len(t, setup.Specs, 1, "the specs of the setup group")
	assert.Equal(t, stateFail, setup.Specs[0].State, "the state of the BeforeSuite spec")
	assert.Contains(t, setup.Specs[0].Detail, "preflight failed", "the detail carries the failure message")
	assert.Contains(t, setup.Specs[0].Detail, "no Deployment", "the detail carries the failure body")
}

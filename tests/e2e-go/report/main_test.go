package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

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

func parse(t *testing.T, raw string) report {
	t.Helper()
	var file junitFile
	if err := xml.Unmarshal([]byte(raw), &file); err != nil {
		t.Fatal(err)
	}
	return build(file)
}

func TestBuildGroupsAndCounts(t *testing.T) {
	rep := parse(t, redRun)

	if rep.Passed != 1 || rep.Failed != 2 || rep.Skipped != 1 {
		t.Fatalf("counts = %d/%d/%d, want 1 passed, 2 failed, 1 skipped",
			rep.Passed, rep.Failed, rep.Skipped)
	}
	if rep.Verdict != "2 of 4 specs failed" {
		t.Fatalf("verdict = %q", rep.Verdict)
	}

	labels := make([]string, 0, len(rep.Groups))
	for _, g := range rep.Groups {
		labels = append(labels, g.Label)
	}
	// The green ReportAfterSuite node stays out; the red BeforeSuite lands in
	// setup, and the labeled groups keep their first-appearance order.
	if got := strings.Join(labels, ","); got != "setup,policy,redis" {
		t.Fatalf("groups = %s", got)
	}
}

func TestBuildLiftsSharedPrefixIntoTitle(t *testing.T) {
	rep := parse(t, redRun)

	redis := rep.Groups[2]
	if redis.Title != "the store" {
		t.Fatalf("redis title = %q", redis.Title)
	}
	if redis.Specs[0].Name != "enforces a limit" {
		t.Fatalf("spec name = %q, the shared prefix was not stripped", redis.Specs[0].Name)
	}
	// A single-spec group has no shared prefix to lift.
	if policy := rep.Groups[1]; policy.Title != "policy" {
		t.Fatalf("policy title = %q", policy.Title)
	}
}

func TestBuildCarriesFailureDetail(t *testing.T) {
	rep := parse(t, redRun)

	setup := rep.Groups[0].Specs[0]
	if setup.State != stateFail || !strings.Contains(setup.Detail, "no Deployment") {
		t.Fatalf("setup spec = %+v", setup)
	}
}

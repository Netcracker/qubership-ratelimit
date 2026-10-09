package main

import (
	"encoding/xml"
	"regexp"
	"strings"
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
	return buildRun(t, redRun)
}

// buildRun parses a JUnit file and builds the report of it.
func buildRun(t *testing.T, run string) report {
	t.Helper()
	var file junitFile
	require.NoError(t, xml.Unmarshal([]byte(run), &file), "xml.Unmarshal of the JUnit file:\n%s", run)
	return build(file)
}

// suiteOf wraps testcase elements in a JUnit file of one suite.
func suiteOf(testcases string) string {
	return `<testsuites><testsuite name="ratelimit e2e" timestamp="2026-10-09T10:00:00">` +
		testcases + `</testsuite></testsuites>`
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

// specNamed returns the spec of the group under the name, and stops the test
// when there is none.
func specNamed(t *testing.T, g group, name string) spec {
	t.Helper()
	names := make([]string, 0, len(g.Specs))
	for _, s := range g.Specs {
		if s.Name == name {
			return s
		}
		names = append(names, s.Name)
	}
	require.FailNow(t, "no spec named "+name, "the %s group holds the specs %q", g.Label, names)
	return spec{}
}

// renderRun builds the report of a JUnit file and renders the page of it.
func renderRun(t *testing.T, run string) string {
	t.Helper()
	var out strings.Builder
	require.NoError(t, page.Execute(&out, buildRun(t, run)), "page.Execute of the report of:\n%s", run)
	return out.String()
}

// spanTexts returns the text of every span of the class on the page, in the
// order of the page.
func spanTexts(html, class string) []string {
	span := regexp.MustCompile(`<span class="` + regexp.QuoteMeta(class) + `">([^<]*)</span>`)
	matches := span.FindAllStringSubmatch(html, -1)
	texts := make([]string, 0, len(matches))
	for _, m := range matches {
		texts = append(texts, m[1])
	}
	return texts
}

// barWidths returns the width of every spec's bar on the page, in the order of
// the page.
func barWidths(html string) []string {
	bar := regexp.MustCompile(`<span class="bar"><i style="width: ([^"]*)"></i></span>`)
	matches := bar.FindAllStringSubmatch(html, -1)
	widths := make([]string, 0, len(matches))
	for _, m := range matches {
		widths = append(widths, m[1])
	}
	return widths
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

// A spec with several labels groups under the first, the label of its
// outermost container, and loses the whole bracket from its name, as a spec
// with one label does; a label on the spec itself keeps it in its suite's
// group. Such specs used to fall into a group named other, the bracket left
// in their names.
func TestBuildGroupsASpecOfSeveralLabelsByTheFirst(t *testing.T) {
	rep := buildRun(t, suiteOf(`
    <testcase name="[It] the operator applies the configuration [operator, leader]" time="1"/>
    <testcase name="[It] the operator signs the lease [operator, leader]" time="1"/>
    <testcase name="[It] the operator hands the lease over [operator, leader, slow]" time="1"/>`))

	require.Len(t, rep.Groups, 1, "the groups of a run of one suite")
	operator := groupLabeled(t, rep, "operator")
	assert.Equal(t, "the operator", operator.Title, "the title of the operator group")
	names := make([]string, 0, len(operator.Specs))
	for _, s := range operator.Specs {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"applies the configuration", "signs the lease", "hands the lease over"}, names,
		"the spec names of the operator group, with the bracket cut whole")
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

// Ginkgo writes a panicked or interrupted spec as an <error> element rather
// than a <failure>.
func TestBuildReportsAnErroredSpecAsFailed(t *testing.T) {
	rep := buildRun(t, suiteOf(`
		<testcase name="[It] the store keeps the key [redis]" time="0.2">
			<error message="runtime error: invalid memory address" type="panicked">[PANICKED] Test Panicked</error>
		</testcase>`))

	errored := specNamed(t, groupLabeled(t, rep, "redis"), "the store keeps the key")
	assert.Equal(t, stateFail, errored.State, "the state of the errored spec")
	assert.Equal(t, 1, rep.Failed, "the failed count of build(a run with one errored spec)")
	assert.Contains(t, errored.Detail, "runtime error: invalid memory address", "the detail carries the error message")
	assert.Contains(t, errored.Detail, "[PANICKED] Test Panicked", "the detail carries the error body")
}

// The detail of a failure that carries only its message, or only its body, is
// that part alone.
func TestBuildDetailsAFailureByTheOnePartItCarries(t *testing.T) {
	tests := []struct {
		name     string
		testcase string
		want     string
	}{
		{
			name:     "message only",
			testcase: `<testcase name="[It] the store enforces a limit [redis]"><failure message="request refused"/></testcase>`,
			want:     "request refused",
		},
		{
			name:     "body only",
			testcase: `<testcase name="[It] the store enforces a limit [redis]"><failure>429</failure></testcase>`,
			want:     "429",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := buildRun(t, suiteOf(tt.testcase))

			failed := specNamed(t, groupLabeled(t, rep, "redis"), "the store enforces a limit")
			assert.Equal(t, tt.want, failed.Detail, "the detail of %s", tt.testcase)
		})
	}
}

func TestBuildCarriesTheReasonOfASkippedSpec(t *testing.T) {
	rep := buildRun(t, suiteOf(`
		<testcase name="[It] shadow rules count a refused request [shadow]" time="0">
			<skipped message="skipped - the namespace carries no ratelimit-service-redis Secret"/>
		</testcase>`))

	skipped := specNamed(t, groupLabeled(t, rep, "shadow"), "shadow rules count a refused request")
	assert.Equal(t, stateSkip, skipped.State, "the state of the skipped spec")
	assert.Equal(t, "skipped - the namespace carries no ratelimit-service-redis Secret", skipped.Detail,
		"the detail of the skipped spec")
}

// Without a failed spec the verdict counts the passed specs, and the skipped
// ones where there are any.
func TestBuildStatesTheVerdictOfARunWithoutFailures(t *testing.T) {
	tests := []struct {
		name      string
		testcases string
		want      string
	}{
		{
			name: "every spec passed",
			testcases: `
				<testcase name="[It] policy lifecycle accepts a policy [policy]" time="3.1"/>
				<testcase name="[It] policy lifecycle reports a rule problem [policy]" time="2.4"/>`,
			want: "all 2 specs passed",
		},
		{
			name: "a spec skipped",
			testcases: `
				<testcase name="[It] policy lifecycle accepts a policy [policy]" time="3.1"/>
				<testcase name="[It] policy lifecycle reports a rule problem [policy]" time="2.4"/>
				<testcase name="[It] the store keeps the key [redis]" time="0">
					<skipped message="skipped - no redis-cli reachable"/>
				</testcase>`,
			want: "2 specs passed, 1 skipped",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := buildRun(t, suiteOf(tt.testcases))

			assert.Equal(t, tt.want, rep.Verdict, "the verdict of build(suiteOf(%s))", tt.testcases)
		})
	}
}

// Every suite in tests/e2e-go carries a label; a spec outside them still
// shows, under other.
func TestBuildGroupsASpecWithoutATrailingLabelUnderOther(t *testing.T) {
	rep := buildRun(t, suiteOf(`<testcase name="[It] a spec outside every labeled container" time="0.1"/>`))

	other := groupLabeled(t, rep, "other")
	require.Len(t, other.Specs, 1, "the specs of the other group")
	assert.Equal(t, "a spec outside every labeled container", other.Specs[0].Name, "the name of the unlabeled spec")
}

func TestBuildDrawsEachBarInProportionToTheLongestSpec(t *testing.T) {
	rep := buildRun(t, suiteOf(`
		<testcase name="[It] policy lifecycle accepts a policy [policy]" time="2"/>
		<testcase name="[It] policy lifecycle reports a rule problem [policy]" time="1"/>
		<testcase name="[It] policy lifecycle revives a rule [policy]" time="0.5"/>`))

	policy := groupLabeled(t, rep, "policy")
	bars := make([]float64, 0, len(policy.Specs))
	for _, s := range policy.Specs {
		bars = append(bars, s.BarPct)
	}
	assert.Equal(t, []float64{100, 50, 25}, bars, "the bar widths of specs that took 2 s, 1 s, and 0.5 s")
}

// However short a spec is beside the longest one, the page draws its bar
// wider than the 0.0% it prints for no bar at all.
func TestPageDrawsAVisibleBarForASpecThatTookNoTime(t *testing.T) {
	html := renderRun(t, suiteOf(`
		<testcase name="[It] policy lifecycle accepts a policy [policy]" time="2"/>
		<testcase name="[It] policy lifecycle reports a rule problem [policy]" time="0"/>`))

	widths := barWidths(html)
	require.Len(t, widths, 2, "the bar widths on the page")
	assert.Equal(t, "100.0%", widths[0], "the bar width of the spec that took 2 s")
	assert.NotEqual(t, "0.0%", widths[1], "the bar width of the spec that took 0 s")
}

// A JUnit file of several suites carries a timestamp on each; the page shows
// the first.
func TestBuildStampsTheReportWithTheFirstSuitesTimestamp(t *testing.T) {
	rep := buildRun(t, `<testsuites>
  <testsuite name="ratelimit e2e" timestamp="2026-10-09T10:00:00">
    <testcase name="[It] policy lifecycle accepts a policy [policy]" time="3.1"/>
  </testsuite>
  <testsuite name="ratelimit e2e" timestamp="2026-10-09T10:20:00">
    <testcase name="[It] the store keeps the key [redis]" time="0.2"/>
  </testsuite>
</testsuites>`)

	assert.Equal(t, "2026-10-09T10:00:00", rep.Timestamp, "the timestamp of the report of two suites")
}

// The page writes a spec's time in seconds from one second on, in milliseconds
// below that, and as <1 ms below one millisecond.
func TestPageWritesASpecsDurationInTheUnitOfItsRange(t *testing.T) {
	tests := []struct {
		name    string
		seconds string
		want    string
	}{
		{name: "just under a millisecond", seconds: "0.0009", want: "&lt;1 ms"},
		{name: "one millisecond", seconds: "0.001", want: "1 ms"},
		{name: "just under a second", seconds: "0.999", want: "999 ms"},
		{name: "one second", seconds: "1", want: "1.0 s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html := renderRun(t, suiteOf(`<testcase name="[It] the store keeps the key [redis]" time="`+tt.seconds+`"/>`))

			assert.Equal(t, []string{tt.want}, spanTexts(html, "time"), "the time of a spec that took %s s", tt.seconds)
		})
	}
}

func TestPageCountsTheSpecsOfAGroupInItsHeader(t *testing.T) {
	tests := []struct {
		name      string
		testcases string
		want      string
	}{
		{
			name:      "one spec",
			testcases: `<testcase name="[It] the store keeps the key [redis]" time="0.5"/>`,
			want:      "redis &middot; 1 spec &middot; 500 ms",
		},
		{
			name: "two specs",
			testcases: `
				<testcase name="[It] the store keeps the key [redis]" time="0.25"/>
				<testcase name="[It] the store enforces a limit [redis]" time="0.25"/>`,
			want: "redis &middot; 2 specs &middot; 500 ms",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html := renderRun(t, suiteOf(tt.testcases))

			assert.Equal(t, []string{tt.want}, spanTexts(html, "suite-meta"),
				"the suite-meta spans of the page of %s", tt.testcases)
		})
	}
}

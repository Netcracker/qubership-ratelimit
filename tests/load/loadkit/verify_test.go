package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// midnight is 2027-01-16T00:00:00Z in milliseconds, a multiple of every
// window period of these tests, so offsets from it fall in the instances the
// counter store would put them in.
const midnight = int64(1_800_057_600_000)

// at returns a sample of user in the group orders that starts offset after
// midnight and lasts elapsed, with the outcome and the response code of a
// gateway that answers it that way.
func at(user string, o outcome, offset, elapsed time.Duration) sample {
	code := map[outcome]string{admitted: "200", refused: "429", undecided: "200",
		failed: "Non HTTP response code: java.net.SocketTimeoutException"}[o]
	return sample{start: midnight + offset.Milliseconds(), elapsed: elapsed.Milliseconds(),
		label: "READ", code: code, user: user, group: "orders", kind: "background", outcome: o}
}

// inGroup moves samples to group.
func inGroup(group string, samples []sample) []sample {
	for i := range samples {
		samples[i].group = group
	}
	return samples
}

// admissions returns an admission of user lasting 10 ms at each offset.
func admissions(user string, offsets ...time.Duration) []sample {
	s := make([]sample, 0, len(offsets))
	for _, o := range offsets {
		s = append(s, at(user, admitted, o, 10*time.Millisecond))
	}
	return s
}

type found struct{ kind, user, window string }

func limitInputOf(samples []sample) limitInput {
	in := limitInput{}
	for _, s := range samples {
		in.add(s)
	}
	return in
}

func violations(t *testing.T, samples []sample, windows string) []found {
	t.Helper()
	w, err := parseWindows(windows)
	require.NoError(t, err)
	_, listed, count := checkLimits(limitInputOf(samples), w, 100*time.Millisecond)
	require.Equal(t, len(listed), count, "checkLimits lists every violation of these short runs")
	got := make([]found, 0, len(listed))
	for _, v := range listed {
		got = append(got, found{v.Kind, v.User, v.Window})
	}
	return got
}

func join(parts ...[]sample) []sample {
	var all []sample //nolint:prealloc // a few short slices per test
	for _, p := range parts {
		all = append(all, p...)
	}
	return all
}

// An instance holding more admissions than the window's requests is
// reported, and one holding exactly the requests is not.
func TestCheckLimits_reportsAnInstanceThatAdmittedMoreThanItsRequests(t *testing.T) {
	samples := join(
		admissions("alice", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second, 6*time.Second),
		admissions("bob", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
	)
	assert.Equal(t, []found{{"over-admission", "alice", "5/1m0s"}}, violations(t, samples, "5/1m"))
}

// An admission counts toward an instance only where it cannot have been
// decided in the next one: carol's sixth admission starts 50 ms before the
// minute ends, inside the skew of 100 ms, while dave's ends 289 ms before it.
func TestCheckLimits_countsOnlyAdmissionsThatCannotFallInTheNextInstance(t *testing.T) {
	samples := join(
		admissions("carol", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second,
			59950*time.Millisecond),
		admissions("dave", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second,
			59700*time.Millisecond),
	)
	assert.Equal(t, []found{{"over-admission", "dave", "5/1m0s"}}, violations(t, samples, "5/1m"))
}

// An admission at the start of an instance counts toward it only where it
// cannot have been decided in the one before: uma's first admission starts
// 50 ms into the minute, inside the skew, and vic's 300 ms into it.
func TestCheckLimits_countsOnlyAdmissionsThatCannotFallInThePreviousInstance(t *testing.T) {
	samples := join(
		admissions("uma", 60050*time.Millisecond, 61*time.Second, 62*time.Second, 63*time.Second, 64*time.Second,
			65*time.Second),
		admissions("vic", 60300*time.Millisecond, 61*time.Second, 62*time.Second, 63*time.Second, 64*time.Second,
			65*time.Second),
	)
	assert.Equal(t, []found{{"over-admission", "vic", "5/1m0s"}}, violations(t, samples, "5/1m"))
}

// A user's windows count per group: mia's five admissions to orders and five
// to billing fill two instances, nina's six to orders overfill one.
func TestCheckLimits_countsTheWindowsOfAUserPerGroup(t *testing.T) {
	samples := join(
		admissions("mia", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		inGroup("billing", admissions("mia", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second)),
		admissions("nina", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second, 6*time.Second),
	)
	assert.Equal(t, []found{{"over-admission", "nina", "5/1m0s"}}, violations(t, samples, "5/1m"))
}

// The report of a window counts the instances with an admission, the ones
// that reached the requests, and the most admissions in one: five in the
// first minute, three in the second.
func TestCheckLimits_reportsHowTheInstancesFilled(t *testing.T) {
	samples := admissions("wendy", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second,
		61*time.Second, 62*time.Second, 63*time.Second)
	windows, err := parseWindows("5/1m")
	require.NoError(t, err)
	reports, _, _ := checkLimits(limitInputOf(samples), windows, 100*time.Millisecond)
	assert.Equal(t, []windowReport{{Window: "5/1m0s", Instances: 2, Full: 1, MaxAdmitted: 5}}, reports)
}

// Over-admission counts only the admissions a response confirms: kate's
// minute holds five admissions and one undecided response, kurt's five
// admissions and one sample without a response, leo's six admissions.
func TestCheckLimits_overAdmissionCountsOnlyConfirmedAdmissions(t *testing.T) {
	samples := join(
		admissions("kate", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		[]sample{at("kate", undecided, 6*time.Second, 10*time.Millisecond)},
		admissions("kurt", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		[]sample{at("kurt", failed, 6*time.Second, 10*time.Second)},
		admissions("leo", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second, 6*time.Second),
	)
	assert.Equal(t, []found{{"over-admission", "leo", "5/1m0s"}}, violations(t, samples, "5/1m"))
}

// A 429 is false when no window can have been full: erin is refused after
// four admissions in a window of five, frank after five.
func TestCheckLimits_reportsARefusalBeforeAnyWindowFilled(t *testing.T) {
	samples := join(
		admissions("erin", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second),
		[]sample{at("erin", refused, 10*time.Second, 10*time.Millisecond)},
		admissions("frank", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		[]sample{at("frank", refused, 10*time.Second, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "erin", ""}}, violations(t, samples, "5/1m"))
}

// An admission after a refusal cannot have filled the window before it:
// oscar is refused after four admissions and admitted once more later in the
// minute, paul is refused after five.
func TestCheckLimits_ignoresAdmissionsAfterTheRefusal(t *testing.T) {
	samples := join(
		admissions("oscar", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 20*time.Second),
		[]sample{at("oscar", refused, 10*time.Second, 10*time.Millisecond)},
		admissions("paul", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		[]sample{at("paul", refused, 10*time.Second, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "oscar", ""}}, violations(t, samples, "5/1m"))
}

// A refusal within the skew of a window's start may have been decided in the
// window before: quinn and tom are refused 50 ms into the second minute,
// quinn after five admissions in the first minute, tom after four.
func TestCheckLimits_acceptsARefusalThatThePreviousInstanceExplains(t *testing.T) {
	samples := join(
		admissions("quinn", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		[]sample{at("quinn", refused, 60050*time.Millisecond, 10*time.Millisecond)},
		admissions("tom", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second),
		[]sample{at("tom", refused, 60050*time.Millisecond, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "tom", ""}}, violations(t, samples, "5/1m"))
}

// A refusal within the skew of a window's end may have been decided in the
// next window: with 1/1m, xena and yuri are refused 20 ms before the minute
// ends. xena's admission 150 ms into the next minute can only have been
// decided there, and early enough to precede her refusal; yuri's 250 ms into
// it cannot precede his.
func TestCheckLimits_acceptsARefusalThatTheNextInstanceExplains(t *testing.T) {
	samples := join(
		[]sample{at("xena", refused, 59980*time.Millisecond, 10*time.Millisecond)},
		admissions("xena", 60150*time.Millisecond),
		[]sample{at("yuri", refused, 59980*time.Millisecond, 10*time.Millisecond)},
		admissions("yuri", 60250*time.Millisecond),
	)
	assert.Equal(t, []found{{"false refusal", "yuri", ""}}, violations(t, samples, "1/1m"))
}

// An admission that ends within the skew before a window starts may have
// been decided in that window: with 1/1m, rita's admission 50 ms before the
// minute ends explains her refusal a second into the next minute, and sam's
// 300 ms before it does not explain his.
func TestCheckLimits_countsAnAdmissionWithinTheSkewOfTheWindowStart(t *testing.T) {
	samples := join(
		admissions("rita", 59950*time.Millisecond),
		[]sample{at("rita", refused, 61*time.Second, 10*time.Millisecond)},
		admissions("sam", 59700*time.Millisecond),
		[]sample{at("sam", refused, 61*time.Second, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "sam", ""}}, violations(t, samples, "1/1m"))
}

// Any full window justifies a 429. With 5/10s and 8/1m, gina's refusal at
// 25 s follows three admissions in its ten seconds and eight in its minute;
// henry's follows three and seven.
func TestCheckLimits_acceptsARefusalThatAnyFullWindowExplains(t *testing.T) {
	samples := join(
		admissions("gina", 1*time.Second, 2*time.Second, 3*time.Second, 11*time.Second, 12*time.Second,
			21*time.Second, 22*time.Second, 23*time.Second),
		[]sample{at("gina", refused, 25*time.Second, 10*time.Millisecond)},
		admissions("henry", 1*time.Second, 2*time.Second, 11*time.Second, 12*time.Second,
			21*time.Second, 22*time.Second, 23*time.Second),
		[]sample{at("henry", refused, 25*time.Second, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "henry", ""}}, violations(t, samples, "5/10s,8/1m"))
}

// A sample without a response may have been admitted: ivan's refusal follows
// four admissions and a request that timed out, judy's four admissions only.
func TestCheckLimits_countsASampleWithoutResponseAsAPossibleAdmission(t *testing.T) {
	samples := join(
		admissions("ivan", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second),
		[]sample{
			at("ivan", failed, 5*time.Second, 10*time.Second),
			at("ivan", refused, 20*time.Second, 10*time.Millisecond),
		},
		admissions("judy", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second),
		[]sample{at("judy", refused, 20*time.Second, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "judy", ""}}, violations(t, samples, "5/1m"))
}

// An undecided response may have been admitted, because the service can
// charge the counters after the filter stopped waiting: olga's refusal
// follows four admissions and an undecided response, pete's four admissions
// only.
func TestCheckLimits_countsAnUndecidedResponseAsAPossibleAdmission(t *testing.T) {
	samples := join(
		admissions("olga", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second),
		[]sample{
			at("olga", undecided, 5*time.Second, 52*time.Millisecond),
			at("olga", refused, 20*time.Second, 10*time.Millisecond),
		},
		admissions("pete", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second),
		[]sample{at("pete", refused, 20*time.Second, 10*time.Millisecond)},
	)
	assert.Equal(t, []found{{"false refusal", "pete", ""}}, violations(t, samples, "5/1m"))
}

// The statistics of a step cover the step without its first -warmup, and
// its rate divides their samples by that measured span.
func TestBuildReport_stepStatisticsLeaveOutTheWarmup(t *testing.T) {
	samples := []sample{
		at("a", admitted, 0, 100*time.Millisecond),
		at("a", admitted, 3*time.Second, 5*time.Millisecond),
		at("a", admitted, 4*time.Second, 7*time.Millisecond),
		at("a", admitted, 9999*time.Millisecond, 9*time.Millisecond),
		at("a", admitted, 10*time.Second, 200*time.Millisecond),
		at("a", admitted, 13*time.Second, 1*time.Millisecond),
	}
	steps, err := parseSteps("1:10s,2:10s")
	require.NoError(t, err)
	rep := buildReport(samples, verifyConfig{steps: steps, warmup: 2 * time.Second})

	type measured struct {
		samples       int64
		seconds, rate float64
		p50, max      int64
	}
	got := make([]measured, 0, len(rep.Steps))
	for _, s := range rep.Steps {
		got = append(got, measured{s.Samples, s.Seconds, s.AchievedRPS, s.P50Millis, s.MaxMillis})
	}
	assert.Equal(t, []measured{{3, 8, 0.375, 7, 9}, {1, 8, 0.125, 1, 1}}, got)
	assert.Equal(t, int64(6), rep.Total.Samples, "the whole run counts the warmups too")
}

// The steps start at the moment the schedule began, not at the earliest
// sample: a leading step of rate 0 sends nothing and still lasts its time.
func TestBuildReport_stepsStartAtTheStartOfTheSchedule(t *testing.T) {
	samples := []sample{at("a", admitted, 12*time.Second, time.Millisecond),
		at("a", admitted, 13*time.Second, time.Millisecond)}
	steps, err := parseSteps("0:10s,1:10s")
	require.NoError(t, err)
	rep := buildReport(samples, verifyConfig{steps: steps, start: midnight})

	assert.Equal(t, []int64{0, 2}, []int64{rep.Steps[0].Samples, rep.Steps[1].Samples}, "samples of steps 1 and 2")
}

// A run that meets every threshold exactly, at its bound, passes with no
// failure: six samples in ten seconds against 0.6 of one per second, a p99
// of 10 ms against 10 ms, and a lag of one second against one second.
func TestBuildReport_passesARunAtTheBoundOfEveryThreshold(t *testing.T) {
	steps, err := parseSteps("1:10s")
	require.NoError(t, err)
	windows, err := parseWindows("5/1m")
	require.NoError(t, err)
	samples := join(admissions("a", 1*time.Second, 2*time.Second, 3*time.Second, 4*time.Second, 5*time.Second),
		[]sample{at("a", refused, 6*time.Second, 10*time.Millisecond)})
	for i := range samples {
		samples[i].lag = 1000
	}
	rep := buildReport(samples, verifyConfig{steps: steps, start: midnight, windows: windows,
		skew: 100 * time.Millisecond, minRateRatio: 0.6, maxP99: 10 * time.Millisecond, maxLag: time.Second})

	assert.True(t, rep.Passed)
	assert.Empty(t, rep.Failures)
}

// Each threshold fails the run on its own, with a failure that names it.
func TestBuildReport_failsTheRunOnEachThreshold(t *testing.T) {
	steps, err := parseSteps("1:10s")
	require.NoError(t, err)
	windows, err := parseWindows("1/1m")
	require.NoError(t, err)
	behind := at("a", admitted, 1*time.Second, 10*time.Millisecond)
	behind.lag = 2000
	gatewayError := at("a", admitted, 1*time.Second, 10*time.Millisecond)
	gatewayError.code = "503"

	tests := []struct {
		name    string
		samples []sample
		cfg     verifyConfig
		want    string
	}{
		{"an answer other than 200 or 429", []sample{gatewayError}, verifyConfig{steps: steps},
			"answered with neither 200 nor 429"},
		{"an answer without a decision", []sample{at("a", undecided, time.Second, 10*time.Millisecond)},
			verifyConfig{steps: steps}, "without a rate limit decision"},
		{"a step below its rate", admissions("a", time.Second), verifyConfig{steps: steps, minRateRatio: 0.5},
			"achieved 0.1 requests per second of the 1.0 targeted"},
		{"a step behind its schedule", []sample{behind}, verifyConfig{steps: steps, maxLag: time.Second},
			"fell 2000 ms behind its schedule"},
		{"a slow step", []sample{at("a", admitted, time.Second, 60*time.Millisecond)},
			verifyConfig{steps: steps, maxP99: 50 * time.Millisecond}, "p99 of 60 ms"},
		{"a broken limit", admissions("a", time.Second, 2*time.Second),
			verifyConfig{steps: steps, windows: windows, skew: 100 * time.Millisecond}, "break the limits"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := buildReport(tt.samples, tt.cfg)
			assert.False(t, rep.Passed)
			if assert.Len(t, rep.Failures, 1) {
				assert.Contains(t, rep.Failures[0], tt.want)
			}
		})
	}
}

func TestParseSteps_refusesAMalformedStep(t *testing.T) {
	for _, v := range []string{"", "10", "x:1m", "-1:1m", "10:0", "10:soon"} {
		_, err := parseSteps(v)
		assert.Error(t, err, "parseSteps(%q)", v)
	}
}

func TestParseSteps_readsSecondsAndGoDurations(t *testing.T) {
	steps, err := parseSteps("10:120, 0.5:2m")
	require.NoError(t, err)
	assert.Equal(t, []step{{10, 2 * time.Minute}, {0.5, 2 * time.Minute}}, steps)
}

func TestParseWindows_refusesAMalformedWindow(t *testing.T) {
	for _, v := range []string{"50", "0/1m", "x/1m", "50/0", "50/1500us"} {
		_, err := parseWindows(v)
		assert.Error(t, err, "parseWindows(%q)", v)
	}
}

func TestParseWindows_readsSecondsAndGoDurations(t *testing.T) {
	windows, err := parseWindows("50/60,1000/1h")
	require.NoError(t, err)
	assert.Equal(t, []window{{50, time.Minute}, {1000, time.Hour}}, windows)
}

// The nearest-rank quantile returns a recorded value: the smallest one whose
// rank reaches q of the count.
func TestHistogram_quantileIsTheNearestRank(t *testing.T) {
	var h histogram
	for _, ms := range []int64{4, 1, 3, 2} {
		h.add(ms)
	}
	for _, tt := range []struct {
		q    float64
		want int64
	}{{0.25, 1}, {0.5, 2}, {0.51, 3}, {0.99, 4}, {1, 4}} {
		assert.Equal(t, tt.want, h.quantile(tt.q), "quantile(%v) of 1, 2, 3, 4", tt.q)
	}
	var empty histogram
	assert.Equal(t, int64(0), empty.quantile(0.99), "quantile of an empty histogram")
}

func TestFloorDiv_roundsTowardNegativeInfinity(t *testing.T) {
	for _, tt := range []struct{ a, b, want int64 }{{7, 5, 1}, {5, 5, 1}, {-1, 5, -1}, {-5, 5, -1}, {-6, 5, -2}} {
		assert.Equal(t, tt.want, floorDiv(tt.a, tt.b), "floorDiv(%d, %d)", tt.a, tt.b)
	}
}

// The command reports a failed check through its exit status, the contract
// run.sh and the workflow read: 1 for a broken limit, 0 for the same run
// checked against a limit it kept.
func TestRun_verifyExitsWithOneWhenACheckFails(t *testing.T) {
	dir := t.TempDir()
	jtl := filepath.Join(dir, "results.jtl")
	require.NoError(t, os.WriteFile(jtl, []byte(strings.Join([]string{
		"timeStamp,elapsed,label,responseCode,user,group,kind,remaining,lag",
		"1800057601000,10,READ,200,a,orders,background,1,0",
		"1800057602000,10,READ,200,a,orders,background,0,0",
	}, "\n")+"\n"), 0o644))
	args := func(windows string) []string {
		return []string{"verify", "-jtl", jtl, "-steps", "1:10s", "-windows", windows, "-out", dir}
	}
	var out, errOut strings.Builder
	assert.Equal(t, 1, run(args("1/1m"), &out, &errOut), "verify against 1/1m")
	assert.Equal(t, 0, run(args("2/1m"), &out, &errOut), "verify against 2/1m")
}

// -metrics adds the table of the calls to the rate limit service to
// summary.md, and -require-metrics fails a run whose metrics hold no call;
// -require-metrics without -metrics is a usage error.
func TestRun_verifyReportsTheCallsToTheRateLimitService(t *testing.T) {
	dir := t.TempDir()
	jtl := filepath.Join(dir, "results.jtl")
	require.NoError(t, os.WriteFile(jtl, []byte(strings.Join([]string{
		"timeStamp,elapsed,label,responseCode,user,group,kind,remaining,lag",
		"1800057601000,10,READ,200,a,orders,background,1,0",
		"1800057602000,10,READ,200,a,orders,background,0,0",
	}, "\n")+"\n"), 0o644))
	lines := make([]string, 0, 2)
	for i, n := range []float64{0, 2} {
		check := histogramStats{Bounds: []float64{0.001}, Counts: []float64{n}, Count: n}
		line, err := json.Marshal(metricsSample{T: 1800057601500 + int64(i)*5000,
			Gateway: map[string]gatewayStats{"a": gw(envoyHist(n, n, n), 0)},
			Service: map[string]serviceStats{"s": {Check: check}}})
		require.NoError(t, err)
		lines = append(lines, string(line))
	}
	called, empty := filepath.Join(dir, "called.jsonl"), filepath.Join(dir, "empty.jsonl")
	require.NoError(t, os.WriteFile(called, []byte(strings.Join(lines, "\n")+"\n"), 0o644))
	require.NoError(t, os.WriteFile(empty, nil, 0o644))
	args := func(extra ...string) []string {
		return append([]string{"verify", "-jtl", jtl, "-steps", "1:10s", "-out", dir}, extra...)
	}
	var out, errOut strings.Builder

	t.Run("a file with calls passes and fills the table", func(t *testing.T) {
		assert.Equal(t, 0, run(args("-metrics", called, "-require-metrics"), &out, &errOut))
		md, err := os.ReadFile(filepath.Join(dir, "summary.md"))
		require.NoError(t, err)
		assert.Contains(t, string(md), "\n| 1 | 2 | <1 | <1 | <1 | 0 | 2 | ")
	})
	t.Run("a file without calls fails", func(t *testing.T) {
		assert.Equal(t, 1, run(args("-metrics", empty, "-require-metrics"), &out, &errOut))
	})
	t.Run("-require-metrics alone is a usage error", func(t *testing.T) {
		assert.Equal(t, 2, run(args("-require-metrics"), &out, &errOut))
	})
}

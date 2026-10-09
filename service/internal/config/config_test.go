package config

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	v1 "github.com/netcracker/qubership-ratelimit/api/v1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/metrics"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

const testNamespace = "biz"

// fixture is a directory written the way the kubelet projects the ConfigMap:
// the manifest under its key, one gzip payload per domain.
type fixture struct {
	t   *testing.T
	dir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, dir: t.TempDir()}
}

// spec is the spec of domain with one rule of requests a minute.
func spec(domain string, requests int32) v1.RateLimitPolicySpec {
	return v1.RateLimitPolicySpec{Domain: domain, Limits: []v1.LimitBlock{{
		Name: "api", Rules: []v1.Rule{{Name: "total", Rates: []v1.Rate{{Requests: requests, PeriodSeconds: 60}}}}}}}
}

// write puts the specs in the directory under a manifest at the given
// generation for every domain, each spec under its own domain.
func (f *fixture) write(generation int64, specs ...v1.RateLimitPolicySpec) manifest.Manifest {
	f.t.Helper()
	payloads := make(map[string]any, len(specs))
	for _, s := range specs {
		payloads[s.Domain] = s
	}
	return f.writePayloads(generation, payloads)
}

// writePayloads puts each payload in the directory under the key of its
// domain, and a manifest that names every domain at the given generation with
// the hash its payload has.
func (f *fixture) writePayloads(generation int64, payloads map[string]any) manifest.Manifest {
	f.t.Helper()
	m := manifest.Manifest{OperatorVersion: "t", Domains: map[string]manifest.Domain{}}
	for domain, payload := range payloads {
		compressed, hash, err := manifest.EncodePayload(payload)
		require.NoError(f.t, err)
		f.writeCompressed(domain, compressed)
		m.Domains[domain] = manifest.Domain{Generation: generation, UID: "uid-" + domain, Hash: hash}
	}
	raw, err := manifest.Encode(m)
	require.NoError(f.t, err)
	f.writeManifest(raw)
	return m
}

// writePayload replaces the payload of domain and leaves the manifest as it is.
func (f *fixture) writePayload(domain string, payload any) {
	f.t.Helper()
	compressed, _, err := manifest.EncodePayload(payload)
	require.NoError(f.t, err)
	f.writeCompressed(domain, compressed)
}

func (f *fixture) writeCompressed(domain string, compressed []byte) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, manifest.PayloadKey(domain)), compressed, 0o600))
}

func (f *fixture) writeManifest(raw []byte) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, contract.ManifestKey), raw, 0o600))
}

func (f *fixture) remove(name string) {
	f.t.Helper()
	require.NoError(f.t, os.Remove(filepath.Join(f.dir, name)))
}

// apply writes the specs at generation, reads the directory, and applies the
// reading, which is what the watcher does on a change.
func (f *fixture) apply(a *Applier, generation int64, specs ...v1.RateLimitPolicySpec) {
	f.t.Helper()
	f.write(generation, specs...)
	cfg, err := Read(f.dir)
	require.NoError(f.t, err)
	a.Apply(cfg)
}

func newApplier() *Applier {
	return &Applier{Namespace: testNamespace, Store: store.New(), Counters: memory.New(), Log: logr.Discard()}
}

// gzipped compresses raw the way the operator compresses a payload.
func gzipped(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// The reader: what it applies, and every way it refuses.

func TestRead_returnsTheManifestAndTheSpecOfEveryDomain(t *testing.T) {
	f := newFixture(t)
	want := f.write(3, spec("gateway.public", 10), spec("gateway.private", 20))

	cfg, err := Read(f.dir)

	require.NoError(t, err)
	assert.Equal(t, want.Domains, cfg.Manifest.Domains)
	assert.Equal(t, map[string]v1.RateLimitPolicySpec{
		"gateway.public":  spec("gateway.public", 10),
		"gateway.private": spec("gateway.private", 20),
	}, cfg.Specs)
}

// An empty directory is the volume mounted optional before the ConfigMap
// exists.
func TestRead_reportsAnEmptyDirectoryAsAbsent(t *testing.T) {
	_, err := Read(newFixture(t).dir)

	assert.ErrorIs(t, err, ErrAbsent)
}

// Before the volume is mounted the directory is not there at all.
func TestRead_reportsAMissingDirectoryAsAbsent(t *testing.T) {
	_, err := Read(filepath.Join(newFixture(t).dir, "not-mounted"))

	assert.ErrorIs(t, err, ErrAbsent)
}

// A manifest the reader cannot open as a file, here a directory under the
// manifest's key, is a read that failed on the way: neither ErrAbsent nor a
// *Refusal.
func TestRead_reportsAManifestItCannotOpenAsAFailedRead(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(f.dir, contract.ManifestKey), 0o750))

	_, err := Read(f.dir)

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrAbsent)
	var refusal *Refusal
	assert.NotErrorAs(t, err, &refusal)
}

// Every row starts from a sound directory and damages one part of it. The
// refusal carries the format version the manifest declared, zero when it
// could not be read that far, and a reason that names what was refused: the
// reason is what the replica reports on the applied endpoint.
func TestRead_refusesAReadingItCannotApplyWhole(t *testing.T) {
	cases := map[string]struct {
		damage  func(f *fixture)
		version int
		reason  string
	}{
		"a format version this reader does not accept": {
			damage: func(f *fixture) {
				f.writeManifest([]byte(`{"formatVersion": 99, "operatorVersion": "x", "domains": {}}`))
			},
			version: 99, reason: "unsupported format version",
		},
		"a field the manifest does not define": {
			damage: func(f *fixture) {
				f.writeManifest([]byte(`{"formatVersion": 1, "operatorVersion": "x", "domains": {}, "extra": 1}`))
			},
			version: 1, reason: "extra",
		},
		"a manifest that is not JSON": {
			damage:  func(f *fixture) { f.writeManifest([]byte(`{`)) },
			version: 0, reason: "malformed",
		},
		"a payload the manifest names but the directory lacks": {
			damage:  func(f *fixture) { f.remove(manifest.PayloadKey("gateway.public")) },
			version: 1, reason: "read the payload",
		},
		"a payload whose hash disagrees with the manifest": {
			damage:  func(f *fixture) { f.writePayload("gateway.public", spec("gateway.public", 11)) },
			version: 1, reason: "does not match",
		},
		"a payload with a field the spec does not define": {
			// The hash is over the bytes as written, so it agrees; the strict
			// decode is what refuses.
			damage: func(f *fixture) {
				f.writePayloads(1, map[string]any{
					"gateway.public": map[string]any{"domain": "gateway.public", "limits": []any{}, "futureField": true},
				})
			},
			version: 1, reason: "futureField",
		},
		"a payload that decompresses past the decoder's limit": {
			damage: func(f *fixture) {
				f.writeCompressed("gateway.public", gzipped(f.t, bytes.Repeat([]byte{'0'}, manifest.MaxPayloadSize+1)))
			},
			version: 1, reason: "decompresses past",
		},
		"a payload that belongs to another domain": {
			damage: func(f *fixture) {
				f.writePayloads(1, map[string]any{"gateway.public": spec("gateway.other", 10)})
			},
			version: 1, reason: `for domain "gateway.other"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.write(1, spec("gateway.public", 10))
			tc.damage(f)

			_, err := Read(f.dir)

			var refusal *Refusal
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, tc.version, refusal.FormatVersion, "the declared format version")
			assert.ErrorContains(t, refusal, tc.reason)
		})
	}
}

// The applier: the Ready gate and the report.

// The versions are reported before anything is applied, so the operator can
// read them off a NotReady replica.
func TestApplier_isNotReadyBeforeTheFirstApply(t *testing.T) {
	a := newApplier()

	report := a.Report()

	assert.False(t, a.Ready())
	assert.Empty(t, report.Domains)
	assert.Equal(t, manifest.SupportedVersions(), report.FormatVersions)
}

// An explicitly empty manifest is a configuration: the replica is Ready, and
// every request is an unknown domain.
func TestApplier_isReadyAfterApplyingAnEmptyManifest(t *testing.T) {
	a := newApplier()

	a.Apply(Configuration{Manifest: manifest.Manifest{FormatVersion: 1, Domains: map[string]manifest.Domain{}}})

	assert.True(t, a.Ready())
	assert.False(t, a.Store.HasDomain("gateway.public"))
}

// A refusal after the first apply keeps the replica Ready on its snapshot.
func TestApplier_staysReadyThroughARefusalAfterTheFirstApply(t *testing.T) {
	a := newApplier()
	a.Apply(Configuration{Manifest: manifest.Manifest{FormatVersion: 1, Domains: map[string]manifest.Domain{}}})

	a.Refuse(&Refusal{FormatVersion: 99, Err: errors.New("unsupported")})

	assert.True(t, a.Ready())
	assert.Equal(t, &applied.Refusal{FormatVersion: 99, Reason: "unsupported"}, a.Report().Refusal)
}

func TestApplier_staysNotReadyThroughARefusalBeforeTheFirstApply(t *testing.T) {
	a := newApplier()

	a.Refuse(&Refusal{FormatVersion: 2, Err: errors.New("no")})

	assert.False(t, a.Ready())
	report := a.Report()
	assert.Equal(t, &applied.Refusal{FormatVersion: 2, Reason: "no"}, report.Refusal)
	assert.Empty(t, report.Domains)
}

// The report is one set's facts: a refused reading rides on the set it left
// in place, with that set's generations.
func TestApplier_reportsARefusalWithTheGenerationsOfTheSetItLeftInPlace(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 4, spec("gateway.public", 10))

	a.Refuse(&Refusal{FormatVersion: 99, Err: errors.New("unsupported")})

	report := a.Report()
	assert.Equal(t, int64(4), report.Domains["gateway.public"].Generation)
	assert.Equal(t, &applied.Refusal{FormatVersion: 99, Reason: "unsupported"}, report.Refusal)
}

// The applied set that follows a refusal carries the new generation and no
// refusal, and the refused set a reader may still hold is not rewritten under
// it. No reader can pair the refusal with the generation that answered it.
func TestApplier_reportsNoRefusalAfterTheNextApply(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 4, spec("gateway.public", 10))
	a.Refuse(&Refusal{FormatVersion: 99, Err: errors.New("unsupported")})
	refused := a.Store.Load()

	f.apply(a, 5, spec("gateway.public", 11))

	report := a.Report()
	assert.Equal(t, int64(5), report.Domains["gateway.public"].Generation)
	assert.Nil(t, report.Refusal)
	assert.Equal(t, &applied.Refusal{FormatVersion: 99, Reason: "unsupported"}, ReportOf(refused).Refusal,
		"the refusal of the set a reader already held")
}

func TestApplier_bindsEveryDomainAtTheGenerationOfTheManifest(t *testing.T) {
	f := newFixture(t)
	a := newApplier()

	f.apply(a, 4, spec("gateway.public", 10), spec("gateway.private", 20))

	assert.True(t, a.Store.HasDomain("gateway.public"))
	assert.True(t, a.Store.HasDomain("gateway.private"))
	report := a.Report()
	assert.Equal(t, int64(4), report.Domains["gateway.public"].Generation)
	assert.Equal(t, "uid-gateway.public", report.Domains["gateway.public"].UID)
	assert.Equal(t, int64(4), report.Domains["gateway.private"].Generation)
	assert.Nil(t, report.Refusal)
}

// The generation rides on the domain the engine is bound to, so the report
// and the rules a reader pairs it with come from one load.
func TestApplier_reportsTheAppliedFactsOfTheCurrentRuleSet(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 4, spec("gateway.public", 10))

	report := a.Report()

	d, ok := a.Store.Load().Domain("gateway.public")
	require.True(t, ok)
	assert.Equal(t, applied.Domain{Generation: d.Generation, UID: d.UID, AppliedAt: d.AppliedAt},
		report.Domains["gateway.public"])
}

func TestApplier_servesTheReportAsJSON(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 4, spec("gateway.public", 10), spec("gateway.private", 20))

	recorder := httptest.NewRecorder()
	a.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, contract.AppliedPath, nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	var served applied.Report
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &served))
	assert.Equal(t, int64(4), served.Domains["gateway.private"].Generation)
	assert.Equal(t, manifest.SupportedVersions(), served.FormatVersions)
}

// A domain whose payload hash did not move keeps its engine, and with it the
// warm token cache, while its generation moves with the manifest. The domain
// whose payload changed is the control.
func TestApplier_reusesTheEngineOfAnUnchangedDomain(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 1, spec("gateway.public", 10), spec("gateway.private", 20))
	unchanged := a.Store.Engine("gateway.public")
	changed := a.Store.Engine("gateway.private")

	f.apply(a, 2, spec("gateway.public", 10), spec("gateway.private", 21))

	assert.Same(t, unchanged, a.Store.Engine("gateway.public"), "the engine of the unchanged gateway.public")
	assert.NotSame(t, changed, a.Store.Engine("gateway.private"), "the engine of the changed gateway.private")
	assert.Equal(t, int64(2), a.Report().Domains["gateway.public"].Generation)
}

// The swap time moves only when the enforced rules change while the replica
// runs. It used to be set on every apply, the first one after a restart
// included, so a restarted replica reported a rule change that never happened.
func TestApplier_leavesTheSwapTimeAtZeroOnTheFirstApply(t *testing.T) {
	metrics.SnapshotTimestamp.Set(0)
	f := newFixture(t)
	a := newApplier()

	f.apply(a, 1, spec("gateway.public", 10))

	assert.Zero(t, testutil.ToFloat64(metrics.SnapshotTimestamp))
}

// A new generation of the same payload is not a change of the rules.
func TestApplier_leavesTheSwapTimeOnANewGenerationOfTheSamePayload(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 1, spec("gateway.public", 10))
	metrics.SnapshotTimestamp.Set(0)

	f.apply(a, 2, spec("gateway.public", 10))

	assert.Zero(t, testutil.ToFloat64(metrics.SnapshotTimestamp))
}

// A changed payload stamps the swap time. This is the control of the two tests
// that leave the swap time at zero.
func TestApplier_stampsTheSwapTimeWhenAPayloadChanges(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 1, spec("gateway.public", 10))
	metrics.SnapshotTimestamp.Set(0)

	f.apply(a, 2, spec("gateway.public", 11))

	assert.Positive(t, testutil.ToFloat64(metrics.SnapshotTimestamp))
}

// A spec the operator validated under rules this build does not share: two
// rules of one name, which the compiler refuses.
func badSpec(domain string) v1.RateLimitPolicySpec {
	return v1.RateLimitPolicySpec{Domain: domain, Limits: []v1.LimitBlock{{
		Name: "api", Rules: []v1.Rule{
			{Name: "total", Rates: []v1.Rate{{Requests: 1, PeriodSeconds: 60}}},
			{Name: "total", Rates: []v1.Rate{{Requests: 2, PeriodSeconds: 60}}},
		}}}}
}

// The rules enforced a moment ago stay enforced, the design's last-good, and
// the domain is reported at the generation it enforces, so the operator sees
// this replica behind on that one domain while the others move on. The
// manifest was applied, so nothing is refused.
func TestApplier_aSpecThatDoesNotCompileHereKeepsTheLastGoodEngine(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 4, spec("gateway.public", 10), spec("gateway.private", 20))
	lastGood := a.Store.Engine("gateway.public")

	f.apply(a, 5, badSpec("gateway.public"), spec("gateway.private", 21))

	assert.True(t, a.Ready())
	assert.Same(t, lastGood, a.Store.Engine("gateway.public"), "the engine of gateway.public")
	report := a.Report()
	assert.Equal(t, int64(4), report.Domains["gateway.public"].Generation)
	assert.Equal(t, int64(5), report.Domains["gateway.private"].Generation)
	assert.Nil(t, report.Refusal)
}

// The hash kept with a last-good engine is the one of its own payload, so the
// good payload back under a new generation reuses that engine.
func TestApplier_reusesTheLastGoodEngineWhenItsPayloadReturns(t *testing.T) {
	f := newFixture(t)
	a := newApplier()
	f.apply(a, 4, spec("gateway.public", 10), spec("gateway.private", 20))
	lastGood := a.Store.Engine("gateway.public")
	f.apply(a, 5, badSpec("gateway.public"), spec("gateway.private", 21))

	f.apply(a, 6, spec("gateway.public", 10), spec("gateway.private", 21))

	assert.Same(t, lastGood, a.Store.Engine("gateway.public"), "the engine of the payload of generation 4")
	assert.Equal(t, int64(6), a.Report().Domains["gateway.public"].Generation)
}

// A domain this replica never applied has nothing to keep: it is claimed, so
// a request for it is not an unknown domain, and it enforces nothing, reported
// at generation zero so the operator sees this replica behind.
func TestApplier_aSpecThatDoesNotCompileHereAndWasNeverAppliedClaimsTheDomainEmpty(t *testing.T) {
	f := newFixture(t)
	a := newApplier()

	f.apply(a, 5, badSpec("gateway.public"), spec("gateway.private", 20))

	assert.True(t, a.Ready())
	require.True(t, a.Store.HasDomain("gateway.public"))
	assert.Empty(t, a.Store.Load().Snapshot("gateway.public").Blocks)
	report := a.Report()
	assert.Equal(t, int64(0), report.Domains["gateway.public"].Generation)
	assert.Equal(t, int64(5), report.Domains["gateway.private"].Generation, "the other domain is untouched")
}

// The watcher: one apply per change of the manifest, through file events
// and through the resync timer.

func startWatcher(t *testing.T, dir string, a *Applier) {
	t.Helper()
	runWatcher(t, &Watcher{Dir: dir, Applier: a, Log: logr.Discard(),
		Resync: 200 * time.Millisecond, Settle: 20 * time.Millisecond})
}

// runWatcher runs w until the test ends.
func runWatcher(t *testing.T, w *Watcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

// waitForGeneration waits until the applier reports generation for
// gateway.public.
func waitForGeneration(t *testing.T, a *Applier, generation int64) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, generation, a.Report().Domains["gateway.public"].Generation,
			"the reported generation of gateway.public")
	}, 2*time.Second, 10*time.Millisecond, "waiting for the watcher to apply generation %d", generation)
}

func waitForRefusal(t *testing.T, a *Applier) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotNil(c, a.Report().Refusal, "the reported refusal")
	}, 2*time.Second, 10*time.Millisecond, "waiting for the watcher to refuse the manifest")
}

func waitForAbsence(t *testing.T, a *Applier) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, a.Report().ConfigAbsent, "the reported absence")
	}, 2*time.Second, 10*time.Millisecond, "waiting for the watcher to report the manifest gone")
}

// unsupported is a manifest of a format version this reader does not accept.
var unsupported = []byte(`{"formatVersion": 99, "operatorVersion": "x", "domains": {}}`)

func TestWatcher_appliesTheConfigurationPresentAtStart(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()

	startWatcher(t, f.dir, a)

	waitForGeneration(t, a, 1)
}

func TestWatcher_appliesAChangedManifest(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)
	waitForGeneration(t, a, 1)

	f.write(2, spec("gateway.public", 11))

	waitForGeneration(t, a, 2)
}

// A refusal is reported, and the snapshot stays.
func TestWatcher_keepsTheSnapshotThroughARefusedManifest(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)
	waitForGeneration(t, a, 1)

	f.writeManifest(unsupported)

	waitForRefusal(t, a)
	assert.True(t, a.Store.HasDomain("gateway.public"))
	assert.Equal(t, int64(1), a.Report().Domains["gateway.public"].Generation)
}

// The files vanish: the replica stays Ready on what it applied, and the
// absence is reported and counted, since nothing will rebuild what it holds.
func TestWatcher_keepsTheSnapshotWhenTheManifestVanishes(t *testing.T) {
	t.Cleanup(func() { metrics.ConfigAbsent.Set(0) })
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)
	waitForGeneration(t, a, 1)

	f.remove(contract.ManifestKey)

	waitForAbsence(t, a)
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.ConfigAbsent))
	assert.True(t, a.Ready())
	assert.Equal(t, int64(1), a.Report().Domains["gateway.public"].Generation)
}

// A good manifest that comes back after a refusal and a removal is applied,
// and the refusal and the absence both go.
func TestWatcher_aGoodManifestClearsAPendingRefusalAndAbsence(t *testing.T) {
	t.Cleanup(func() { metrics.ConfigAbsent.Set(0) })
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)
	waitForGeneration(t, a, 1)
	f.writeManifest(unsupported)
	waitForRefusal(t, a)
	f.remove(contract.ManifestKey)
	waitForAbsence(t, a)

	f.write(3, spec("gateway.public", 11))

	waitForGeneration(t, a, 3)
	report := a.Report()
	assert.Nil(t, report.Refusal)
	assert.False(t, report.ConfigAbsent)
	assert.Zero(t, testutil.ToFloat64(metrics.ConfigAbsent))
}

// The directory is not there at all until it is. No timeout turns a missing
// configuration into an empty one: the replica stays NotReady across the
// resyncs of the Never window, and the resync timer then finds the directory
// and applies it. The window is the behavior here, not a wait for a condition.
func TestWatcher_staysNotReadyUntilAMissingDirectoryAppears(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "config")
	a := newApplier()
	startWatcher(t, dir, a)

	assert.Never(t, a.Ready, 300*time.Millisecond, 10*time.Millisecond,
		"the replica turned Ready with no directory to read")

	require.NoError(t, os.Mkdir(dir, 0o750))
	f := &fixture{t: t, dir: dir}
	f.write(1, spec("gateway.public", 10))
	require.Eventually(t, a.Ready, 3*time.Second, 10*time.Millisecond,
		"waiting for the resync timer to find the directory and apply its contents")
}

// The kubelet's periodic refresh rewrites unchanged files, and the same
// manifest is the same configuration: no second swap. The window covers two
// resyncs of the watcher, so a read that applied the manifest again would
// show within it.
func TestWatcher_appliesTheSameManifestOnce(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)
	require.Eventually(t, a.Ready, 2*time.Second, 10*time.Millisecond, "waiting for the read at start")
	swapped := a.Store.SwappedAt()

	f.write(1, spec("gateway.public", 10))

	assert.Never(t, func() bool { return !a.Store.SwappedAt().Equal(swapped) },
		500*time.Millisecond, 10*time.Millisecond, "the rule set was swapped again for the same manifest")
}

// A refused manifest is reported once, however often it is read again: the
// resync timer reads it every 200 ms here, over three resyncs, and the
// refusal counter grows by one.
// TestWatcher_reportsADifferentRefusedManifestAgain is the control.
func TestWatcher_reportsARefusedManifestOnce(t *testing.T) {
	f := newFixture(t)
	f.writeManifest(unsupported)
	a := newApplier()
	refused := metrics.SnapshotRebuilds.WithLabelValues("refused")
	before := testutil.ToFloat64(refused)

	startWatcher(t, f.dir, a)

	require.Eventually(t, func() bool { return testutil.ToFloat64(refused) == before+1 },
		2*time.Second, 10*time.Millisecond, "waiting for the refusal of the manifest to be counted")
	assert.Never(t, func() bool { return testutil.ToFloat64(refused) != before+1 },
		700*time.Millisecond, 10*time.Millisecond, "the refusal was reported again for the same manifest")
	assert.Equal(t, before+1, testutil.ToFloat64(refused), `ratelimit_snapshot_rebuilds_total{result="refused"}`)
}

// A refused manifest that differs from the one refused before it is reported
// in its turn: the refusal counter grows by one more, and the report carries
// the refusal of the new manifest, here of format version 98 after 99.
func TestWatcher_reportsADifferentRefusedManifestAgain(t *testing.T) {
	f := newFixture(t)
	f.writeManifest(unsupported)
	a := newApplier()
	refused := metrics.SnapshotRebuilds.WithLabelValues("refused")
	before := testutil.ToFloat64(refused)
	startWatcher(t, f.dir, a)
	waitForRefusal(t, a)

	f.writeManifest([]byte(`{"formatVersion": 98, "operatorVersion": "x", "domains": {}}`))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		refusal := a.Report().Refusal
		require.NotNil(c, refusal, "the reported refusal")
		assert.Equal(c, 98, refusal.FormatVersion, "the format version of the reported refusal")
		assert.Equal(c, before+2, testutil.ToFloat64(refused), `ratelimit_snapshot_rebuilds_total{result="refused"}`)
	}, 2*time.Second, 10*time.Millisecond, "waiting for the refusal of the manifest of format version 98")
}

// failedReads counts the lines a watcher logs about a manifest it could not
// read, one line per read.
type failedReads struct {
	lines atomic.Int64
}

func (r *failedReads) logger() logr.Logger {
	return funcr.New(func(_, args string) {
		if strings.Contains(args, "failed to read the configuration") {
			r.lines.Add(1)
		}
	}, funcr.Options{})
}

func waitForFailedReads(t *testing.T, reads *failedReads, want int64) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, want, reads.lines.Load(), "the failed reads logged")
	}, 3*time.Second, 10*time.Millisecond, "waiting for %d failed reads", want)
}

// The watcher reads once per burst of events. A manifest that cannot be read
// logs a line on every read, which makes the reads countable: one at start,
// and one for a burst of five files written at once. The resync timer is an
// hour away.
func TestWatcher_readsOncePerBurstOfEvents(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, os.Mkdir(filepath.Join(f.dir, contract.ManifestKey), 0o750))
	var reads failedReads
	runWatcher(t, &Watcher{Dir: f.dir, Applier: newApplier(), Log: reads.logger(),
		Resync: time.Hour, Settle: 300 * time.Millisecond})
	waitForFailedReads(t, &reads, 1)

	for i := range 5 {
		require.NoError(t, os.WriteFile(filepath.Join(f.dir, fmt.Sprintf("burst-%d", i)), nil, 0o600))
	}

	waitForFailedReads(t, &reads, 2)
	assert.Never(t, func() bool { return reads.lines.Load() > 2 }, time.Second, 10*time.Millisecond,
		"the burst of five writes was read more than once")
	assert.Equal(t, int64(2), reads.lines.Load(), "the failed reads logged")
}

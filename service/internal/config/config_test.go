package config

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/internal/store"
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

func spec(domain string, requests int32) v1alpha1.RateLimitPolicySpec {
	return v1alpha1.RateLimitPolicySpec{Domain: domain, Limits: []v1alpha1.LimitBlock{{
		Name: "api", Rules: []v1alpha1.Rule{{Name: "total", Rates: []v1alpha1.Rate{{Requests: requests, PeriodSeconds: 60}}}}}}}
}

// write puts the specs in the directory under a manifest at the given
// generation for every domain.
func (f *fixture) write(generation int64, specs ...v1alpha1.RateLimitPolicySpec) manifest.Manifest {
	f.t.Helper()
	m := manifest.Manifest{OperatorVersion: "t", Domains: map[string]manifest.Domain{}}
	for _, s := range specs {
		compressed, hash, err := manifest.EncodePayload(s)
		require.NoError(f.t, err)
		require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, manifest.PayloadKey(s.Domain)), compressed, 0o600))
		m.Domains[s.Domain] = manifest.Domain{Generation: generation, UID: "uid-" + s.Domain, Hash: hash}
	}
	raw, err := manifest.Encode(m)
	require.NoError(f.t, err)
	f.writeManifest(raw)
	return m
}

func (f *fixture) writeManifest(raw []byte) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, contract.ManifestKey), raw, 0o600))
}

func (f *fixture) remove(name string) {
	f.t.Helper()
	require.NoError(f.t, os.Remove(filepath.Join(f.dir, name)))
}

func newApplier() *Applier {
	return &Applier{Namespace: testNamespace, Store: store.New(), Counters: memory.New(), Log: logr.Discard()}
}

// The reader: what it applies, and every way it refuses.

func TestRead_theDirectoryAsTheKubeletWritesIt(t *testing.T) {
	f := newFixture(t)
	want := f.write(3, spec("gateway.public", 10), spec("gateway.private", 20))

	cfg, err := Read(f.dir)
	require.NoError(t, err)
	assert.Equal(t, want.Domains, cfg.Manifest.Domains)
	assert.Len(t, cfg.Specs, 2)
	assert.Equal(t, int32(10), cfg.Specs["gateway.public"].Limits[0].Rules[0].Rates[0].Requests)
}

func TestRead_anEmptyDirectoryIsAbsentAndAMissingOneToo(t *testing.T) {
	f := newFixture(t)
	_, err := Read(f.dir)
	assert.ErrorIs(t, err, ErrAbsent)
	_, err = Read(filepath.Join(f.dir, "not-mounted"))
	assert.ErrorIs(t, err, ErrAbsent, "before the volume is mounted the directory is not there at all")
}

func TestRead_refusals(t *testing.T) {
	sound := func(f *fixture) { f.write(1, spec("gateway.public", 10)) }
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
			damage: func(f *fixture) {
				other, _, err := manifest.EncodePayload(spec("gateway.public", 11))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, manifest.PayloadKey("gateway.public")), other, 0o600))
			},
			version: 1, reason: "does not match",
		},
		"a payload with a field the spec does not define": {
			damage: func(f *fixture) {
				// The hash is over the bytes as written, so it agrees; the
				// strict decode is what refuses.
				raw := map[string]any{"domain": "gateway.public", "limits": []any{}, "futureField": true}
				compressed, hash, err := manifest.EncodePayload(raw)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, manifest.PayloadKey("gateway.public")), compressed, 0o600))
				m := manifest.Manifest{OperatorVersion: "t", Domains: map[string]manifest.Domain{
					"gateway.public": {Generation: 1, UID: "u", Hash: hash}}}
				encoded, err := manifest.Encode(m)
				require.NoError(t, err)
				f.writeManifest(encoded)
			},
			version: 1, reason: "futureField",
		},
		"a payload that decompresses past the decoder's limit": {
			damage: func(f *fixture) {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				_, err := zw.Write(bytes.Repeat([]byte{'0'}, manifest.MaxPayloadSize+1))
				require.NoError(t, err)
				require.NoError(t, zw.Close())
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, manifest.PayloadKey("gateway.public")), buf.Bytes(), 0o600))
			},
			version: 1, reason: "decompresses past",
		},
		"a payload that belongs to another domain": {
			damage: func(f *fixture) {
				compressed, hash, err := manifest.EncodePayload(spec("gateway.other", 10))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, manifest.PayloadKey("gateway.public")), compressed, 0o600))
				m := manifest.Manifest{OperatorVersion: "t", Domains: map[string]manifest.Domain{
					"gateway.public": {Generation: 1, UID: "u", Hash: hash}}}
				encoded, err := manifest.Encode(m)
				require.NoError(t, err)
				f.writeManifest(encoded)
			},
			version: 1, reason: `for domain "gateway.other"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			sound(f)
			tc.damage(f)

			_, err := Read(f.dir)
			var refusal *Refusal
			require.ErrorAs(t, err, &refusal, "%v", err)
			assert.Equal(t, tc.version, refusal.FormatVersion)
			assert.Contains(t, refusal.Error(), tc.reason)
		})
	}
}

// The applier: the Ready gate and the report.

func TestApplier_isNotReadyUntilTheFirstApplyAndStaysReadyAfter(t *testing.T) {
	a := newApplier()
	assert.False(t, a.Ready())
	report := a.Report()
	assert.Empty(t, report.Domains)
	assert.Equal(t, manifest.SupportedVersions(), report.FormatVersions,
		"the versions are reported before anything is applied, so the operator can read them off a NotReady replica")

	// An explicitly empty manifest is a configuration.
	a.Apply(Configuration{Manifest: manifest.Manifest{FormatVersion: 1, Domains: map[string]manifest.Domain{}}})
	assert.True(t, a.Ready())
	assert.False(t, a.Store.HasDomain("gateway.public"), "every request is an unknown domain")

	// A refusal after the first apply keeps the replica Ready on its snapshot.
	a.Refuse(&Refusal{FormatVersion: 99, Err: errors.New("unsupported")})
	assert.True(t, a.Ready())
	require.NotNil(t, a.Report().Refusal)
	assert.Equal(t, 99, a.Report().Refusal.FormatVersion)
	assert.Equal(t, "unsupported", a.Report().Refusal.Reason)
}

func TestApplier_aRefusalBeforeTheFirstApplyIsReportedAndNotReady(t *testing.T) {
	a := newApplier()
	a.Refuse(&Refusal{FormatVersion: 2, Err: errors.New("no")})
	assert.False(t, a.Ready())
	assert.Equal(t, 2, a.Report().Refusal.FormatVersion)
	assert.Empty(t, a.Report().Domains)
}

func TestApplier_compilesEveryDomainAndReportsItsGeneration(t *testing.T) {
	f := newFixture(t)
	f.write(4, spec("gateway.public", 10), spec("gateway.private", 20))
	cfg, err := Read(f.dir)
	require.NoError(t, err)

	a := newApplier()
	a.Apply(cfg)
	assert.True(t, a.Store.HasDomain("gateway.public"))
	assert.True(t, a.Store.HasDomain("gateway.private"))
	report := a.Report()
	assert.Equal(t, int64(4), report.Domains["gateway.public"].Generation)
	assert.Equal(t, "uid-gateway.public", report.Domains["gateway.public"].UID)
	assert.Nil(t, report.Refusal)

	// The handler serves the same report.
	recorder := httptest.NewRecorder()
	a.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, contract.AppliedPath, nil))
	assert.Equal(t, http.StatusOK, recorder.Code)
	var served applied.Report
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &served))
	assert.Equal(t, report.Domains["gateway.private"].Generation, served.Domains["gateway.private"].Generation)
	assert.Equal(t, manifest.SupportedVersions(), served.FormatVersions)
}

func TestApplier_reusesTheEngineOfAnUnchangedDomain(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10), spec("gateway.private", 20))
	cfg, err := Read(f.dir)
	require.NoError(t, err)
	a := newApplier()
	a.Apply(cfg)
	before := a.Store.Engine("gateway.public")
	changed := a.Store.Engine("gateway.private")

	f.write(2, spec("gateway.public", 10), spec("gateway.private", 21))
	cfg, err = Read(f.dir)
	require.NoError(t, err)
	a.Apply(cfg)
	assert.Same(t, before, a.Store.Engine("gateway.public"), "same hash, same engine, warm cache kept")
	assert.NotSame(t, changed, a.Store.Engine("gateway.private"))
	assert.Equal(t, int64(2), a.Report().Domains["gateway.public"].Generation,
		"the generation moves with the manifest even when the payload did not")
}

// A spec the operator validated under rules this build does not share: two
// rules of one name, which the compiler refuses.
func badSpec(domain string) v1alpha1.RateLimitPolicySpec {
	return v1alpha1.RateLimitPolicySpec{Domain: domain, Limits: []v1alpha1.LimitBlock{{
		Name: "api", Rules: []v1alpha1.Rule{
			{Name: "total", Rates: []v1alpha1.Rate{{Requests: 1, PeriodSeconds: 60}}},
			{Name: "total", Rates: []v1alpha1.Rate{{Requests: 2, PeriodSeconds: 60}}},
		}}}}
}

func TestApplier_aSpecThatDoesNotCompileHereKeepsTheLastGoodEngine(t *testing.T) {
	f := newFixture(t)
	f.write(4, spec("gateway.public", 10), spec("gateway.private", 20))
	cfg, err := Read(f.dir)
	require.NoError(t, err)
	a := newApplier()
	a.Apply(cfg)
	lastGood := a.Store.Engine("gateway.public")

	f.write(5, badSpec("gateway.public"), spec("gateway.private", 21))
	cfg, err = Read(f.dir)
	require.NoError(t, err, "the payload decodes; it is the compiler that objects")
	a.Apply(cfg)

	assert.True(t, a.Ready())
	assert.Same(t, lastGood, a.Store.Engine("gateway.public"),
		"the rules enforced a moment ago stay enforced; the design's last-good, and this replica has it")
	assert.Equal(t, int64(4), a.Report().Domains["gateway.public"].Generation,
		"reported at the generation it enforces, so the operator sees this replica behind on the one domain")
	assert.Equal(t, int64(5), a.Report().Domains["gateway.private"].Generation, "the other domain moves on")
	assert.Nil(t, a.Report().Refusal, "not a refusal: the manifest was applied, one domain on last-good")

	// The good payload back under a new generation: applied, reported.
	f.write(6, spec("gateway.public", 10), spec("gateway.private", 21))
	cfg, err = Read(f.dir)
	require.NoError(t, err)
	a.Apply(cfg)
	assert.Same(t, lastGood, a.Store.Engine("gateway.public"), "same payload hash as generation 4")
	assert.Equal(t, int64(6), a.Report().Domains["gateway.public"].Generation)
}

func TestApplier_aSpecThatDoesNotCompileHereAndWasNeverAppliedClaimsTheDomainEmpty(t *testing.T) {
	f := newFixture(t)
	f.write(5, badSpec("gateway.public"), spec("gateway.private", 20))
	cfg, err := Read(f.dir)
	require.NoError(t, err)

	a := newApplier()
	a.Apply(cfg)
	assert.True(t, a.Ready())
	assert.True(t, a.Store.HasDomain("gateway.public"), "claimed, so the request is not an unknown domain")
	assert.Empty(t, a.Store.Load().Snapshot("gateway.public").Blocks, "and nothing to keep, so empty")
	assert.Equal(t, int64(0), a.Report().Domains["gateway.public"].Generation,
		"reported at zero: the operator sees this replica behind, not enforcing")
	assert.Equal(t, int64(5), a.Report().Domains["gateway.private"].Generation, "the other domain is untouched")
}

// The watcher: one apply per change of the manifest, through file events
// and through the resync timer.

func startWatcher(t *testing.T, dir string, a *Applier) {
	t.Helper()
	w := &Watcher{Dir: dir, Applier: a, Log: logr.Discard(), Resync: 200 * time.Millisecond, Settle: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

func TestWatcher_appliesWhatIsThereAndThenEachChange(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)

	require.Eventually(t, a.Ready, 2*time.Second, 10*time.Millisecond, "the first read is at start")
	assert.Equal(t, int64(1), a.Report().Domains["gateway.public"].Generation)

	f.write(2, spec("gateway.public", 11))
	require.Eventually(t, func() bool { return a.Report().Domains["gateway.public"].Generation == 2 },
		2*time.Second, 10*time.Millisecond)

	// A refusal is reported, the snapshot stays.
	f.writeManifest([]byte(`{"formatVersion": 99, "operatorVersion": "x", "domains": {}}`))
	require.Eventually(t, func() bool { return a.Report().Refusal != nil }, 2*time.Second, 10*time.Millisecond)
	assert.True(t, a.Store.HasDomain("gateway.public"))
	assert.Equal(t, int64(2), a.Report().Domains["gateway.public"].Generation)

	// The files vanish: still Ready, still generation 2.
	f.remove(contract.ManifestKey)
	time.Sleep(300 * time.Millisecond)
	assert.True(t, a.Ready())
	assert.Equal(t, int64(2), a.Report().Domains["gateway.public"].Generation)

	// The good manifest comes back, and the refusal goes.
	f.write(3, spec("gateway.public", 11))
	require.Eventually(t, func() bool {
		return a.Report().Refusal == nil && a.Report().Domains["gateway.public"].Generation == 3
	}, 2*time.Second, 10*time.Millisecond)
}

func TestWatcher_staysNotReadyWithoutAConfigurationAndWatchesADirectoryThatAppearsLater(t *testing.T) {
	// The volume mounted optional and empty, then written; and the directory
	// that is not there at all until it is.
	root := t.TempDir()
	dir := filepath.Join(root, "config")
	a := newApplier()
	startWatcher(t, dir, a)

	time.Sleep(300 * time.Millisecond)
	assert.False(t, a.Ready(), "no timeout turns a missing configuration into an empty one")

	require.NoError(t, os.Mkdir(dir, 0o750))
	f := &fixture{t: t, dir: dir}
	f.write(1, spec("gateway.public", 10))
	require.Eventually(t, a.Ready, 3*time.Second, 10*time.Millisecond, "the resync timer finds the directory and its contents")
}

func TestWatcher_appliesTheSameManifestOnce(t *testing.T) {
	f := newFixture(t)
	f.write(1, spec("gateway.public", 10))
	a := newApplier()
	startWatcher(t, f.dir, a)
	require.Eventually(t, a.Ready, 2*time.Second, 10*time.Millisecond)
	swapped := a.Store.SwappedAt()

	// The kubelet's periodic refresh rewrites unchanged files.
	f.write(1, spec("gateway.public", 10))
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, swapped, a.Store.SwappedAt(), "the same manifest is the same configuration; no swap")
}

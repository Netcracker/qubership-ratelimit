package manifest

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// update rewrites the goldens of the current format version: the manifest
// from the sample, and the field set of the spec. It is the one way a golden
// is written: when FormatVersion is incremented, run
// "go test ./api/manifest -update" once and commit the new files beside the
// previous version's, and delete the version before that, which the reader
// no longer promises. Running it without an increment is how the bump check
// is silenced, which is why the check names the flag only after it fails.
var update = flag.Bool("update", false, "write testdata/v<FormatVersion>.* from the sample and the spec")

// sample is the manifest every golden is written from. It does not change
// between versions: what a golden pins is the format, and a sample that moved
// with it would hide a moved format behind a moved sample.
func sample() Manifest {
	return Manifest{
		FormatVersion:   FormatVersion,
		OperatorVersion: "0.0.0-golden",
		Domains: map[string]Domain{
			"gateway.public": {
				Generation: 7,
				UID:        "1d8c9c4e-0b2a-4c1f-9e2b-7a6f5d4c3b2a",
				Hash:       "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
			},
			"gateway.private": {
				Generation: 3,
				UID:        "9f0e1d2c-3b4a-4596-8778-695a4b3c2d1e",
				Hash:       "sha256:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
			},
		},
	}
}

func golden(version int) string {
	return filepath.Join("testdata", fmt.Sprintf("v%d.json", version))
}

// fieldsGolden is the payload's golden: the JSON paths of every field the
// spec carries under this format version, one per line.
func fieldsGolden(version int) string {
	return filepath.Join("testdata", fmt.Sprintf("v%d.fields.txt", version))
}

// TestDecode_readsEverySupportedVersion is the skew guarantee: the service
// reads the current format and the one before it, so the golden of each has
// to decode with this reader. A golden that stops decoding is a reader that
// broke a version it promised to read.
func TestDecode_readsEverySupportedVersion(t *testing.T) {
	for _, version := range SupportedVersions() {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			data, err := os.ReadFile(golden(version))
			require.NoError(t, err, "no golden for a supported version; write it with -update when the version is introduced")

			m, err := Decode(data)
			require.NoError(t, err)
			assert.Equal(t, version, m.FormatVersion)
			assert.NotEmpty(t, m.Domains, "the golden sample carries domains")
		})
	}
}

// TestEncode_matchesTheGoldenOfTheCurrentVersion is the bump check. The
// writer's output for the sample has to equal the committed golden of
// FormatVersion byte for byte; a change of what the operator writes is a new
// version, with a golden of its own, and never a rewrite of an old one.
func TestEncode_matchesTheGoldenOfTheCurrentVersion(t *testing.T) {
	got, err := Encode(sample())
	require.NoError(t, err)

	path := golden(FormatVersion)
	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o644))
		t.Logf("wrote %s", path)
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err,
		"no golden for FormatVersion %d: a new version needs its golden written once with -update and committed",
		FormatVersion)
	require.Equal(t, string(want), string(got),
		"the writer's output changed without a version increment: increment FormatVersion, "+
			"then write the new golden with -update and keep the previous one")
}

// TestPayloadFields_matchTheGoldenOfTheCurrentVersion is the bump check for
// the payload. The manifest golden cannot see a field added to the spec, and
// a payload sample would not either when the field is optional and omitted;
// the field set can. An older service meeting a field it does not define
// refuses the payload as malformed under a version it believes it supports,
// which is the corruption-for-skew confusion the version exists to prevent.
// So a field added, removed, or renamed on RateLimitPolicySpec fails here
// until FormatVersion moves.
func TestPayloadFields_matchTheGoldenOfTheCurrentVersion(t *testing.T) {
	got := strings.Join(FieldPaths(reflect.TypeFor[v1alpha1.RateLimitPolicySpec]()), "\n") + "\n"

	path := fieldsGolden(FormatVersion)
	if *update {
		require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
		t.Logf("wrote %s", path)
		return
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err,
		"no field-set golden for FormatVersion %d: write it once with -update and commit it", FormatVersion)
	require.Equal(t, string(want), got,
		"the field set of RateLimitPolicySpec changed without a version increment: an older service would "+
			"refuse the payload as malformed. Increment FormatVersion, then write the new goldens with -update")
}

// TestFieldPaths_walksTheShapesTheSpecUses pins the walker on a type built
// to hold every shape the spec has: nested structs, slices of structs,
// slices of scalars, pointers, maps, an inlined struct, and a recursive type.
func TestFieldPaths_walksTheShapesTheSpecUses(t *testing.T) {
	type leaf struct {
		Name  string         `json:"name"`
		Count *int32         `json:"count,omitempty"`
		Skip  string         `json:"-"`
		Bare  string         // no tag: the Go name
		Tags  []string       `json:"tags,omitempty"`
		Extra map[string]int `json:"extra,omitempty"`
	}
	type inlined struct {
		Kind string `json:"kind"`
	}
	type node struct {
		inlined
		Leaf     leaf            `json:"leaf"`
		Leaves   []leaf          `json:"leaves"`
		ByName   map[string]leaf `json:"byName"`
		Next     *node           `json:"next,omitempty"`
		Anything any             `json:"anything"`

		// Types with a JSON form of their own: a struct of unexported fields
		// to a walk, one value in JSON. Each is one path, and one that goes
		// missing is a field whose addition the golden would not see.
		Timeout  metav1.Duration    `json:"timeout"`
		Timeouts []metav1.Duration  `json:"timeouts"`
		Size     *resource.Quantity `json:"size,omitempty"`
		When     metav1.Time        `json:"when"`
	}

	assert.Equal(t, []string{
		"anything<any>",
		"byName{}.Bare",
		"byName{}.count",
		"byName{}.extra{}",
		"byName{}.name",
		"byName{}.tags[]",
		"kind",
		"leaf.Bare",
		"leaf.count",
		"leaf.extra{}",
		"leaf.name",
		"leaf.tags[]",
		"leaves[].Bare",
		"leaves[].count",
		"leaves[].extra{}",
		"leaves[].name",
		"leaves[].tags[]",
		"next...",
		"size",
		"timeout",
		"timeouts[]",
		"when",
	}, FieldPaths(reflect.TypeFor[node]()))
}

// TestGoldens_areOnlyTheSupportedVersions keeps testdata honest in the other
// direction: a golden nobody reads any more is a version the service no
// longer promises, and leaving it would make the decoder test look wider
// than the reader is.
func TestGoldens_areOnlyTheSupportedVersions(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	require.NoError(t, err)
	present := make([]string, 0, len(entries))
	for _, e := range entries {
		present = append(present, e.Name())
	}
	expected := make([]string, 0, 2*len(SupportedVersions()))
	for _, v := range SupportedVersions() {
		expected = append(expected, fmt.Sprintf("v%d.json", v), fmt.Sprintf("v%d.fields.txt", v))
	}
	assert.ElementsMatch(t, expected, present,
		"testdata holds the two goldens of every supported version and nothing else")
}

func TestDecode_refusesAnUnknownField(t *testing.T) {
	data, err := Encode(sample())
	require.NoError(t, err)
	skewed := strings.Replace(string(data), `"operatorVersion"`, `"operatorVersion": "x", "burstProfile"`, 1)

	_, err = Decode([]byte(skewed))
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "burstProfile",
		"the refusal names the field; it is the only clue a reader of /debug/applied gets")
}

func TestDecode_refusesAnUnknownDomainField(t *testing.T) {
	data, err := Encode(sample())
	require.NoError(t, err)
	skewed := strings.Replace(string(data), `"generation": 7`, `"generation": 7, "priority": 1`, 1)

	_, err = Decode([]byte(skewed))
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "priority")
}

func TestDecode_refusesAnUnknownVersion(t *testing.T) {
	for _, version := range []int{0, FormatVersion + 1, FormatVersion + 7} {
		data, err := Encode(sample())
		require.NoError(t, err)
		skewed := strings.Replace(string(data),
			fmt.Sprintf(`"formatVersion": %d`, FormatVersion),
			fmt.Sprintf(`"formatVersion": %d`, version), 1)

		_, err = Decode([]byte(skewed))
		require.ErrorIs(t, err, ErrUnsupportedFormat, "version %d", version)
		assert.Contains(t, err.Error(), fmt.Sprint(version), "the refusal names the version it met")
	}
}

// TestDecode_reportsANewerFormatAsUnsupportedNotMalformed is what the skew
// policy rests on. From the older side, every version increment looks like a
// manifest with fields this reader does not define; if the strict decode ran
// first it would report corruption, and the operator would turn that into the
// wrong status reason. The version has to be judged before any field is.
func TestDecode_reportsANewerFormatAsUnsupportedNotMalformed(t *testing.T) {
	data, err := Encode(sample())
	require.NoError(t, err)
	newer := string(data)
	newer = strings.Replace(newer, fmt.Sprintf(`"formatVersion": %d`, FormatVersion),
		fmt.Sprintf(`"formatVersion": %d, "checksum": "abc"`, FormatVersion+1), 1)
	newer = strings.Replace(newer, `"generation": 7`, `"generation": 7, "priority": 1`, 1)

	_, err = Decode([]byte(newer))
	require.ErrorIs(t, err, ErrUnsupportedFormat,
		"a newer format with fields this reader does not define is unsupported, not malformed: %v", err)
	assert.NotErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), fmt.Sprint(FormatVersion+1))
}

func TestDecode_refusesAManifestWithoutAVersion(t *testing.T) {
	_, err := Decode([]byte(`{"operatorVersion": "x", "domains": {}}`))
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "formatVersion")
}

func TestDecode_refusesAManifestWithoutDomains(t *testing.T) {
	_, err := Decode([]byte(`{"formatVersion": 1, "operatorVersion": "x"}`))
	require.ErrorIs(t, err, ErrMalformed)
}

func TestDecode_readsAnEmptyNamespace(t *testing.T) {
	// No policy is a configuration, not an absence: a replica applying this
	// is Ready and passes every request as an unknown domain.
	data, err := Encode(Manifest{FormatVersion: FormatVersion, OperatorVersion: "x"})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"domains": {}`, "no domains encodes as an empty object, never null")

	m, err := Decode(data)
	require.NoError(t, err)
	assert.NotNil(t, m.Domains)
	assert.Empty(t, m.Domains)
}

func TestEncode_stampsTheVersionItProduces(t *testing.T) {
	// The writer produces one version; whatever the caller put in the field
	// is overwritten, so there is no way to write a manifest that claims a
	// version it is not.
	m := sample()
	m.FormatVersion = FormatVersion + 7
	data, err := Encode(m)
	require.NoError(t, err)
	decoded, err := Decode(data)
	require.NoError(t, err)
	assert.Equal(t, FormatVersion, decoded.FormatVersion)
}

func TestEncode_isDeterministic(t *testing.T) {
	// The bump check compares bytes, so the writer has to produce the same
	// bytes for the same value: map iteration order must not leak into it.
	first, err := Encode(sample())
	require.NoError(t, err)
	for range 20 {
		again, err := Encode(sample())
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}
}

// The payloads.

type payload struct {
	Domain string   `json:"domain"`
	Rules  []string `json:"rules"`
}

func TestPayload_roundTripsAndHashesTheUncompressedJSON(t *testing.T) {
	in := payload{Domain: "gateway.public", Rules: []string{"a", "b"}}
	compressed, hash, err := EncodePayload(in)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "sha256:"))

	var out payload
	got, err := DecodePayload(compressed, &out)
	require.NoError(t, err)
	assert.Equal(t, in, out)
	assert.Equal(t, hash, got, "the hash the decoder computes is the one the encoder wrote to the manifest")
}

func TestPayload_refusesAnUnknownField(t *testing.T) {
	compressed, _, err := EncodePayload(map[string]any{"domain": "d", "rules": []string{}, "burst": 3})
	require.NoError(t, err)

	var out payload
	_, err = DecodePayload(compressed, &out)
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "burst")
}

func TestPayload_refusesWhatIsNotGzip(t *testing.T) {
	var out payload
	_, err := DecodePayload([]byte(`{"domain":"d"}`), &out)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestPayloadKey(t *testing.T) {
	assert.Equal(t, "gateway.public.json.gz", PayloadKey("gateway.public"))
}

// TestPayload_carriesTheResourceSpec pins what the payload is: the validated
// spec in the resource's own format, not a compiled snapshot. The strict
// decode has to accept every field the spec defines and refuse one it does
// not, which is the skew case of a spec that grew on the operator's side.
func TestPayload_carriesTheResourceSpec(t *testing.T) {
	spec := v1alpha1.RateLimitPolicySpec{
		Domain: "gateway.public",
		Limits: []v1alpha1.LimitBlock{{
			Name: "probe",
			Rules: []v1alpha1.Rule{{
				Name:     "per-path",
				Counters: []string{"path"},
				Rates: []v1alpha1.Rate{{
					Requests: 2, PeriodSeconds: 3600, Algorithm: v1alpha1.AlgorithmGCRA}},
			}},
		}},
	}
	compressed, hash, err := EncodePayload(spec)
	require.NoError(t, err)

	var out v1alpha1.RateLimitPolicySpec
	got, err := DecodePayload(compressed, &out)
	require.NoError(t, err)
	assert.Equal(t, spec, out)
	assert.Equal(t, hash, got)

	// A field a newer spec defines and this one does not.
	raw, err := json.Marshal(spec)
	require.NoError(t, err)
	grown := strings.Replace(string(raw), `"domain":"gateway.public"`, `"domain":"gateway.public","tier":"gold"`, 1)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write([]byte(grown))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	_, err = DecodePayload(buf.Bytes(), &out)
	require.ErrorIs(t, err, ErrMalformed)
	assert.Contains(t, err.Error(), "tier")
}

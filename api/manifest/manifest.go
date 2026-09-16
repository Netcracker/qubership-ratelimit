// Package manifest is the format of the configuration the operator writes and
// the service reads: the manifest under the ConfigMap's data, and one
// compressed payload per domain under its binaryData.
//
// The format carries an integer version, and the version is the whole skew
// policy between an operator and a service of different releases. The
// operator writes the current version; the service reads the current one and
// the one before it, so an upgrade installs the service first and a rollback
// reverses the order. Any change of what the operator writes, a field added
// to the spec included, increments the version. The decoder is strict on both
// counts, an unknown field and an unknown version, because a manifest read in
// part would be a policy enforced in part, which the design forbids.
//
// The goldens under testdata pin the format: one manifest per version,
// written by Encode when the version was introduced. A test decodes every
// supported one, and a test re-encodes the sample of the current version and
// fails when the bytes moved without a version increment.
package manifest

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"

	kjson "sigs.k8s.io/json"
)

// FormatVersion is the version the operator writes. Increment it with any
// change of what Encode or EncodePayload produce, and write the golden of the
// new version (see manifest_test.go); the decoder then reads this version and
// the previous one.
const FormatVersion = 1

// SupportedVersions lists the format versions Decode accepts: the current one
// and the one before it, when there is one.
func SupportedVersions() []int {
	if FormatVersion > 1 {
		return []int{FormatVersion - 1, FormatVersion}
	}
	return []int{FormatVersion}
}

// Manifest is what the operator writes under the manifest key.
type Manifest struct {
	// FormatVersion is the version of this format. The decoder refuses a
	// manifest whose version it does not read.
	FormatVersion int `json:"formatVersion"`

	// OperatorVersion is the release of the operator that wrote the
	// manifest. Informational: the service decides by FormatVersion alone,
	// and this is for a reader of the ConfigMap and for /debug/applied.
	OperatorVersion string `json:"operatorVersion"`

	// Domains describes the payload of every domain of the namespace, keyed
	// by domain. A namespace without a policy has an empty map, which is a
	// configuration: a replica applying it is Ready and passes every request
	// as an unknown domain.
	Domains map[string]Domain `json:"domains"`
}

// Domain is the manifest's entry for one domain: which generation of its
// policy the payload holds, of which object, and what the payload hashes to.
type Domain struct {
	// Generation is the generation of the RateLimitPolicy the payload was
	// taken from. It is the active generation: when the latest one does not
	// compile, the last-good one is here, and the policy status shows the
	// divergence.
	Generation int64 `json:"generation"`

	// UID is the object's UID, which is what makes a generation comparable
	// across a delete and a recreate under the same name.
	UID string `json:"uid"`

	// Hash is the content hash of the payload before compression, as Hash
	// computes it. Gzip output is not stable across implementations, so the
	// hash covers what was compressed rather than the compressed bytes.
	Hash string `json:"hash"`
}

// ErrUnsupportedFormat marks a manifest whose formatVersion this decoder does
// not read. The service keeps its snapshot and reports the refusal.
var ErrUnsupportedFormat = errors.New("manifest: unsupported format version")

// ErrMalformed marks a manifest or a payload the decoder cannot read whole:
// invalid JSON, a field this format does not define, a bad gzip stream.
var ErrMalformed = errors.New("manifest: malformed")

// PayloadKey is the binaryData key of a domain's payload.
func PayloadKey(domain string) string {
	return domain + ".json.gz"
}

// Encode renders a manifest the way the operator writes it. The output is
// deterministic - domains are emitted in sorted order and the layout is
// fixed - which is what lets a golden pin the format.
func Encode(m Manifest) ([]byte, error) {
	if m.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("manifest: encode version %d, this writer produces %d",
			m.FormatVersion, FormatVersion)
	}
	// A nil map encodes as null, an empty one as {}; the manifest says "no
	// domains" with the latter, and a reader should never meet the former.
	if m.Domains == nil {
		m.Domains = map[string]Domain{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("manifest: encode: %w", err)
	}
	return buf.Bytes(), nil
}

// Decode reads a manifest strictly. A field this format does not define, or a
// version outside SupportedVersions, is a refusal with a reason: the caller
// keeps whatever it applied last.
func Decode(data []byte) (Manifest, error) {
	var m Manifest
	if err := unmarshalStrict(data, &m); err != nil {
		return Manifest{}, err
	}
	if !supported(m.FormatVersion) {
		return Manifest{}, fmt.Errorf("%w: %d (this reader accepts %v)",
			ErrUnsupportedFormat, m.FormatVersion, SupportedVersions())
	}
	if m.Domains == nil {
		return Manifest{}, fmt.Errorf("%w: domains is absent", ErrMalformed)
	}
	return m, nil
}

// EncodePayload renders a domain's payload: the value as JSON, gzip
// compressed. It returns the compressed bytes and the hash Domain.Hash
// carries, computed over the JSON before compression.
func EncodePayload(v any) (compressed []byte, hash string, err error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", fmt.Errorf("manifest: encode payload: %w", err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, "", fmt.Errorf("manifest: compress payload: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("manifest: compress payload: %w", err)
	}
	return buf.Bytes(), Hash(raw), nil
}

// DecodePayload reads a domain's payload into v, strictly: a field the value's
// type does not define is a refusal. The hash of the decompressed bytes is
// returned so the caller can check it against the manifest.
func DecodePayload(compressed []byte, v any) (hash string, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return "", fmt.Errorf("%w: payload is not gzip: %v", ErrMalformed, err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return "", fmt.Errorf("%w: payload does not decompress: %v", ErrMalformed, err)
	}
	if err := unmarshalStrict(raw, v); err != nil {
		return "", err
	}
	return Hash(raw), nil
}

// Hash is the content hash the manifest carries for a payload: SHA-256 of
// the uncompressed JSON, prefixed with the algorithm so a later change of it
// is visible in the value.
func Hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// unmarshalStrict decodes JSON and refuses unknown fields, naming them. Every
// strict error is reported, sorted, so the reason a manifest was refused is
// complete on the first read.
func unmarshalStrict(data []byte, v any) error {
	strict, err := kjson.UnmarshalStrict(data, v)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(strict) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(strict))
	for _, e := range strict {
		reasons = append(reasons, e.Error())
	}
	sort.Strings(reasons)
	return fmt.Errorf("%w: %v", ErrMalformed, reasons)
}

func supported(version int) bool {
	return slices.Contains(SupportedVersions(), version)
}

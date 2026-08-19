package policy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// MaxBundleSize bounds one encoded bundle. A ConfigMap holds about a mebibyte,
// and the encoded state has to leave room for the rest of the object.
const MaxBundleSize = 900 * 1024

// Bundle is the last-good state of one domain: the specs that are being
// enforced, as opposed to the latest ones in etcd.
//
// It is persisted because etcd holds only the latest generation, which may be the
// one that was rejected. Without the bundle a restart would forget what is
// running and fall back to "nothing", turning a rejected edit into an outage at
// the next rollout.
type Bundle struct {
	// Mapping is the active mapping spec of the domain, absent when the domain
	// runs on the built-in keys.
	Mapping *MappingState `json:"mapping,omitempty"`

	// Policies are the active policy specs, in a stable order so that the
	// encoding of an unchanged state does not change.
	Policies []PolicyState `json:"policies,omitempty"`
}

// MappingState is the active generation of the mapping of a domain.
type MappingState struct {
	// UID guards against a recreated object of the same name. A different UID is
	// a different object, and reviving the state of its namesake would apply a
	// spec nobody wrote.
	UID string `json:"uid"`

	// GoodGeneration is the generation GoodSpec came from.
	GoodGeneration int64 `json:"goodGeneration"`

	// GoodSpec is the spec being enforced.
	GoodSpec v1alpha1.RateLimitMappingSpec `json:"goodSpec"`
}

// PolicyState is the active generation of one policy.
type PolicyState struct {
	// Name identifies the policy within its namespace.
	Name string `json:"name"`

	// UID guards against a recreated object of the same name.
	UID string `json:"uid"`

	// GoodGeneration is the generation GoodSpec came from.
	GoodGeneration int64 `json:"goodGeneration"`

	// GoodSpec is the spec being enforced.
	GoodSpec v1alpha1.RateLimitPolicySpec `json:"goodSpec"`
}

// policy returns the last-good state of a policy, or nil when the object has
// none. A UID mismatch counts as none: the object was deleted and recreated, so
// its namesake's state is not its own.
func (b Bundle) policy(name, uid string) *PolicyState {
	for i := range b.Policies {
		if b.Policies[i].Name == name {
			if b.Policies[i].UID != uid {
				return nil
			}
			return &b.Policies[i]
		}
	}
	return nil
}

// mapping returns the last-good state of the mapping, or nil.
func (b Bundle) mapping(uid string) *MappingState {
	if b.Mapping == nil || b.Mapping.UID != uid {
		return nil
	}
	return b.Mapping
}

// EncodeBundle renders a bundle for persistence. It is gzipped because a domain
// with thousands of rules holds far more spec than a ConfigMap would take
// verbatim.
func EncodeBundle(bundle Bundle) ([]byte, error) {
	plain, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("encode domain state: %w", err)
	}

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(plain); err != nil {
		return nil, fmt.Errorf("compress domain state: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compress domain state: %w", err)
	}

	if compressed.Len() > MaxBundleSize {
		return nil, fmt.Errorf(
			"domain state is %d bytes, over the %d byte limit: the objects of this domain cannot keep a last-good spec across a restart",
			compressed.Len(), MaxBundleSize)
	}
	return compressed.Bytes(), nil
}

// DecodeBundle reads a persisted bundle.
func DecodeBundle(data []byte) (Bundle, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Bundle{}, fmt.Errorf("read domain state: %w", err)
	}
	defer func() { _ = reader.Close() }()

	plain, err := io.ReadAll(io.LimitReader(reader, 16*MaxBundleSize))
	if err != nil {
		return Bundle{}, fmt.Errorf("read domain state: %w", err)
	}

	var bundle Bundle
	if err := json.Unmarshal(plain, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode domain state: %w", err)
	}
	return bundle, nil
}

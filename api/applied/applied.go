// Package applied is the shape of what a service replica publishes on
// contract.AppliedPath and what the operator reads from every ready replica:
// the generation it enforces per domain, the manifest format versions it
// reads, and a refusal of the manifest it was last given, with its reason.
//
// It lives under api/ because the two sides land in different binaries after
// the split, and the operator turns a refusal into a status reason of its
// own (ReplicaFormatUnsupported), so the field has to mean the same thing on
// both ends.
package applied

import "time"

// Report is the body of a GET on contract.AppliedPath.
type Report struct {
	// Domains is what this replica enforces, keyed by domain. A domain that
	// is absent is one this replica has no configuration for.
	Domains map[string]Domain `json:"domains"`

	// FormatVersions lists the manifest format versions this replica reads.
	// Empty for a replica that reads no manifest, which is the one-binary
	// packaging.
	FormatVersions []int `json:"formatVersions,omitempty"`

	// Refusal is set while the replica keeps its snapshot because the
	// manifest it was last given could not be read. It stays until a
	// manifest is applied again.
	Refusal *Refusal `json:"refusal,omitempty"`
}

// Domain is one replica's answer for one domain: the generation it enforces,
// of which object, and since when.
type Domain struct {
	Generation int64     `json:"generation"`
	UID        string    `json:"uid"`
	AppliedAt  time.Time `json:"appliedAt"`
}

// Refusal says why the last manifest was not applied. FormatVersion is the
// version the manifest declared, zero when the manifest could not be read
// far enough to say; Reason is the decoder's error, for a human.
type Refusal struct {
	FormatVersion int    `json:"formatVersion,omitempty"`
	Reason        string `json:"reason"`
}

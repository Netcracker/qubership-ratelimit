// Package config is the service's side of the ConfigMap: the mounted
// directory read whole and decoded strictly, the domains compiled with the
// engine and swapped into the rule store atomically, and the report of what
// this replica enforces for the operator's probe.
//
// The reader is deliberately all or nothing. A manifest is applied when every
// payload it names decodes, hashes as it says, and compiles here; anything
// less is a refusal, the snapshot in memory stays, and the refusal is
// reported. Enforcing the domains that did decode would enforce a namespace
// in part, which the design forbids for the same reason it forbids enforcing
// a policy in part.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/manifest"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Configuration is one reading of the mounted directory: the manifest and
// the spec of every domain it names.
type Configuration struct {
	Manifest manifest.Manifest

	// Specs is keyed by domain; every domain of the manifest has one.
	Specs map[string]v1alpha1.RateLimitPolicySpec

	// Raw is the manifest as read, the identity of a reading: the watcher
	// applies a reading whose bytes differ from the last one's, and the
	// kubelet writes the whole directory at once, so a changed payload comes
	// with a changed manifest.
	Raw []byte
}

// ErrAbsent is a directory without a manifest: the ConfigMap does not exist
// yet, or the volume is mounted optional and empty. It is not a refusal; a
// replica that has never applied anything stays NotReady on it, and one that
// has keeps what it applied.
var ErrAbsent = errors.New("no manifest in the mounted directory")

// Refusal is a reading this replica will not apply, with the format version
// the manifest declared when it could be read that far. It is what the
// replica reports on the applied endpoint until a manifest is applied again.
type Refusal struct {
	FormatVersion int
	Err           error

	// raw is the manifest the refusal is about, so the watcher reports one
	// refusal per manifest rather than one per read.
	raw []byte
}

func (r *Refusal) Error() string { return "configuration refused: " + r.Err.Error() }
func (r *Refusal) Unwrap() error { return r.Err }

// Read decodes the mounted directory. It returns ErrAbsent for a directory
// without a manifest, a *Refusal for one this replica cannot apply, and any
// other error for a read that failed on the way.
func Read(dir string) (Configuration, error) {
	raw, err := os.ReadFile(filepath.Join(dir, contract.ManifestKey))
	if errors.Is(err, fs.ErrNotExist) {
		return Configuration{}, ErrAbsent
	}
	if err != nil {
		return Configuration{}, fmt.Errorf("read the manifest: %w", err)
	}

	m, err := manifest.Decode(raw)
	if err != nil {
		return Configuration{}, &Refusal{FormatVersion: declaredVersion(raw), Err: err, raw: raw}
	}
	refuse := func(domain string, err error) (Configuration, error) {
		return Configuration{}, &Refusal{FormatVersion: m.FormatVersion,
			Err: fmt.Errorf("domain %s: %w", domain, err), raw: raw}
	}

	cfg := Configuration{Manifest: m, Specs: make(map[string]v1alpha1.RateLimitPolicySpec, len(m.Domains)), Raw: raw}
	for _, domain := range sortedDomains(m) {
		entry := m.Domains[domain]
		compressed, err := os.ReadFile(filepath.Join(dir, manifest.PayloadKey(domain)))
		if err != nil {
			return refuse(domain, fmt.Errorf("read the payload: %w", err))
		}
		var spec v1alpha1.RateLimitPolicySpec
		hash, err := manifest.DecodePayload(compressed, &spec)
		if err != nil {
			return refuse(domain, err)
		}
		if hash != entry.Hash {
			return refuse(domain, fmt.Errorf("payload hash %s does not match the manifest's %s", hash, entry.Hash))
		}
		if spec.Domain != domain {
			return refuse(domain, fmt.Errorf("the payload is for domain %q", spec.Domain))
		}
		cfg.Specs[domain] = spec
	}
	return cfg, nil
}

// declaredVersion reads the format version alone, leniently, for the
// refusal report; zero when the manifest cannot be read that far.
func declaredVersion(raw []byte) int {
	var header struct {
		FormatVersion int `json:"formatVersion"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return 0
	}
	return header.FormatVersion
}

func sortedDomains(m manifest.Manifest) []string {
	domains := make([]string, 0, len(m.Domains))
	for domain := range m.Domains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

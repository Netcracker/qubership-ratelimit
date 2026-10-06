package management

import (
	"fmt"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// unnormalized refuses an identity value the domain's normalization would
// change. Traffic counts a key under its normalized value, whichever form
// carried it: the built-in client is the sub claim in lower case, and a
// mapping may declare Lowercase. A value that differs from its normalized form
// names no counter any request writes and no identity any rule sees, so
// listing, resetting, or simulating it would answer about nobody, silently.
// The refusal names the form that does address the identity. A key in
// captured is skipped: a path capture counts the segment as sent, so in the
// blocks that capture the key any value can be a counter's. field turns a key
// name into the request field it came from.
func unnormalized(snapshot *compile.Snapshot, values map[string][]string, captured map[string]bool,
	field func(key string) string) *apiError {
	for _, extraction := range snapshot.Extraction {
		if extraction.Normalization != model.NormalizeLowercase || captured[extraction.Key] {
			continue
		}
		for _, value := range values[extraction.Key] {
			if lower := strings.ToLower(value); lower != value {
				return invalid(fmt.Sprintf("the %s value %q addresses no counter and no identity a request carries: "+
					"the domain lowercases %s, so use %q", extraction.Key, logSafe(value), extraction.Key,
					logSafe(lower)), field(extraction.Key))
			}
		}
	}
	return nil
}

// capturedKeys returns the keys a path capture sets in the blocks the rule ids
// address: a whole block/rule id or the block heading one. No rule ids
// address every block, so a key any block captures is in the set.
func capturedKeys(snapshot *compile.Snapshot, ruleIDs []string) map[string]bool {
	addressed := make(map[string]bool, len(ruleIDs))
	for _, id := range ruleIDs {
		block, _, _ := strings.Cut(id, "/")
		addressed[block] = true
	}
	out := map[string]bool{}
	for _, block := range snapshot.Blocks {
		if len(addressed) > 0 && !addressed[block.Name] {
			continue
		}
		for _, key := range block.Captures {
			out[key] = true
		}
	}
	return out
}

// axisField names the query parameter an axis value came from.
func axisField(key string) string { return axisPrefix + key }

// singleValues turns one value per key into the lists unnormalized reads.
func singleValues(axes map[string]string) map[string][]string {
	out := make(map[string][]string, len(axes))
	for key, value := range axes {
		out[key] = []string{value}
	}
	return out
}

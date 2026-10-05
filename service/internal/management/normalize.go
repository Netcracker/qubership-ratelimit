package management

import (
	"fmt"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// unnormalized refuses an identity value the domain's normalization would
// change. Traffic counts a key under its normalized value: the built-in client
// is the sub claim in lower case, and a mapping may declare Lowercase. A value
// that differs from its normalized form names no counter any request writes
// and no identity any rule sees, so listing, resetting, or simulating it would
// answer about nobody, silently. The refusal names the form that does address
// the identity. field turns a key name into the request field it came from.
func unnormalized(snapshot *compile.Snapshot, values map[string][]string, field func(key string) string) *apiError {
	for _, extraction := range snapshot.Extraction {
		if extraction.Normalization != model.NormalizeLowercase {
			continue
		}
		for _, value := range values[extraction.Key] {
			if lower := strings.ToLower(value); lower != value {
				return invalid(fmt.Sprintf("the %s value %q addresses no counter: the domain lowercases %s, "+
					"so use %q", extraction.Key, logSafe(value), extraction.Key, logSafe(lower)),
					field(extraction.Key))
			}
		}
	}
	return nil
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

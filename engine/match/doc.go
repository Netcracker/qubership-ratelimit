// Package match turns one request into the counter buckets it must fit into.
//
// Blocks combine additively: a request caught by several must satisfy each of
// them. Within a block the mode decides — every matching rule applies, or only
// the first one does. Each matching rule contributes one bucket per window.
//
// A rule whose counting axis is absent from the request does not match at all,
// because there is nothing to key its bucket with. That is the mechanism by
// which a per-client rule skips anonymous traffic without anyone writing an
// exception for it.
package match

// Package management serves the control interface of the rate limit service:
// read what is enforced, inspect and reset live counters, and simulate a
// request.
//
// It listens on its own address, separate from the RLS gRPC endpoint, and the
// chart never routes a gateway to it. That separation is the point rather than
// a detail of the layout: these endpoints lift limits, so reaching them from
// the data path would let the traffic being limited turn its own limits off.
//
// # What it does and does not mutate
//
// Only runtime state: counters. Configuration lives in custom resources and
// travels the GitOps path; there are no write endpoints for limits, rules, or
// mappings, and there will not be. Reading never spends anyone's budget either:
// every read goes through the engine's Peek facade, which judges at a cost of
// one and charges nothing.
//
// # Blast radius
//
// The addressed reset takes one full policy/block/rule id and one value for
// every axis the rule declares. With the identity fully named its keys are
// computed from the snapshot rather than scanned, so the radius is bounded by
// construction. Anything wider is a sweep, and a sweep belongs to the
// counter-resets action with its preview and its work budget. A partial axis
// selection is refused, never silently widened.
//
// # Security
//
// Authentication happens at the perimeter: the gateway's auth extension
// validates the bearer token, and the mesh is required to keep this service's
// ingress to the gateway. Authorization happens here, by path and verb, over an
// identity read from exactly one place, the bearer token, because a header the
// service trusts is a header an attacker forges. Every mutation leaves an
// audit record naming who made it, which key they used, and what came of it.
//
// # Values
//
// Axis values appear in responses: an operator resetting one client's counter
// has to see which client. Tokens never do: the raw token descriptor a
// simulation accepts is write-only, and nothing echoes, logs, or quotes it.
package management

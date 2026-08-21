// Package management serves the operator's control interface: the endpoints
// that reset counters, report what is being enforced, and turn the decision
// audit stream on.
//
// It listens on its own address, separate from the RLS gRPC endpoint, and the
// chart never routes a gateway to it. That separation is the point rather than
// a detail of the layout: the endpoints below lift limits, so reaching them
// from the data path would let the traffic being limited turn its own limits
// off. Every request is authenticated against the Kubernetes API server and
// authorized by RBAC, and every mutation leaves an audit record naming who
// made it.
//
// # Shape
//
// The responses are built for a browser client as much as for curl: stable
// machine-readable codes on errors, one envelope for every list, cursor
// pagination on the one collection that can grow without bound, and rule
// metadata complete enough for a UI to render a reset form without knowing the
// key schema. Values that identify a client — claim values, token contents —
// are the exception: axis values appear because an operator resetting one
// client's counter has to see which client, but no endpoint reports a token.
//
// # Replica scope
//
// The operator runs several replicas and each serves this API, so an answer
// describes the process that served it unless the counter store is shared.
// With Redis every counter operation is domain-wide and a reset takes effect
// for every replica at once; with the in-process store it reaches only the
// replica that handled the call, and the reset response says so in its scope
// field rather than leaving the caller to guess.
package management

// Package identity turns a token into descriptor keys.
//
// The payload is decoded, never verified: the gateway has already checked the
// signature, and repeating that work in the request path would buy nothing. A
// missing or undecodable token is not an error — the identity keys are simply
// absent, rules that need them do not match, and the rest still apply.
//
// Extraction lives in the engine rather than in the gateway because array-valued
// claims, roles above all, do not survive the trip through a header.
//
// The raw token never leaves this package: not into logs, metric labels, audit
// records, or counter keys.
package identity

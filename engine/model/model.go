package model

import "time"

// Built-in descriptor keys. They exist in every domain with no mapping at
// all; a mapping may override KeyClient and must not declare the others.
const (
	// KeyPath is the request path with the query string already stripped.
	KeyPath = "path"

	// KeyMethod is the HTTP method.
	KeyMethod = "method"

	// KeyClient is the built-in identity: the JWT sub claim, lowercased.
	KeyClient = "client"

	// KeyToken names the raw-token descriptor entry the gateways send. It is
	// never a rule key and never leaves identity extraction.
	KeyToken = "token"
)

// List bounds, mirrored by the CRD schema (where they also feed the CEL cost
// estimator). Compilation re-checks them: a library cannot assume its caller
// validated anything.
const (
	MaxBlocksPerPolicy   = 64
	MaxRulesPerBlock     = 128
	MaxRoutesPerBlock    = 16
	MaxMethodsPerRoute   = 9
	MaxConditionsPerRule = 8
	MaxCountersPerRule   = 4
	MaxRatesPerRule      = 4
	MaxReplacesPerRule   = 16
	MaxGroups            = 64
	MaxClientsPerGroup   = 1024
	MaxMappings          = 32
	MaxFallbacks         = 3
)

// MaxDecisionBucketsPerPolicy caps the buckets one request can collect from
// one policy in the worst case: All sums every counting rule, FirstMatch
// settles on its widest counting rule after every shadow rule. The schema
// cannot check this cross-field product, so compilation enforces it — every
// bucket is one read and possibly one write inside a single atomic store
// script, and an unbounded worst case would let one object monopolize the
// domain's shard.
const MaxDecisionBucketsPerPolicy = 64

// Domain-wide reference bounds. When a set of policies exceeds them, no
// single policy is at fault, so compilation excludes nobody and reports an
// informational domain-level problem instead; the operator's admission gate
// holds live domains inside these bounds, and the engine's runtime backstop
// refuses decisions over MaxDomainDecisionBuckets.
const (
	// MaxDomainDecisionBuckets is the worst-case bucket count one request
	// may collect across every policy of a domain.
	MaxDomainDecisionBuckets = 128

	// MaxDomainBlocks bounds the linear target scan.
	MaxDomainBlocks = 256
)

// PathType selects how a route's path value matches.
type PathType string

const (
	PathExact    PathType = "Exact"
	PathPrefix   PathType = "Prefix"
	PathTemplate PathType = "Template"
)

// Mode governs how the rules of one block combine.
type Mode string

const (
	// ModeAll applies every matching rule; replaces is available for
	// targeted overrides.
	ModeAll Mode = "All"

	// ModeFirstMatch applies the first matching rule in list order — the
	// one place in the whole model where ordering is semantics.
	ModeFirstMatch Mode = "FirstMatch"
)

// Operator is a set predicate: a key's value is a set (scalar — singleton,
// array — its elements, absent — empty).
type Operator string

const (
	OperatorEquals    Operator = "Equals"    // equality to a singleton; rejected for array keys
	OperatorIn        Operator = "In"        // non-empty intersection with Values
	OperatorInGroup   Operator = "InGroup"   // non-empty intersection with a named group
	OperatorContains  Operator = "Contains"  // element membership, never a substring
	OperatorExists    Operator = "Exists"    // the set is non-empty
	OperatorNotExists Operator = "NotExists" // the set is empty; the key itself must be produced
)

// Behavior is what a matched rule does with its verdict.
type Behavior string

const (
	// BehaviorEnforce counts and can reject.
	BehaviorEnforce Behavior = "Enforce"

	// BehaviorShadow counts and reports, never rejects, and is transparent
	// inside a FirstMatch cascade.
	BehaviorShadow Behavior = "Shadow"

	// BehaviorBypass allows without touching storage and ends a cascade; a
	// bypass rule carries no rates.
	BehaviorBypass Behavior = "Bypass"
)

// ValueType is the shape a mapped claim extracts into.
type ValueType string

const (
	ValueString      ValueType = "String"
	ValueStringArray ValueType = "StringArray"
)

// Normalize is the transformation applied to extracted values.
type Normalize string

const (
	NormalizeNone      Normalize = "None"
	NormalizeLowercase Normalize = "Lowercase"
)

// Policy is one RateLimitPolicy as authored: a unit of ownership and review,
// not of evaluation — compilation dissolves policies into a flat block set.
type Policy struct {
	// Name is the object name and the first segment of the counter identity
	// (policy/block/rule), which is what makes same-named blocks in
	// different policies independent rather than colliding.
	Name string

	Domain string

	// Groups are private: visible to this policy's rules only, shadowing a
	// same-named shared group deterministically.
	Groups []Group

	// Blocks is the spec's limits list.
	Blocks []Block
}

// Group is a named client list backing the InGroup operator: one shared
// bucket over the enumerated set.
type Group struct {
	Name    string
	Clients []string
}

// Block pairs routes written once with the rules that share them.
type Block struct {
	Name   string
	Target Target
	Mode   Mode // empty reads as ModeAll
	Rules  []Rule
}

// Target is an OR-list of routes; within a route the fields are AND.
type Target struct {
	Routes []Route
}

// Route matches a request location.
type Route struct {
	Path PathMatch

	// Methods is OR over values; empty means any method.
	Methods []string
}

// PathMatch matches the request path, query string already stripped.
type PathMatch struct {
	Type PathType

	// Value is the literal, the prefix, or the template. Template
	// placeholders ({name}) each match exactly one non-empty segment, cover
	// the whole path, and become block-scoped descriptor keys.
	Value string
}

// Rule is one named limit: identity predicates, bucket axes, and windows.
type Rule struct {
	Name string

	// When are identity predicates, AND-combined; path and method belong to
	// the target and are rejected here.
	When []Condition

	// Counters are the bucket axes; empty means one shared bucket. A rule
	// whose axis is absent from the request does not match.
	Counters []string

	Rates []Rate

	Behavior Behavior // empty reads as BehaviorEnforce

	// Replaces suppresses named rules of the same block for requests this
	// rule matched; ModeAll only.
	Replaces []string
}

// Condition is one when predicate.
type Condition struct {
	Key      string
	Operator Operator

	// Value serves Equals, Contains, and InGroup (the group name); Values
	// serves In. Exists and NotExists take neither.
	Value  string
	Values []string
}

// Rate is one window of a rule as authored: an independent bucket.
type Rate struct {
	Requests int64
	Period   time.Duration

	// Burst is meaningful for GCRA only; zero means unset, and compilation
	// resolves the default (= Requests, the full bucket).
	Burst int64

	// Algorithm is the passport name (GCRA, FixedWindow); empty means unset,
	// and compilation resolves the default (GCRA).
	Algorithm string
}

// Mapping is one RateLimitMapping as authored: the per-domain singleton
// declaring identity extraction and shared groups.
type Mapping struct {
	Domain string

	Mappings []KeyMapping

	// Groups are shared: visible to the rules of every policy of the domain.
	Groups []Group
}

// KeyMapping declares one descriptor key extracted from the token.
type KeyMapping struct {
	// Key must not collide with the built-ins other than KeyClient, which a
	// mapping may override.
	Key string

	// Claim is a dot path into the token payload; ClaimPath is the literal
	// segment list for claim names that contain dots. Exactly one is set.
	Claim     string
	ClaimPath []string

	Type      ValueType // empty reads as ValueString
	Normalize Normalize // empty reads as NormalizeNone

	// Fallbacks are claim dot paths tried in order; the first non-empty
	// result wins.
	Fallbacks []string
}

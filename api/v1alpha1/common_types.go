package v1alpha1

// Condition types reported by RateLimitPolicy, following the Kubernetes API
// conventions.
const (
	// ConditionAccepted reports whether the latest generation compiles. It
	// answers "is the object well formed", separately from whether it is the
	// one running.
	ConditionAccepted = "Accepted"

	// ConditionReady is the strict summary: every ready replica enforces the
	// latest generation. GitOps tooling reads it as the health signal, so
	// waiting for it in a pipeline is what catches a rejected edit before it
	// rolls out further.
	ConditionReady = "Ready"

	// ConditionStalled separates "in progress" from "stuck". Ready is false
	// during any rollout; Stalled going true is what deserves an alert.
	ConditionStalled = "Stalled"
)

// Reasons for the Accepted condition.
const (
	// ReasonRulesCompiled marks a generation the compiler accepted whole.
	ReasonRulesCompiled = "RulesCompiled"

	// ReasonCompilationFailed marks a generation with at least one blocking
	// problem. The condition message summarizes; the causes live in
	// RuleProblems, because conditions are a map by type and a generation can
	// break in several places at once.
	ReasonCompilationFailed = "CompilationFailed"
)

// Reasons for the Ready condition.
const (
	// ReasonAllReplicas marks the healthy state: every ready replica enforces
	// the latest generation.
	ReasonAllReplicas = "AllReplicas"

	// ReasonReconciling marks a leader that has not caught up with the latest
	// generation yet.
	ReasonReconciling = "Reconciling"

	// ReasonPropagating marks replicas still taking up a new generation,
	// within the lag threshold.
	ReasonPropagating = "Propagating"

	// ReasonNoReplicas marks a Service with no ready endpoint: nothing is
	// enforcing anything, and nothing is receiving traffic either.
	ReasonNoReplicas = "NoReplicas"

	// ReasonReplicaStale marks a replica lagging past the threshold: a broken
	// informer, or image version skew mid-rollout.
	ReasonReplicaStale = "ReplicaStale"

	// ReasonNotCompiled marks a latest generation that does not compile, with
	// the last-good one enforced in its place.
	ReasonNotCompiled = "NotCompiled"

	// ReasonProbeFailed marks a leader that could not observe the replicas at
	// all, which is the one case where Ready is Unknown rather than false.
	ReasonProbeFailed = "ProbeFailed"
)

// Reason for the Stalled condition when it is false; the true cases reuse
// ReasonReplicaStale and ReasonNotCompiled.
const ReasonProgressing = "Progressing"

// Reasons recorded in RateLimitPolicyStatus.RuleProblems.
//
// A single blocking problem invalidates the whole generation: not one of its
// rules enters the snapshot. There is no such thing as a partly applied
// generation, because "applied" has to mean "applied as written" — a
// FirstMatch cascade with one dead rule silently hands its traffic to the
// neighbours, which are either stricter or looser than the author intended.
// The last-good generation keeps serving in the meantime.
const (
	// ProblemUnresolvedKeyReference marks a rule that references a key nothing
	// produces: no built-in key, no mapping of the policy, no route capture of
	// the block. Blocking.
	ProblemUnresolvedKeyReference = "UnresolvedKeyReference"

	// ProblemUnresolvedGroupReference marks an InGroup predicate naming a
	// group the policy does not define. Blocking.
	ProblemUnresolvedGroupReference = "UnresolvedGroupReference"

	// ProblemUnresolvedReplacedRules marks a replacedRules entry naming a rule
	// outside its own block. Blocking.
	ProblemUnresolvedReplacedRules = "UnresolvedReplacedRules"

	// ProblemIncompatibleOperator marks an operator that cannot apply to the
	// type of its key, such as Equals against an array claim. Blocking.
	ProblemIncompatibleOperator = "IncompatibleOperator"

	// ProblemInvalidCounterAxis marks a counter axis that cannot key a bucket,
	// such as an array-typed key. Blocking.
	ProblemInvalidCounterAxis = "InvalidCounterAxis"

	// ProblemInvalidSpec marks a structural defect the schema cannot see:
	// predicate arity, a Bypass without replacedRules under All, a repeated
	// placeholder, an unknown field or enum value of a newer schema. Blocking.
	ProblemInvalidSpec = "InvalidSpec"

	// ProblemInvalidWindow marks a rate the counting math cannot honor, such
	// as one whose period does not divide evenly at the resolution it asks
	// for. Blocking.
	ProblemInvalidWindow = "InvalidWindow"

	// ProblemDomainBudgetExceeded marks a generation whose worst-case request
	// would collect more counter buckets than one decision may carry.
	// Blocking: enforcing it would leave the widest paths to the runtime
	// backstop, which refuses them outright.
	ProblemDomainBudgetExceeded = "DomainBudgetExceeded"

	// ProblemCaptureShadowsMappedKey is informational: inside the block, a
	// route capture takes precedence over the mapped key of the same name.
	ProblemCaptureShadowsMappedKey = "CaptureShadowsMappedKey"
)

// Descriptor keys the engine produces on its own. A mapping entry cannot
// declare them, and a predicate cannot match path, method or token: routes
// select paths and methods, and the token is an input the engine decodes
// rather than a key.
const (
	// KeyPath carries the :path pseudo-header with the query string removed.
	KeyPath = "path"

	// KeyMethod carries the :method pseudo-header.
	KeyMethod = "method"

	// KeyToken carries the value of the authorization header. The gateway has
	// already verified the signature, so the engine only decodes the payload.
	KeyToken = "token"

	// KeyClient is the built-in identity key: claim sub, lower-cased. It works
	// with an empty mappings list, and an entry of the same name overrides it.
	KeyClient = "client"
)

// ClaimType is the shape a claim takes once extracted, which decides which
// operators apply to it and whether it can key a bucket.
// +kubebuilder:validation:Enum=String;StringArray
type ClaimType string

const (
	// ClaimTypeString extracts one value, so the key is a one-element set and
	// can serve as a counter axis.
	ClaimTypeString ClaimType = "String"

	// ClaimTypeStringArray extracts a list, so the key is a set of elements.
	// Equals is rejected for it, and it cannot serve as a counter axis.
	ClaimTypeStringArray ClaimType = "StringArray"
)

// NormalizeMode is the transformation applied to an extracted value before it
// is compared or put into a counter key.
// +kubebuilder:validation:Enum=None;Lowercase
type NormalizeMode string

const (
	// NormalizeNone keeps the value as the token carries it.
	NormalizeNone NormalizeMode = "None"

	// NormalizeLowercase lower-cases the value, which makes comparison
	// case-insensitive without making the operators case-insensitive.
	NormalizeLowercase NormalizeMode = "Lowercase"
)

// ClaimMapping turns one JWT claim into one descriptor key.
type ClaimMapping struct {
	// Key names the descriptor key the rules reference. It uses the one
	// descriptor key pattern of this API, camelCase included; path, method and
	// token are produced by the engine and cannot be redefined, while client
	// is an allowed override.
	// +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9_]*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Key string `json:"key"`

	// Claim is a dotted path into the payload, such as realm_access.roles.
	// Exactly one of Claim and ClaimPath is set.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Claim string `json:"claim,omitempty"`

	// ClaimPath is the same path given segment by segment, which is how a
	// claim name that itself contains a dot is addressed.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=atomic
	ClaimPath []string `json:"claimPath,omitempty"`

	// Type is the shape of the extracted value.
	// +kubebuilder:default=String
	Type ClaimType `json:"type,omitempty"`

	// Normalization is applied to the extracted value.
	// +kubebuilder:default=None
	Normalization NormalizeMode `json:"normalization,omitempty"`

	// Fallbacks are dotted paths tried in order when the primary path yields
	// nothing. The first non-empty result wins.
	// +optional
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=atomic
	Fallbacks []string `json:"fallbacks,omitempty"`
}

// ClientGroup names a list of client identities that the InGroup operator
// matches against.
type ClientGroup struct {
	// Name is how a predicate references the group. It is unique within the
	// policy.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Clients lists the members of the group. Values are compared with the
	// client key after its effective normalization, which is lower-case unless
	// a mapping entry overrides client with normalization None — then they are
	// compared as written, and the case is the author's responsibility.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=atomic
	Clients []string `json:"clients"`
}

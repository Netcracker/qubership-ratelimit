package v1alpha1

// Condition types reported by both kinds of the group.
const (
	// ConditionAccepted reports that the spec is valid and took part in the
	// compilation of its domain.
	ConditionAccepted = "Accepted"

	// ConditionReady reports that the latest generation is the one being
	// enforced. For a policy that means the generation is valid as a whole; for a
	// mapping it means the generation was accepted by the transaction gate.
	//
	// Accepted and Ready are separate because GitOps tooling reads them
	// separately: kstatus treats Ready as the health signal and leaves the
	// admission verdict to Accepted. Waiting for Ready in a pipeline is what
	// catches a rejected edit before it is rolled out further.
	ConditionReady = "Ready"
)

// Reasons for the Accepted condition, which reports structural validity. After
// the CEL rules of the CRD it is almost always true.
const (
	// ReasonRulesCompiled marks a structurally valid policy spec.
	ReasonRulesCompiled = "RulesCompiled"

	// ReasonKeysResolved marks a structurally valid mapping spec.
	ReasonKeysResolved = "KeysResolved"

	// ReasonInvalidSpec marks a spec the compiler rejected structurally. Only
	// checks that need knowledge the CRD schema cannot express land here; a spec
	// the schema can reject never reaches the compiler.
	ReasonInvalidSpec = "InvalidSpec"
)

// Reasons for the Ready condition.
const (
	// ReasonSnapshotApplied marks an object whose latest generation is the one
	// being enforced.
	ReasonSnapshotApplied = "SnapshotApplied"

	// ReasonMappingRequired marks a policy that references declared keys or
	// shared groups while the domain has no RateLimitMapping at all.
	ReasonMappingRequired = "MappingRequired"

	// ReasonUnresolvedReferences marks a policy that references a key or a group
	// the domain does not produce.
	ReasonUnresolvedReferences = "UnresolvedReferences"

	// ReasonIncompatibleReferences marks a policy whose references resolve but
	// cannot be used the way it uses them, such as an array key under Equals.
	ReasonIncompatibleReferences = "IncompatibleReferences"

	// ReasonRejectedByPolicies marks a mapping the transaction gate vetoed
	// because it would stop rules that are running.
	ReasonRejectedByPolicies = "RejectedByPolicies"

	// ReasonReconciling marks an object whose generation has been seen but not
	// yet compiled into a snapshot.
	ReasonReconciling = "Reconciling"
)

// Reasons recorded in RateLimitPolicyStatus.RuleProblems.
//
// A single blocking problem invalidates the whole generation of the policy: not
// one of its rules enters the snapshot. There is no such thing as a partly
// applied generation, because "applied" has to mean "applied as written" — a
// FirstMatch cascade with one dead rule silently hands its traffic to the
// neighbours, which are either stricter or looser than the author intended. The
// blast radius is the policy itself; the other policies of the domain are
// untouched.
const (
	// ProblemUnresolvedKeyReference marks a rule that references a key nothing
	// produces: no built-in key, no mapping of the domain, no route capture of
	// the block. Blocking.
	ProblemUnresolvedKeyReference = "UnresolvedKeyReference"

	// ProblemUnresolvedGroupReference marks an InGroup predicate naming a group
	// that neither the policy nor the mapping of the domain defines. Blocking.
	ProblemUnresolvedGroupReference = "UnresolvedGroupReference"

	// ProblemIncompatibleOperator marks an operator that cannot apply to the
	// type of its key, such as Equals against an array claim. Blocking.
	ProblemIncompatibleOperator = "IncompatibleOperator"

	// ProblemInvalidCounterAxis marks a counter axis that cannot key a bucket,
	// such as an array-typed key. Blocking.
	ProblemInvalidCounterAxis = "InvalidCounterAxis"

	// ProblemCaptureShadowsMappedKey is informational: inside the block, a route
	// capture takes precedence over the mapped key of the same name.
	ProblemCaptureShadowsMappedKey = "CaptureShadowsMappedKey"
)

// Blocking reports whether a problem reason invalidates the generation that
// carries it.
func Blocking(reason string) bool {
	switch reason {
	case ProblemUnresolvedKeyReference,
		ProblemUnresolvedGroupReference,
		ProblemIncompatibleOperator,
		ProblemInvalidCounterAxis:
		return true
	default:
		return false
	}
}

// Descriptor keys the engine produces on its own. A mapping cannot declare
// them, and a predicate cannot match path, method or token: routes select paths
// and methods, and the token is an input the engine decodes rather than a key.
const (
	// KeyPath carries the :path pseudo-header with the query string removed.
	KeyPath = "path"

	// KeyMethod carries the :method pseudo-header.
	KeyMethod = "method"

	// KeyToken carries the value of the authorization header. The gateway has
	// already verified the signature, so the engine only decodes the payload.
	KeyToken = "token"

	// KeyClient is the built-in identity key: claim sub, lower-cased. It works
	// with no RateLimitMapping present, and a mapping entry of the same name
	// overrides it.
	KeyClient = "client"
)

// GenerationStatus is the pair of generations every kind of this group reports.
//
// They are one concept and are defined once: a reader comparing them is asking
// "is what I wrote what is running", and that question means the same thing for a
// policy and for a mapping. The fields are inlined into each status, so the two
// CRDs render them exactly as they did when each declared its own.
type GenerationStatus struct {
	// ObservedGeneration is the latest spec generation the operator has seen.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ActiveGeneration is the generation actually in effect. It falls behind
	// ObservedGeneration when the latest edit is not the one being enforced and an
	// earlier, last-good generation keeps running. Zero means nothing of this
	// object is in effect at all.
	// +optional
	ActiveGeneration int64 `json:"activeGeneration,omitempty"`
}

// ClientGroup names a list of client identities that the InGroup operator
// matches against.
//
// A group defined by a policy is private to that policy; a group defined by the
// mapping of the domain is visible to every policy of the domain. A private
// name shadows a shared one.
type ClientGroup struct {
	// Name is how a predicate references the group. It is unique among the
	// groups of its object.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Clients lists the members of the group. Values are compared after the
	// same lower-case normalization the client key goes through, so the case a
	// token happens to carry does not decide membership.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1024
	// +kubebuilder:validation:items:MaxLength=253
	// +listType=atomic
	Clients []string `json:"clients"`
}

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// NormalizeMode is the transformation applied to an extracted value before it is
// compared or put into a counter key.
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
// +kubebuilder:validation:XValidation:rule="has(self.claim) != has(self.claimPath)",message="a mapping takes exactly one of claim and claimPath"
// +kubebuilder:validation:XValidation:rule="!(self.key in ['path', 'method', 'token'])",message="path, method and token are produced by the engine and cannot be redefined"
type ClaimMapping struct {
	// Key names the descriptor key the rules of the domain reference.
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9_]*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Key string `json:"key"`

	// Claim is a dotted path into the payload, such as realm_access.roles.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Claim string `json:"claim,omitempty"`

	// ClaimPath is the same path given segment by segment, which is how a claim
	// name that itself contains a dot is addressed.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +listType=atomic
	ClaimPath []string `json:"claimPath,omitempty"`

	// Type is the shape of the extracted value.
	// +kubebuilder:default=String
	Type ClaimType `json:"type,omitempty"`

	// Normalize is applied to the extracted value.
	// +kubebuilder:default=None
	Normalize NormalizeMode `json:"normalize,omitempty"`

	// Fallbacks are dotted paths tried in order when the primary path yields
	// nothing. The first non-empty result wins.
	// +optional
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +listType=atomic
	Fallbacks []string `json:"fallbacks,omitempty"`
}

// RateLimitMappingSpec declares how the domain reads identity out of a token,
// and the client groups its policies share.
type RateLimitMappingSpec struct {
	// Domain is the traffic source this mapping serves. It equals
	// metadata.name, which is what makes the mapping a singleton.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Domain string `json:"domain"`

	// Mappings are the declared keys of the domain. The built-in client key
	// works with no mapping present; an entry named client overrides it.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=key
	Mappings []ClaimMapping `json:"mappings,omitempty"`

	// Groups are the client lists shared by every policy of the domain. A
	// policy that defines a group of the same name shadows the shared one.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Groups []ClientGroup `json:"groups,omitempty"`
}

// MappingRejection names one policy that vetoed a mapping generation.
//
// Generation is the generation that was vetoing, which is the one that was
// running — not necessarily the latest in etcd. Without it the culprit cannot be
// found, because that spec may no longer exist as written.
type MappingRejection struct {
	// Policy is the name of the vetoing policy.
	Policy string `json:"policy"`

	// Generation is the generation of the policy that was running.
	Generation int64 `json:"generation"`

	// Block and Rule locate the reference that the candidate would break.
	// +optional
	Block string `json:"block,omitempty"`
	// +optional
	Rule string `json:"rule,omitempty"`

	// Reason is one of the Problem constants of this package.
	Reason string `json:"reason"`
}

// RateLimitMappingStatus is the observed state of a RateLimitMapping.
type RateLimitMappingStatus struct {
	// GenerationStatus reports which generation is in effect. It falls behind when
	// the transaction gate vetoes an edit; zero for ActiveGeneration means the
	// domain fell back to its built-in keys.
	GenerationStatus `json:",inline"`

	// EffectiveKeys is the set of keys the domain produces: the built-in keys
	// plus the mapped ones. It reports the active generation rather than the
	// candidate, so a rule author reads what is in effect rather than what was
	// asked for. Route captures are per block and do not appear here.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	EffectiveKeys []string `json:"effectiveKeys,omitempty"`

	// RejectedBy lists the policies that vetoed the latest generation.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	RejectedBy []MappingRejection `json:"rejectedBy,omitempty"`

	// Conditions holds the latest observations of the mapping state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=ratelimit,shortName=rlm
// +kubebuilder:printcolumn:name="Domain",type=string,JSONPath=`.spec.domain`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activeGeneration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.domain",message="metadata.name has to equal spec.domain: the mapping is the singleton of its domain"

// RateLimitMapping is the singleton that tells one domain how to read identity
// out of a JWT, and holds the client groups its policies share.
//
// The singleton comes out of the naming rule rather than out of arbitration:
// metadata.name equals spec.domain, and object names are unique in a namespace,
// so a second mapping for a domain cannot be created. The API server rejects it
// with AlreadyExists, and there is no "which one wins" question to answer.
//
// A policy does not wait for a mapping, but it does not run half-way either. A
// policy over built-in keys alone works with no mapping present; a policy
// referencing declared keys or shared groups is invalid as a whole until the
// mapping appears, and comes alive on the same domain rebuild.
//
// Updating a mapping goes through a transaction gate that vetoes a candidate
// which would stop rules that are running. Deleting one does not: that is a
// deliberate administrative act, the domain falls back to the built-in keys, and
// the policies depending on it lose validity. RBAC is the guard against deleting
// it by accident, not the controller.
type RateLimitMapping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RateLimitMappingSpec   `json:"spec,omitempty"`
	Status RateLimitMappingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RateLimitMappingList contains a list of RateLimitMapping.
type RateLimitMappingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateLimitMapping `json:"items"`
}

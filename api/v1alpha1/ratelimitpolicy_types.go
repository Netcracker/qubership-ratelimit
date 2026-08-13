package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
	// ConditionAccepted reports whether the operator has taken this policy into account.
	ConditionAccepted = "Accepted"
)

// RateLimitPolicySpec defines the desired state of RateLimitPolicy.
type RateLimitPolicySpec struct {
	// Domain binds this policy to a traffic source. It must equal the domain
	// configured in that gateway's rate limit filter.
	// +kubebuilder:validation:MinLength=1
	Domain string `json:"domain"`
}

// RateLimitPolicyStatus defines the observed state of RateLimitPolicy.
type RateLimitPolicyStatus struct {
	// ObservedGeneration is the spec generation the conditions were computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions holds the latest observations of the policy state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=ratelimit,shortName=rlp
// +kubebuilder:printcolumn:name="Domain",type=string,JSONPath=`.spec.domain`
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RateLimitPolicy is a set of rate limit rules bound to one gateway domain.
type RateLimitPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RateLimitPolicySpec   `json:"spec,omitempty"`
	Status RateLimitPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RateLimitPolicyList contains a list of RateLimitPolicy.
type RateLimitPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateLimitPolicy `json:"items"`
}

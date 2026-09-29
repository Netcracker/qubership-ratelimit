// Package v1 contains API Schema definitions for the ratelimit v1 API group.
// +kubebuilder:object:generate=true
// +groupName=ratelimit.netcracker.com
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group version these objects are registered under.
	GroupVersion = schema.GroupVersion{Group: "ratelimit.netcracker.com", Version: "v1"}

	// SchemeBuilder registers the types of this group version with a scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types of this group version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &RateLimitPolicy{}, &RateLimitPolicyList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

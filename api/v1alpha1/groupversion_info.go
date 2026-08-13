// Package v1alpha1 contains API Schema definitions for the ratelimit v1alpha1 API group.
// +kubebuilder:object:generate=true
// +groupName=ratelimit.netcracker.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion  = schema.GroupVersion{Group: "ratelimit.netcracker.com", Version: "v1alpha1"}
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion, &RateLimitPolicy{}, &RateLimitPolicyList{})
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

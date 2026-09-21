package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kjson "sigs.k8s.io/json"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Object and ObjectList name the kind in the form every reader of it uses.
//
// There is one such form on purpose. The informer this process runs is the
// unstructured one, and a caller that asks the cache for the typed kind does
// not get an error: a read fails, and GetInformer quietly starts a second
// informer with a second cached copy of every policy. Both are far from where
// the mistake reads, so the shape lives here rather than at each call site.
func Object() *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("RateLimitPolicy"))
	return object
}

func ObjectList() *unstructured.UnstructuredList {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("RateLimitPolicyList"))
	return list
}

// Load reads every policy the reader can see.
//
// Both the updater and the reconciler compile from this same input, which is what
// keeps the status of an object and the rules serving traffic in agreement: they
// are two readings of one pure function, not two implementations of one rule.
//
// The objects arrive unstructured and are decoded here rather than listed as
// the typed kind. A typed decode drops a field this build does not know, and
// dropping it silently is the one failure this component must not have: the
// object would be enforced as the part of itself this build happens to
// understand, which is neither what the author wrote nor a refusal they can
// see. See Decode.
func Load(ctx context.Context, reader client.Reader, namespace string) (Input, error) {
	list := ObjectList()
	if err := reader.List(ctx, list); err != nil {
		return Input{}, fmt.Errorf("list RateLimitPolicy: %w", err)
	}

	input := Input{
		Namespace: namespace,
		Policies:  make([]v1alpha1.RateLimitPolicy, 0, len(list.Items)),
		Skew:      map[client.ObjectKey][]v1alpha1.RuleProblem{},
	}
	for i := range list.Items {
		object, skew, err := Decode(&list.Items[i])
		if err != nil {
			return Input{}, err
		}
		if len(skew) > 0 {
			input.Skew[client.ObjectKeyFromObject(object)] = skew
		}
		input.Policies = append(input.Policies, *object)
	}
	return input, nil
}

// Decode turns one stored object into the typed structure, and reports the
// fields of its spec that this build's schema does not define.
//
// The decode is lenient and the report is separate on purpose. A skewed object
// still has to be usable: its status is where the refusal gets written, and a
// component that could not decode it at all would have nowhere to say so. So
// the unknown fields are dropped from the value and named in the problems, and
// the caller refuses to enforce the result rather than refusing to read it.
//
// A hard error is different in kind - the object is not a RateLimitPolicy at
// all, which the API server does not store - and is returned as an error.
func Decode(object *unstructured.Unstructured) (*v1alpha1.RateLimitPolicy, []v1alpha1.RuleProblem, error) {
	var typed v1alpha1.RateLimitPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, &typed); err != nil {
		return nil, nil, fmt.Errorf("decode RateLimitPolicy %s: %w", client.ObjectKeyFromObject(object), err)
	}

	skew, err := specSkew(object)
	if err != nil {
		return nil, nil, fmt.Errorf("read RateLimitPolicy %s: %w", client.ObjectKeyFromObject(object), err)
	}
	return &typed, skew, nil
}

// specSkew names the fields of the object's spec that this build's schema does
// not define.
//
// Only the spec. The whole object would be the wrong thing to be strict about,
// and not by a little: the status is this component's own and changes far more
// often than the spec. During a rolling upgrade the new leader writes a status
// field an older replica has no schema for, and being strict there would make
// every old replica read every policy as skewed and stop taking new
// generations until the rollout finished - and a rollback would do it the
// other way round. Metadata is the API server's and grows on its own schedule.
// What #379 is about is an object whose spec was written for a newer schema.
//
// The strict pass therefore runs over an object that carries the spec alone,
// which is also what keeps the reported paths spec-relative.
func specSkew(object *unstructured.Unstructured) ([]v1alpha1.RuleProblem, error) {
	spec, found, err := unstructured.NestedFieldNoCopy(object.Object, "spec")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	raw, err := json.Marshal(map[string]any{"spec": spec})
	if err != nil {
		return nil, err
	}

	// Decoded into a holder of the spec alone rather than the whole policy, so
	// that "unknown field" can only ever mean a field of the spec.
	var holder struct {
		Spec v1alpha1.RateLimitPolicySpec `json:"spec"`
	}
	strict, err := kjson.UnmarshalStrict(raw, &holder)
	if err != nil {
		return nil, err
	}

	var problems []v1alpha1.RuleProblem
	for _, e := range strict {
		problems = append(problems, v1alpha1.RuleProblem{
			Reason:  v1alpha1.ProblemInvalidSpec,
			Message: e.Error(),
		})
	}
	return problems, nil
}

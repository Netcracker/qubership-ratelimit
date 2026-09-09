package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
// fields this build's schema does not define.
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
	raw, err := json.Marshal(object.Object)
	if err != nil {
		return nil, nil, fmt.Errorf("read RateLimitPolicy %s: %w", client.ObjectKeyFromObject(object), err)
	}

	var typed v1alpha1.RateLimitPolicy
	strict, err := kjson.UnmarshalStrict(raw, &typed)
	if err != nil {
		return nil, nil, fmt.Errorf("decode RateLimitPolicy %s: %w", client.ObjectKeyFromObject(object), err)
	}

	var problems []v1alpha1.RuleProblem
	for _, e := range strict {
		problems = append(problems, v1alpha1.RuleProblem{
			Reason:  v1alpha1.ProblemInvalidSpec,
			Message: e.Error(),
		})
	}
	return &typed, problems, nil
}

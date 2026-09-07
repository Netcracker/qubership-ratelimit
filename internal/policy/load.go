package policy

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Load reads every policy the reader can see.
//
// Both the updater and the reconciler compile from this same input, which is what
// keeps the status of an object and the rules serving traffic in agreement: they
// are two readings of one pure function, not two implementations of one rule.
func Load(ctx context.Context, reader client.Reader, namespace string) (Input, error) {
	var policies v1alpha1.RateLimitPolicyList
	if err := reader.List(ctx, &policies); err != nil {
		return Input{}, fmt.Errorf("list RateLimitPolicy: %w", err)
	}
	return Input{Namespace: namespace, Policies: policies.Items}, nil
}

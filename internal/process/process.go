// Package process holds what both binaries of the split do the same way at
// startup: read the namespace they serve, sign the leader lease with their
// pod name, and route controller-runtime's logging through the platform's.
// It is the root internal package for that reason; operator/ and service/
// have internal trees of their own that neither may import from the other.
package process

import (
	"fmt"
	"os"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// LeaseName is the Lease both the one-binary packaging and the operator
// compete for. One name, because the two never run side by side in a
// namespace: the split replaces the one binary.
const LeaseName = "ratelimit.netcracker.com"

// Namespace returns the namespace this installation serves, from
// CLOUD_NAMESPACE. Unset is a startup error, not a fallback to the whole
// cluster: the namespace is what keeps the RBAC a Role.
func Namespace() (string, error) {
	namespace := configloader.GetOrDefaultString("cloud.namespace", "")
	if namespace == "" {
		return "", fmt.Errorf("CLOUD_NAMESPACE must be set")
	}
	return namespace, nil
}

// LeaderIdentity is the name this replica signs the lease with: the pod's own
// name, from the Downward API. It is empty outside a pod, where there is no
// pod name to borrow.
func LeaderIdentity() string {
	return os.Getenv("POD_NAME")
}

// LeaderLock builds the lease this replica competes for, signed with the pod
// name. It returns a nil lock when POD_NAME is unset, which hands the choice
// of identity back to controller-runtime: outside a pod - a local run, an
// envtest - the hostname is the only name there is. The manager that takes
// the nil lock has to set LeaderElectionNamespace as well, since off cluster
// controller-runtime has no pod to read the namespace from and refuses to
// start without it. The caller logs the hostname case; this function has no
// logger.
//
// The renew deadline mirrors controller-runtime's own default, because it only
// sizes the client timeout of the lock; the manager keeps timing the election
// itself.
func LeaderLock(config *rest.Config, namespace string) (resourcelock.Interface, error) {
	identity := LeaderIdentity()
	if identity == "" {
		return nil, nil
	}
	lock, err := resourcelock.NewFromKubeconfig(
		resourcelock.LeasesResourceLock,
		namespace,
		LeaseName,
		resourcelock.ResourceLockConfig{Identity: identity},
		config,
		10*time.Second,
	)
	if err != nil {
		return nil, fmt.Errorf("create the leader election lock: %w", err)
	}
	return lock, nil
}

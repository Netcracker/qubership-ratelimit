// Package leader is the lease the operator's pods compete for, signed with
// the pod name: one writer of the status and the ConfigMap while two pods
// overlap during a rollout.
package leader

import (
	"fmt"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/netcracker/qubership-ratelimit/internal/process"
)

// LeaseName is the Lease the operator's pods compete for.
const LeaseName = "ratelimit.netcracker.com"

// Lock builds the lease this replica competes for, signed with the pod
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
func Lock(config *rest.Config, namespace string) (resourcelock.Interface, error) {
	identity := process.PodName()
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

// Package process holds what every binary of the split does the same way at
// startup: read the namespace it serves and its own pod name from the
// environment the Downward API fills, and route logr logging through the
// platform's logger. It is the root internal package for that reason;
// operator/ and service/ have internal trees of their own that neither may
// import from the other. It imports no Kubernetes client, because the service
// carries none; the leader lease lives in operator/internal/leader.
package process

import (
	"fmt"
	"os"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
)

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

// PodName is this replica's own name, from the Downward API. It is empty
// outside a pod, where there is no pod name to borrow: a local run, an
// envtest.
func PodName() string {
	return os.Getenv("POD_NAME")
}

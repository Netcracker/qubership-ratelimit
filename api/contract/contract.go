// Package contract holds the constants the operator and the service agree on.
//
// The two are delivered as separate images and separate charts, and nothing
// orders their installation or keeps their versions equal. What joins them
// is a Service name, two port names, and one ConfigMap, and each of those has
// to be the same string on both sides or the pair fails silently: filters
// aimed at a missing Service pass everything under fail-open, and a ConfigMap
// nobody mounts leaves the service NotReady. So the strings live here, once,
// and both binaries import them. The charts carry the same names and ports,
// and the CI test that renders both charts and compares them with these
// values comes with the second chart (Netcracker/qubership-core-infra#412).
package contract

const (
	// ServiceName is the Service of the data plane, whatever the release is
	// called. Satellites compute the RLS address from it with nothing but the
	// baseline's namespace to go on, and the operator reads its fleet through
	// the same name.
	ServiceName = "ratelimit"

	// GRPCPort is the port the Service publishes the rate limit endpoint on,
	// and the port the gateway filters address. GRPCPortName is its name on
	// the Service; the port carries appProtocol grpc, without which Istio
	// takes it for HTTP/1.1.
	GRPCPort     = 9000
	GRPCPortName = "grpc"

	// MetricsPortName is the name under which the Service publishes the
	// service's metrics port. The operator takes the number from the
	// EndpointSlice by this name and reads the applied generation of every
	// ready replica on it.
	MetricsPortName = "metrics"

	// AppliedPath is where a service replica publishes what it enforces, on
	// the metrics port: the applied generation per domain, the format
	// versions it reads, and a refusal with its reason. The operator reads it
	// from every ready replica to judge Ready. It sits under /debug/: read-only
	// diagnostics inside the cluster, with no authentication and no
	// compatibility promise beyond the two halves of this delivery.
	AppliedPath = "/debug/applied"

	// SnapshotPath is where a service replica renders what it enforces, on
	// the same port and under the same terms as AppliedPath: a summary of
	// every domain at the path itself, and one domain in full, rules and
	// resolved client lists included, at SnapshotPath/<domain>. Nothing in
	// the delivery reads it; it is for a human with a port-forward.
	SnapshotPath = "/debug/snapshot"

	// ConfigMapName is the one ConfigMap per namespace that the operator
	// writes and the service mounts. The operator is its only writer; no
	// chart renders it.
	ConfigMapName = "ratelimit-config"

	// ManifestKey is the key under the ConfigMap's data that holds the
	// manifest: plain JSON with the format version, the operator version, and
	// the generation, UID, and hash of every domain. The per-domain payloads
	// sit under binaryData, one <domain>.json.gz each.
	ManifestKey = "manifest"

	// MountPath is where the service mounts the ConfigMap, as a whole
	// directory: the manifest at MountPath/manifest and each payload beside
	// it. The kubelet swaps the ..data symlink on an update, and that swap is
	// what the service watches.
	MountPath = "/etc/ratelimit/config"
)

{{/*
The namespace every object lands in: NAMESPACE, the platform parameter, as
on the platform's other services, or the release namespace without it. The
pods read it back through the Downward API, so the installation's scope is
this namespace either way.
*/}}
{{- define "ratelimit.namespace" -}}
{{- .Values.NAMESPACE | default .Release.Namespace -}}
{{- end -}}

{{/*
SERVICE_NAME, the platform's name of the microservice. It is the value of
app.kubernetes.io/name and name on every object, so the pods of the operator
carry ratelimit-operator unless the platform parameter says otherwise.
*/}}
{{- define "ratelimit.name" -}}
{{- .Values.SERVICE_NAME | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The name of the Deployment, the ServiceAccount and the RBAC pair. The
Deployment's name is also what the operator adopts as the owner of the
configuration ConfigMap, so the Deployment passes it as --deployment.
*/}}
{{- define "ratelimit.fullname" -}}
{{- include "ratelimit.name" . -}}
{{- end -}}

{{- define "ratelimit.serviceAccountName" -}}
{{- default (include "ratelimit.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
Which of the composite's namespaces this release lands in.

A business application is installed either into one namespace or as a
composite: one baseline namespace plus satellites, each with its own gateway.
The operator and the service run in the baseline alone; a satellite gets the
gateway filters and nothing else, and its filters send checks to the
baseline's Service.

The signal is the platform's BASELINE_ORIGIN, and it is the one core-operator
itself renders by: a namespace with BASELINE_ORIGIN set is a satellite, and
the value is the baseline's namespace. A namespace without it is the baseline,
or a standalone installation, and those two render the same objects, which
is why there is no third value here. The service chart reads the variable the
same way. A BASELINE_ORIGIN naming the release's own namespace fails the
render: a namespace cannot be a satellite of itself, and rendering it as one
leaves it without an operator and a service.

BASELINE_CONTROLLER is a hedge, not a supported topology. On this platform
the baseline is never blue-green'd, so the platform never sets it for this
chart and the coalesce below always resolves to BASELINE_ORIGIN. It is read
anyway because control-plane reads it the same way, and two charts that would
disagree about where the baseline is, should the variable ever appear, is a
worse outcome than one line here.
*/}}
{{- define "ratelimit.mode" -}}
{{- if and .Values.BASELINE_ORIGIN (eq .Values.BASELINE_ORIGIN (include "ratelimit.namespace" .)) -}}
{{- fail (printf "BASELINE_ORIGIN %q is this release's own namespace. Leave it unset in the baseline namespace; in a satellite, set it to the baseline's namespace." .Values.BASELINE_ORIGIN) -}}
{{- end -}}
{{- if .Values.BASELINE_ORIGIN -}}satellite{{- else -}}baseline{{- end -}}
{{- end -}}

{{/*
The namespace whose Service the gateway filters send checks to: this one, or
the baseline's for a satellite.
*/}}
{{- define "ratelimit.serviceNamespace" -}}
{{- if .Values.BASELINE_ORIGIN -}}
{{- coalesce .Values.BASELINE_CONTROLLER .Values.BASELINE_ORIGIN -}}
{{- else -}}
{{- include "ratelimit.namespace" . -}}
{{- end -}}
{{- end -}}

{{/*
The Service the service chart renders, and the port it serves checks on. Both
are contract constants (api/contract), the same in both charts and both
binaries, and a CI test compares this render with the Go constants. A
satellite namespace of a composite runs no component of its own: its gateway
filters send checks to the baseline's Service, and the address they compute
has only the baseline's namespace to go on. A name or a port taken from the
values would leave the satellite guessing at how the baseline was installed.
*/}}
{{- define "ratelimit.serviceName" -}}
ratelimit
{{- end -}}

{{- define "ratelimit.grpcPort" -}}
9000
{{- end -}}

{{/*
The labels the platform's other services carry, from the platform
parameters APPLICATION_NAME, ARTIFACT_DESCRIPTOR_VERSION and MANAGED_BY,
with the chart's appVersion and Helm standing in for a release installed
without them. The instance is the name in its namespace, as on the
platform's other services.
*/}}
{{- define "ratelimit.labels" -}}
{{ include "ratelimit.selectorLabels" . }}
app.kubernetes.io/version: {{ include "ratelimit.version" . | quote }}
app.kubernetes.io/component: operator
app.kubernetes.io/part-of: {{ .Values.APPLICATION_NAME | quote }}
app.kubernetes.io/technology: go
app.kubernetes.io/managed-by: {{ .Values.MANAGED_BY | default .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
The labels of the Deployment object alone: the deployment session, which
changes on every deployment and would restart the pods if their template
carried it.
*/}}
{{- define "ratelimit.deploymentLabels" -}}
{{ include "ratelimit.labels" . }}
deployment.netcracker.com/sessionId: {{ .Values.DEPLOYMENT_SESSION_ID | default "unimplemented" | quote }}
{{- end -}}

{{- define "ratelimit.selectorLabels" -}}
name: {{ include "ratelimit.name" . }}
app.kubernetes.io/name: {{ include "ratelimit.name" . }}
app.kubernetes.io/instance: {{ printf "%s-%s" (include "ratelimit.name" .) (include "ratelimit.namespace" .) | trunc 63 | trimSuffix "-" | quote }}
{{- end -}}

{{/*
The release the image is: ARTIFACT_DESCRIPTOR_VERSION, the platform
parameter, or the chart's appVersion without it.
*/}}
{{- define "ratelimit.version" -}}
{{- .Values.ARTIFACT_DESCRIPTOR_VERSION | default .Chart.AppVersion -}}
{{- end -}}

{{/*
The image: IMAGE_REPOSITORY and TAG, the platform parameters. An empty TAG
takes the chart's appVersion, which is a fixed release. A floating tag such as
"latest" moves under a running workload, so two pods of one rollout can end up
on different builds.
*/}}
{{- define "ratelimit.tag" -}}
{{- .Values.TAG | default .Chart.AppVersion -}}
{{- end -}}

{{- define "ratelimit.image" -}}
{{- printf "%s:%s" .Values.IMAGE_REPOSITORY (include "ratelimit.tag" .) -}}
{{- end -}}

{{/*
The rollout, by the platform's DEPLOYMENT_STRATEGY_TYPE, read the way the
platform's other services read it. Unset is this chart's own default: one pod
more and none less, so the old pod serves until the new one is Ready.
*/}}
{{- define "ratelimit.strategy" -}}
{{- $type := .Values.DEPLOYMENT_STRATEGY_TYPE | default "" -}}
{{- if eq $type "recreate" }}
type: Recreate
{{- else if eq $type "best_effort_controlled_rollout" }}
type: RollingUpdate
rollingUpdate:
  maxSurge: 0
  maxUnavailable: 80%
{{- else if eq $type "custom_rollout" }}
type: RollingUpdate
rollingUpdate:
  maxSurge: {{ .Values.DEPLOYMENT_STRATEGY_MAXSURGE | default "25%" }}
  maxUnavailable: {{ .Values.DEPLOYMENT_STRATEGY_MAXUNAVAILABLE | default "25%" }}
{{- else }}
type: RollingUpdate
rollingUpdate:
  maxSurge: 1
  maxUnavailable: 0
{{- end }}
{{- end -}}

{{/*
The container's security context. The root filesystem is read-only where
READONLY_CONTAINER_FILE_SYSTEM_ENABLED is set and PAAS_PLATFORM is
KUBERNETES, as on the platform's other services; on OpenShift the platform
assigns the user and the group.
*/}}
{{- define "ratelimit.containerSecurityContext" -}}
{{- $kubernetes := eq (.Values.PAAS_PLATFORM | default "KUBERNETES") "KUBERNETES" -}}
runAsNonRoot: true
{{- if $kubernetes }}
runAsGroup: 10001
{{- end }}
readOnlyRootFilesystem: {{ and .Values.READONLY_CONTAINER_FILE_SYSTEM_ENABLED $kubernetes }}
allowPrivilegeEscalation: false
capabilities:
  drop:
    - ALL
{{- end -}}

{{- define "ratelimit.rlsCluster" -}}
{{- printf "outbound|%s||%s" (include "ratelimit.grpcPort" .) (include "ratelimit.rlsAuthority" .) -}}
{{- end -}}

{{/*
Envoy stat_prefix from a gateway name: dashes become underscores, so the
filter's stats land under one clean prefix per gateway.
*/}}
{{- define "ratelimit.statPrefix" -}}
{{- . | replace "-" "_" -}}
{{- end -}}

{{/*
FQDN of the RLS Service: the :authority the gateway's gRPC calls carry, and
the host half of the rlsCluster name.
*/}}
{{- define "ratelimit.rlsAuthority" -}}
{{- printf "%s.%s.svc.cluster.local" (include "ratelimit.serviceName" .) (include "ratelimit.serviceNamespace" .) -}}
{{- end -}}

{{/*
Fails the render when an enabled gateway has no domain, or when two enabled
gateways share one: their filters would send the same domain and every counter
of both gateways would merge into the same buckets.
*/}}
{{- define "ratelimit.validateDomains" -}}
{{- $seen := dict -}}
{{- range $role, $config := (dict "public" .Values.gateways.public "private" .Values.gateways.private) -}}
{{- $config := $config | default dict -}}
{{- if $config.enabled -}}
{{- if not $config.domain -}}
{{- fail (printf "gateways.%s is enabled and needs a domain" $role) -}}
{{- end -}}
{{- if hasKey $seen $config.domain -}}
{{- fail (printf "gateways: %s and %s share domain %q; the counters of both gateways would merge into the same buckets" (get $seen $config.domain) $role $config.domain) -}}
{{- end -}}
{{- $_ := set $seen $config.domain $role -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The pod's spread over the cluster, the way the platform's other services
spread theirs: one constraint per entry of CLOUD_TOPOLOGIES, the platform
parameter, and without it one on CLOUD_TOPOLOGY_KEY, the node by default. An
entry's maxSkew defaults to 1 and its whenUnsatisfiable to ScheduleAnyway, so
a cluster that cannot spread the replicas still runs them. The selector is
the pod's own selector labels.
*/}}
{{- define "ratelimit.topologySpreadConstraints" -}}
{{- $root := . -}}
{{- $topologies := .Values.CLOUD_TOPOLOGIES | default (list (dict "topologyKey" .Values.CLOUD_TOPOLOGY_KEY)) -}}
{{- range $topologies }}
- topologyKey: {{ .topologyKey | quote }}
  maxSkew: {{ .maxSkew | default 1 }}
  whenUnsatisfiable: {{ .whenUnsatisfiable | default "ScheduleAnyway" }}
  labelSelector:
    matchLabels:
      {{- include "ratelimit.selectorLabels" $root | nindent 6 }}
{{- end }}
{{- end -}}

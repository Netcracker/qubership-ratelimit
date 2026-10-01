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
app.kubernetes.io/name and name on every object, so the pods of the service
carry ratelimit-service unless the platform parameter says otherwise.
*/}}
{{- define "ratelimit.name" -}}
{{- .Values.SERVICE_NAME | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The Deployment's and the ServiceAccount's name; the Service has a fixed
name of its own, below.
*/}}
{{- define "ratelimit.fullname" -}}
{{- include "ratelimit.name" . -}}
{{- end -}}

{{- define "ratelimit.serviceAccountName" -}}
{{- default (include "ratelimit.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
Which of the composite's namespaces this release lands in, read the same
way as the operator chart reads it: a namespace with the platform's
BASELINE_ORIGIN set is a satellite, and a namespace without it is the
baseline or a standalone installation, which render the same objects. A
BASELINE_ORIGIN naming the release's own namespace fails the render, as it
does in the operator chart.

A satellite runs no service. Its gateway filters, rendered by the operator
chart, send checks to the baseline's Service; a service installed there
would wait for an operator that never comes, stay NotReady, and fail the
readiness gate of the deployment. Every template of this chart is wrapped in
this check, so a satellite release is empty, and the platform installs the
same pair of charts in every namespace without a rule of its own.
*/}}
{{- define "ratelimit.mode" -}}
{{- if and .Values.BASELINE_ORIGIN (eq .Values.BASELINE_ORIGIN (include "ratelimit.namespace" .)) -}}
{{- fail (printf "BASELINE_ORIGIN %q is this release's own namespace. Leave it unset in the baseline namespace; in a satellite, set it to the baseline's namespace." .Values.BASELINE_ORIGIN) -}}
{{- end -}}
{{- if .Values.BASELINE_ORIGIN -}}satellite{{- else -}}baseline{{- end -}}
{{- end -}}

{{/*
The Service is named ratelimit whatever the release is called, and its gRPC
port is 9000: both are contract constants (api/contract), the same in both
charts and both binaries, and a CI test compares this render with the Go
constants. A satellite namespace of a composite runs no component of its own:
its gateway filters send checks to this Service by that name, and the address
they compute has only the baseline's namespace to go on. The operator reads
the service replicas through this Service too, by the port named metrics.
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
app.kubernetes.io/component: rls
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

{{/*
The namespace of the dbaas-operator that reconciles the chart's DBaaS objects:
the host of API_DBAAS_ADDRESS is <aggregator>.<namespace>, and the operator
runs beside its aggregator. http://dbaas-aggregator.dbaas:8080 gives dbaas.
*/}}
{{- define "ratelimit.dbaasNamespace" -}}
{{- $host := first (splitList ":" (last (splitList "://" .Values.API_DBAAS_ADDRESS))) -}}
{{- $parts := splitList "." $host -}}
{{- if lt (len $parts) 2 -}}
{{- fail (printf "API_DBAAS_ADDRESS %q names no namespace; expected http://<aggregator>.<namespace>:<port>" .Values.API_DBAAS_ADDRESS) -}}
{{- end -}}
{{- index $parts 1 -}}
{{- end -}}

{{/*
The Secret the counter store's connection lives in: written by dbaas-operator
for the chart's DatabaseSecretClaim, mounted by the Deployment.
*/}}
{{- define "ratelimit.redisSecretName" -}}
{{- printf "%s-redis" (include "ratelimit.fullname" .) | trunc 63 | trimSuffix "-" -}}
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

{{/*
Chart name, overridable through .Values.nameOverride. It is the value of
app.kubernetes.io/name on every object, so the pods of the service carry
ratelimit-service unless the deployer says otherwise.
*/}}
{{- define "ratelimit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified name. Used for the Deployment and the ServiceAccount; the
Service has a fixed name of its own, below.
*/}}
{{- define "ratelimit.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "ratelimit.name" . | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ratelimit.serviceAccountName" -}}
{{- default (include "ratelimit.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
Which of the composite's namespaces this release lands in, read the same
way as the operator chart reads it: a namespace with the deployer's
BASELINE_ORIGIN set is a satellite, and a namespace without it is the
baseline or a standalone installation, which render the same objects.

A satellite runs no service. Its gateway filters, rendered by the operator
chart, send checks to the baseline's Service; a service installed there
would wait for an operator that never comes, stay NotReady, and fail the
readiness gate of the deployment. Every template of this chart is wrapped in
this check, so a satellite release is empty, and the deployer installs the
same pair of charts in every namespace without a rule of its own.
*/}}
{{- define "ratelimit.mode" -}}
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

{{- define "ratelimit.labels" -}}
app.kubernetes.io/name: {{ include "ratelimit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: rls
app.kubernetes.io/technology: go
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "ratelimit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ratelimit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Refuse an in-process counter store on more than one replica.

Without redis.addresses every replica counts in its own memory, so a limit of
N admits N per replica: the rendered limit is not the enforced one, and nothing
in the status says so. The management API makes it worse: its idempotency
records, sweep lease, and confirmation tokens live in that same memory, so a
preview lands on one pod and its confirmation on another that has never heard
of the token. Both are the same mistake, and this is where it is refused.
*/}}
{{- define "ratelimit.validateStore" -}}
{{- if and (not .Values.redis.addresses) (ne (int .Values.REPLICAS) 1) -}}
{{- fail (printf "in-process store needs exactly one replica; set redis.addresses (REPLICAS is %v and redis.addresses is empty)" .Values.REPLICAS) -}}
{{- end -}}
{{- end -}}

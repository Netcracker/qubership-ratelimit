{{/*
Chart name, overridable through .Values.nameOverride.
*/}}
{{- define "ratelimit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified name. Used for the Deployment, the Service, the ServiceAccount
and the RBAC pair, so the gRPC cluster address in the EnvoyFilter resolves.
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

{{- define "ratelimit.rlsCluster" -}}
{{- printf "outbound|%v||%s.%s.svc.cluster.local" .Values.rls.port (include "ratelimit.fullname" .) .Release.Namespace -}}
{{- end -}}

{{/*
The management API settings, with the chart's defaults filled in.

A release upgraded with --reuse-values carries the values of the previous
release and nothing else, so .Values.management is nil on any install made
before this key existed and every reference to it fails the render. Reading the
settings through here means such an upgrade gets the chart's defaults instead of
an error.
*/}}
{{- define "ratelimit.management" -}}
{{- $defaults := dict "enabled" true "port" 8082 "corsOrigins" (list) "createClientRoles" true -}}
{{- merge (deepCopy (.Values.management | default dict)) $defaults | toYaml -}}
{{- end -}}

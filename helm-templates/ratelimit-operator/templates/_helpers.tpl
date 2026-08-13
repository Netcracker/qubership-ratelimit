{{/*
Chart name, overridable through .Values.nameOverride.
*/}}
{{- define "ratelimit-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified name. Used for the Deployment, the Service, the ServiceAccount
and the RBAC pair, so the gRPC cluster address in the EnvoyFilter resolves.
*/}}
{{- define "ratelimit-operator.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "ratelimit-operator.name" . | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ratelimit-operator.serviceAccountName" -}}
{{- default (include "ratelimit-operator.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "ratelimit-operator.labels" -}}
app.kubernetes.io/name: {{ include "ratelimit-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/component: operator
app.kubernetes.io/technology: go
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "ratelimit-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ratelimit-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ratelimit-operator.rlsCluster" -}}
{{- printf "outbound|%v||%s.%s.svc.cluster.local" .Values.rls.port (include "ratelimit-operator.fullname" .) .Release.Namespace -}}
{{- end -}}

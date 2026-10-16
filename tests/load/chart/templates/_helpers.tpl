{{- define "loadtest.name" -}}
{{- printf "%s-loadtest" .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "loadtest.labels" -}}
app.kubernetes.io/name: ratelimit-loadtest
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "loadtest.gatewayNamespace" -}}
{{- default .Release.Namespace .Values.gateway.namespace -}}
{{- end -}}

{{/* The steps as rate:seconds pairs, the form run.sh reads. */}}
{{- define "loadtest.steps" -}}
{{- $pairs := list -}}
{{- range .Values.load.steps -}}
{{- if or (lt (float64 .rate) 0.0) (lt (int64 .seconds) 1) -}}
{{- fail (printf "load.steps: each step needs a rate of at least 0 and seconds of at least 1, got %v" .) -}}
{{- end -}}
{{- $pairs = append $pairs (printf "%v:%d" .rate (int64 .seconds)) -}}
{{- end -}}
{{- if not $pairs -}}
{{- fail "load.steps is empty" -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}

{{/* The windows as requests/period pairs, the form loadkit verify reads; empty when the limits are not checked. */}}
{{- define "loadtest.windows" -}}
{{- if and .Values.load.checkLimits (eq .Values.policy.algorithm "FixedWindow") -}}
{{- $pairs := list -}}
{{- range .Values.policy.windows -}}
{{- $pairs = append $pairs (printf "%d/%ds" (mul (int64 .requests) (int64 $.Values.policy.multiplier)) (int64 .periodSeconds)) -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}
{{- end -}}

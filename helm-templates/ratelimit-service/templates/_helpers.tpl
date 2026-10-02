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
{{- if and .Values.BASELINE_ORIGIN (eq .Values.BASELINE_ORIGIN (.Values.NAMESPACE | default .Release.Namespace)) -}}
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
A CPU quantity in millicores: "500m" is 500, "1" is 1000.
*/}}
{{- define "ratelimit.millicores" -}}
{{- $value := toString . -}}
{{- if hasSuffix "m" $value -}}
{{- trimSuffix "m" $value -}}
{{- else -}}
{{- mulf $value 1000 -}}
{{- end -}}
{{- end -}}

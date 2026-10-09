{{/*
Which of the composite's namespaces this release lands in.

A business application is installed either into one namespace or as a
composite: one baseline namespace plus satellites, each with its own gateway.
The operator and the service run in the baseline alone. A satellite gets the
gateway filters of the service chart and nothing else, so every template of
this chart is wrapped in this check and a satellite release is empty.

The signal is the platform's BASELINE_ORIGIN, and it is the one core-operator
itself renders by: a namespace with BASELINE_ORIGIN set is a satellite, and
the value is the baseline's namespace. A namespace without it is the baseline,
or a standalone installation, and those two render the same objects, which
is why there is no third value here. The service chart reads the variable the
same way. A BASELINE_ORIGIN naming NAMESPACE, the namespace the release
installs into, fails the render: a namespace cannot be a satellite of itself, and rendering it as one
leaves it without an operator and a service.
*/}}
{{- define "ratelimit.mode" -}}
{{- if and .Values.BASELINE_ORIGIN (eq .Values.BASELINE_ORIGIN .Values.NAMESPACE) -}}
{{- fail (printf "BASELINE_ORIGIN %q is this release's own namespace. Leave it unset in the baseline namespace; in a satellite, set it to the baseline's namespace." .Values.BASELINE_ORIGIN) -}}
{{- end -}}
{{- if .Values.BASELINE_ORIGIN -}}satellite{{- else -}}baseline{{- end -}}
{{- end -}}

{{/*
ratelimit.valueOr renders .value, or .default when the value is unset or
empty. Helm's default function also replaces a numeric zero, and zero is a
meaningful maxSurge, maxUnavailable, or stabilization window.
*/}}
{{- define "ratelimit.valueOr" -}}
{{- if or (kindIs "invalid" .value) (eq (toString .value) "") -}}{{ .default }}{{- else -}}{{ .value }}{{- end -}}
{{- end -}}

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
{{- if and .Values.BASELINE_ORIGIN (eq .Values.BASELINE_ORIGIN .Values.NAMESPACE) -}}
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
{{- .Values.NAMESPACE -}}
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

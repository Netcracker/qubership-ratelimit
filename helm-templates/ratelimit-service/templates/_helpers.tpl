{{/*
Which of the composite's namespaces this release lands in, read the same
way as the operator chart reads it: a namespace with the platform's
BASELINE_ORIGIN set is a satellite, and a namespace without it is the
baseline or a standalone installation, which render the same objects. A
BASELINE_ORIGIN naming NAMESPACE, the namespace the release installs into,
fails the render, as it does in the operator chart.

A satellite runs no service: one installed there would wait for an operator
that never comes, stay NotReady, and fail the readiness gate of the
deployment. Every template of this chart but EnvoyFilter.yaml is wrapped in
this check, so a satellite release holds the gateway filters alone, and the
platform installs the same pair of charts in every namespace without a rule
of its own. The filters send the satellite's checks to the baseline's
Service.
*/}}
{{- define "ratelimit.mode" -}}
{{- if and .Values.BASELINE_ORIGIN (eq .Values.BASELINE_ORIGIN .Values.NAMESPACE) -}}
{{- fail (printf "BASELINE_ORIGIN %q is this release's own namespace. Leave it unset in the baseline namespace; in a satellite, set it to the baseline's namespace." .Values.BASELINE_ORIGIN) -}}
{{- end -}}
{{- if .Values.BASELINE_ORIGIN -}}satellite{{- else -}}baseline{{- end -}}
{{- end -}}

{{/*
The Service is named ratelimit whatever the release is called, and its gRPC
port is 9000: both are contract constants (api/contract), the same in both
binaries, and a CI test compares this render with the Go
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
The namespace whose Service the gateway filters send checks to: this one, or
the baseline's for a satellite.

BASELINE_CONTROLLER is a hedge, not a supported topology. On this platform
the baseline is never blue-green'd, so the platform never sets it for this
chart and the coalesce below always resolves to BASELINE_ORIGIN. It is read
anyway because control-plane reads it the same way, and two charts that would
disagree about where the baseline is, should the variable ever appear, is a
worse outcome than one line here.
*/}}
{{- define "ratelimit.serviceNamespace" -}}
{{- if .Values.BASELINE_ORIGIN -}}
{{- coalesce .Values.BASELINE_CONTROLLER .Values.BASELINE_ORIGIN -}}
{{- else -}}
{{- .Values.NAMESPACE -}}
{{- end -}}
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
The namespace of the dbaas-operator that reconciles the chart's DBaaS objects:
redis.dbaas.operatorNamespace when set, or else the namespace in the host of
API_DBAAS_ADDRESS, <aggregator>.<namespace> with an optional .svc or
.svc.cluster.local, since the operator runs beside its aggregator.
http://dbaas-aggregator.dbaas:8080 gives dbaas. A host of any other form, an
IP address or an external name, fails the render rather than naming a
namespace no dbaas-operator watches.
*/}}
{{- define "ratelimit.dbaasNamespace" -}}
{{- if .Values.redis.dbaas.operatorNamespace -}}
{{- .Values.redis.dbaas.operatorNamespace -}}
{{- else -}}
{{- $host := first (splitList "/" (first (splitList ":" (last (splitList "://" .Values.API_DBAAS_ADDRESS))))) -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.[a-z]([-a-z0-9]*[a-z0-9])?(\\.svc(\\.cluster\\.local)?)?$" $host) -}}
{{- fail (printf "API_DBAAS_ADDRESS %q does not name the namespace of dbaas-operator: its host is not <aggregator>.<namespace>[.svc[.cluster.local]]. Set redis.dbaas.operatorNamespace." .Values.API_DBAAS_ADDRESS) -}}
{{- end -}}
{{- index (splitList "." $host) 1 -}}
{{- end -}}
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

{{/*
ratelimit.valueOr renders .value, or .default when the value is unset or
empty. Helm's default function also replaces a numeric zero, and zero is a
meaningful maxSurge, maxUnavailable, or stabilization window.
*/}}
{{- define "ratelimit.valueOr" -}}
{{- if or (kindIs "invalid" .value) (eq (toString .value) "") -}}{{ .default }}{{- else -}}{{ .value }}{{- end -}}
{{- end -}}

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

{{/*
Which of the composite's namespaces this release lands in.

A business application is installed either into one namespace or as a
composite: one baseline namespace plus satellites, each with its own gateway.
The component runs in the baseline alone; a satellite gets the gateway filters
and nothing else, and its filters send checks to the baseline's Service.

The signal is the deployer's BASELINE_ORIGIN, and it is the one core-operator
itself renders by: a namespace with BASELINE_ORIGIN set is a satellite, and
the value is the baseline's namespace. A namespace without it is the baseline,
or a standalone installation - and those two render the same objects, which
is why there is no third value here.

For a blue-green baseline the shared components run in its controller
namespace, so BASELINE_CONTROLLER takes precedence when set. That is the
resolution control-plane uses for the same question.
*/}}
{{- define "ratelimit.mode" -}}
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
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
The Service is named ratelimit whatever the release is called. A satellite
namespace of a composite runs no component of its own: its gateway filters
send checks to the baseline's Service, and the address they compute has only
the baseline's namespace to go on. A name derived from the release would leave
the satellite guessing at how the baseline was installed.

The leader reads its fleet through this Service too, so the Deployment passes
the same name as --service-name.
*/}}
{{- define "ratelimit.serviceName" -}}
ratelimit
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
{{- printf "outbound|%v||%s" .Values.rls.port (include "ratelimit.rlsAuthority" .) -}}
{{- end -}}


{{/*
Envoy stat_prefix from a gateway name: dashes become underscores, so the
filter's stats land under one clean prefix per gateway.
*/}}
{{- define "ratelimit.statPrefix" -}}
{{- . | replace "-" "_" -}}
{{- end -}}

{{/*
FQDN of the RLS Service — the :authority the gateway's gRPC calls carry, and
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
Refuse an in-process counter store on more than one replica.

Without redis.addresses every replica counts in its own memory, so a limit of
N admits N per replica: the rendered limit is not the enforced one, and nothing
in the status says so. The management API makes it worse - its idempotency
records, sweep lease, and confirmation tokens live in that same memory, so a
preview lands on one pod and its confirmation on another that has never heard
of the token. Both are the same mistake, and this is where it is refused.
*/}}
{{- define "ratelimit.validateStore" -}}
{{- if and (not .Values.redis.addresses) (ne (int .Values.REPLICAS) 1) -}}
{{- fail (printf "in-process store needs exactly one replica; set redis.addresses (REPLICAS is %v and redis.addresses is empty)" .Values.REPLICAS) -}}
{{- end -}}
{{- end -}}

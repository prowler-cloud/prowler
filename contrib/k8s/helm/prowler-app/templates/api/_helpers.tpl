{{/*
Create the name of the service account to use
*/}}
{{- define "prowler.api.serviceAccountName" -}}
{{- if .Values.api.serviceAccount.create }}
{{- default (printf "%s-%s" (include "prowler.fullname" .) "api") .Values.api.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.api.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Django allowed hosts for the API ConfigMap. Renders the DJANGO_ALLOWED_HOSTS
value configured by the operator and always includes the in-cluster API
service hostname (<fullname>-api) used by UI_API_BASE_URL, so server-side UI
requests pass Django's Host validation. Django strips the port from the Host
header before matching, so the bare hostname is enough.
*/}}
{{- define "prowler.api.allowedHosts" -}}
{{- $hosts := list "localhost" "127.0.0.1" (printf "%s-api" (include "prowler.fullname" .)) -}}
{{- $configured := "" -}}
{{- if hasKey .Values.api.djangoConfig "DJANGO_ALLOWED_HOSTS" -}}
{{- $configured = index .Values.api.djangoConfig "DJANGO_ALLOWED_HOSTS" -}}
{{- end -}}
{{- range $host := splitList "," $configured -}}
{{- $trimmed := trim $host -}}
{{- if and $trimmed (not (has $trimmed $hosts)) -}}
{{- $hosts = append $hosts $trimmed -}}
{{- end -}}
{{- end -}}
{{- join "," $hosts -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "prowler.worker.serviceAccountName" -}}
{{- if .Values.worker.serviceAccount.create }}
{{- default (printf "%s-%s" (include "prowler.fullname" .) "worker") .Values.ui.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.worker.serviceAccount.name }}
{{- end }}
{{- end }}
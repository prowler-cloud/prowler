{{/*
Expand the name of the chart.
*/}}
{{- define "prowler.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "prowler.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "prowler.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "prowler.labels" -}}
helm.sh/chart: {{ include "prowler.chart" . }}
{{ include "prowler.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "prowler.selectorLabels" -}}
app.kubernetes.io/name: {{ include "prowler.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{/*
Create the name of the service account to use for API
*/}}
{{- define "prowler.apiServiceAccountName" -}}
{{- if .Values.api.serviceAccount.create }}
{{- default (include "prowler.fullname" .) .Values.api.serviceAccount.name }}-api
{{- else }}
{{- default "default" .Values.api.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for Celery Worker
*/}}
{{- define "prowler.celeryWorkerServiceAccountName" -}}
{{- if .Values.celeryWorker.serviceAccount.create }}
{{- default (include "prowler.fullname" .) .Values.celeryWorker.serviceAccount.name }}-celery-worker
{{- else }}
{{- default "default" .Values.celeryWorker.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for Celery Beat
*/}}
{{- define "prowler.celeryBeatServiceAccountName" -}}
{{- if .Values.celeryBeat.serviceAccount.create }}
{{- default (include "prowler.fullname" .) .Values.celeryBeat.serviceAccount.name }}-celery-beat
{{- else }}
{{- default "default" .Values.celeryBeat.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for Django
*/}}
{{- define "prowler.djangoServiceAccountName" -}}
{{- if not (eq .Values.django.serviceAccount.name "") }}
{{- default (include "prowler.fullname" .) .Values.django.serviceAccount.name }}-django
{{- else }}
{{- default "default" .Values.django.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Selector labels for API
*/}}
{{- define "prowler.apiSelectorLabels" -}}
app.kubernetes.io/name: {{ include "prowler.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}-api
app.kubernetes.io/component: api
{{- end }}

{{/*
Selector labels for Celery Worker
*/}}
{{- define "prowler.celeryWorkerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "prowler.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}-celery-worker
app.kubernetes.io/component: celery-worker
{{- end }}

{{/*
Selector labels for Celery Beat
*/}}
{{- define "prowler.celeryBeatSelectorLabels" -}}
app.kubernetes.io/name: {{ include "prowler.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}-celery-beat
app.kubernetes.io/component: celery-beat
{{- end }}

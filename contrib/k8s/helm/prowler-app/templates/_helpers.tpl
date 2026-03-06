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
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Django environment variables for api, worker, and worker_beat.
*/}}
{{- define "prowler.django.env" -}}
- name: DJANGO_TOKEN_SIGNING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.djangoTokenSigningKey.secretKeyRef.name }}
      key: {{ .Values.djangoTokenSigningKey.secretKeyRef.key }}
- name: DJANGO_TOKEN_VERIFYING_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.djangoTokenVerifyingKey.secretKeyRef.name }}
      key: {{ .Values.djangoTokenVerifyingKey.secretKeyRef.key }}
- name: DJANGO_SECRETS_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.djangoSecretsEncryptionKey.secretKeyRef.name }}
      key: {{ .Values.djangoSecretsEncryptionKey.secretKeyRef.key }}
{{- end }}


{{/*
PostgreSQL environment variables for api, worker, and worker_beat.
Outputs nothing when postgresql.enabled is false.
*/}}
{{- define "prowler.postgresql.env" -}}
{{- if .Values.postgresql.enabled }}
{{- if .Values.postgresql.auth.username }}
- name: POSTGRES_USER
  value: {{ .Values.postgresql.auth.username | quote }}
{{- end }}
- name: POSTGRES_PASSWORD
{{- if .Values.postgresql.auth.existingSecret }}
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgresql.auth.existingSecret }}
      key: {{ required "postgresql.auth.secretKeys.userPasswordKey is required when using an existing secret" .Values.postgresql.auth.secretKeys.userPasswordKey }}
{{- else if .Values.postgresql.auth.password }}
  value: {{ .Values.postgresql.auth.password | quote }}
{{- else }}
  valueFrom:
    secretKeyRef:
      name: {{ .Release.Name }}-postgresql
      key: password
{{- end }}
- name: POSTGRES_DB
  value: {{ .Values.postgresql.auth.database | quote }}
- name: POSTGRES_HOST
  value: {{ .Release.Name }}-postgresql
- name: POSTGRES_PORT
  value: "5432"
- name: POSTGRES_ADMIN_USER
  value: postgres
- name: POSTGRES_ADMIN_PASSWORD
{{- if .Values.postgresql.auth.existingSecret }}
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgresql.auth.existingSecret }}
      key: {{ required "postgresql.auth.secretKeys.adminPasswordKey is required when using an existing secret" .Values.postgresql.auth.secretKeys.adminPasswordKey }}
{{- else if .Values.postgresql.auth.postgresPassword }}
  value: {{ .Values.postgresql.auth.postgresPassword | quote }}
{{- else }}
  valueFrom:
    secretKeyRef:
      name: {{ .Release.Name }}-postgresql
      key: postgres-password
{{- end }}
{{- end }}
{{- end }}

{{/*
Neo4j environment variables for api, worker, and worker_beat.
Outputs nothing when neo4j.enabled is false.
*/}}
{{- define "prowler.neo4j.env" -}}
{{- if .Values.neo4j.enabled }}
- name: NEO4J_HOST
  value: {{ .Release.Name }}
- name: NEO4J_PORT
  value: "7687"
- name: NEO4J_USER
  value: "neo4j"
- name: NEO4J_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ required "neo4j.neo4j.passwordFromSecret is required" .Values.neo4j.neo4j.passwordFromSecret }}
      key: NEO4J_PASSWORD
{{- end }}
{{- end }}

{{/* vim: set filetype=mustache: */}}
{{/*
The controller name
*/}}
{{- define "akv2k8s.controller.name" -}}
{{- default .Values.controller.name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The env-injector name
*/}}
{{- define "akv2k8s.envinjector.name" -}}
{{- default .Values.env_injector.name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name for the Helm install
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "akv2k8s.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create a default fully qualified app name for the controller.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "akv2k8s.controller.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- printf "%s-%s" .Values.fullnameOverride "controller" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name "controller" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name "controller" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create a default fully qualified app name for the env-injector.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "akv2k8s.envinjector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- printf "%s-%s" .Values.fullnameOverride "envinjector" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf "%s-%s" .Release.Name "envinjector" | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s-%s" .Release.Name "envinjector" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}


{{/*
Create the name of the service account to use
*/}}
{{- define "controller.serviceAccountName" -}}
{{- if .Values.controller.serviceAccount.create -}}
{{ default (include "akv2k8s.controller.fullname" .) .Values.controller.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.controller.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Create the name of the service account to use
*/}}
{{- define "envinjector.serviceAccountName" -}}
{{- if .Values.env_injector.serviceAccount.create -}}
{{ default (include "akv2k8s.envinjector.fullname" .) .Values.env_injector.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.env_injector.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "akv2k8s.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

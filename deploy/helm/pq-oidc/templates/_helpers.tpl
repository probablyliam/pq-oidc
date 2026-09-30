{{- define "pq-oidc.labels" -}}
app.kubernetes.io/name: pq-oidc
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "pq-oidc.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}

{{- define "pq-oidc.providerName" -}}
{{ .Release.Name }}-provider
{{- end -}}

{{- define "pq-oidc.secretName" -}}
{{ .Release.Name }}-secrets
{{- end -}}

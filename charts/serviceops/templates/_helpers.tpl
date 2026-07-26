{{- define "serviceops.name" -}}serviceops{{- end }}
{{- define "serviceops.fullname" -}}{{ .Release.Name }}{{- end }}
{{- define "serviceops.labels" -}}
app.kubernetes.io/name: {{ include "serviceops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
{{- define "serviceops.bootstrapSecretName" -}}
{{- if .Values.secret.create }}{{ include "serviceops.fullname" . }}-bootstrap{{ else }}{{ required "existingBootstrapSecret is required when secret.create=false" .Values.existingBootstrapSecret }}{{ end }}
{{- end }}
{{- define "serviceops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "serviceops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "serviceops.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "serviceops.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{- default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end }}
{{- define "serviceops.secretName" -}}
{{- if .Values.secret.create }}{{ include "serviceops.fullname" . }}-secrets{{ else }}{{ required "existingSecret is required when secret.create=false" .Values.existingSecret }}{{ end }}
{{- end }}

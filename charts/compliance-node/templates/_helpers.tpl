{{/*
  Activation logic for compliance rules. A rule is active when an explicit
  override exists in .Values.rules (that value wins), else if any enabled
  profile selects it.
*/}}
{{- define "cr.ruleActive" -}}
{{- $root := .root -}}
{{- $rule := .rule -}}
{{- $overrides := $root.Values.rules | default dict -}}
{{- if hasKey $overrides $rule -}}
{{-   if index $overrides $rule -}}true{{- else -}}false{{- end -}}
{{- else -}}
{{-   $active := false -}}
{{-   $profileMap := index $root.Values "profileRules" -}}
{{-   range $profile, $enabled := $root.Values.profiles -}}
{{-     if $enabled -}}
{{-       $ruleList := index $profileMap $profile | default (list) -}}
{{-       if has $rule $ruleList -}}{{- $active = true -}}{{- end -}}
{{-     end -}}
{{-   end -}}
{{-   if $active -}}true{{- else -}}false{{- end -}}
{{- end -}}
{{- end -}}

{{/* True if any rule in the given list is active. */}}
{{- define "cr.anyActive" -}}
{{- $root := .root -}}
{{- $any := false -}}
{{- range $r := .rules -}}
{{-   if eq (include "cr.ruleActive" (dict "root" $root "rule" $r)) "true" -}}{{- $any = true -}}{{- end -}}
{{- end -}}
{{- if $any -}}true{{- else -}}false{{- end -}}
{{- end -}}

{{/* Count how many rules in the list are active (as an int). */}}
{{- define "cr.countActive" -}}
{{- $root := .root -}}
{{- $n := 0 -}}
{{- range $r := .rules -}}
{{-   if eq (include "cr.ruleActive" (dict "root" $root "rule" $r)) "true" -}}{{- $n = add1 $n -}}{{- end -}}
{{- end -}}
{{- $n -}}
{{- end -}}

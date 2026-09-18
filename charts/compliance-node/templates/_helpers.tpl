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

{{/* Canonical `uname -m` architecture; the Kubernetes spellings are accepted. */}}
{{- define "cr.arch" -}}
{{- $a := .Values.cluster.architecture | toString -}}
{{- if eq $a "amd64" -}}x86_64{{- else if eq $a "arm64" -}}aarch64{{- else -}}{{ $a }}{{- end -}}
{{- end -}}

{{/*
  Refuse to render a rule the Compliance Operator would report as
  notapplicable for this cluster. Checked centrally so one render reports every
  offending rule at once instead of failing on the first object it reaches.
*/}}
{{- define "cr.applicabilityPreflight" -}}
{{- $root := . -}}
{{- $arch := include "cr.arch" $root -}}
{{- $bad := list -}}
{{- range $rule, $req := ($root.Values.ruleApplicability | default dict) -}}
{{-   if eq (include "cr.ruleActive" (dict "root" $root "rule" $rule)) "true" -}}
{{-     $reason := "" -}}
{{-     if hasKey $req "never" -}}
{{-       $reason = printf "never applicable (%s)" $req.never -}}
{{-     else if and (hasKey $req "arch") (not (has $arch $req.arch)) -}}
{{-       $reason = printf "not applicable on %s" $arch -}}
{{-     else if and (hasKey $req "hypershift") (not (has $root.Values.cluster.hypershift $req.hypershift)) -}}
{{-       $reason = printf "not applicable when cluster.hypershift is %v" $root.Values.cluster.hypershift -}}
{{-     end -}}
{{-     if $reason -}}
{{-       $bad = append $bad (printf "  %s - %s" $rule $reason) -}}
{{-     end -}}
{{-   end -}}
{{- end -}}
{{- if $bad -}}
{{- $hint := printf "Disable them in .Values.rules, or apply the generated overlay for this architecture (-f values-%s.yaml). See RULES.md for the applicability of every rule." $arch -}}
{{- fail (printf "%d active rule(s) are not applicable to this cluster:\n%s\n%s" (len $bad) (join "\n" (sortAlpha $bad)) $hint) -}}
{{- end -}}
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

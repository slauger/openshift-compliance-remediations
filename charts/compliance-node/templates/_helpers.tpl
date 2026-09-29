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

{{/*
  Percent-encode a value substituted into an Ignition data URI. The operator
  runs url.PathEscape over its own substituted output; the chart keeps the
  payload encoded and injects the value, so the value has to be encoded here.
  Without it a value containing a space and a # is read as a YAML comment and
  the rest of the data: scalar - the rest of the config file - disappears with
  no error. `%` goes first, or it would double-encode the escapes below.
  Quotes and backslashes are not handled here: values.schema.json rejects them
  outright, which is a clearer failure than an encoded surprise.
*/}}
{{- define "cr.enc" -}}
{{- . | toString | replace "%" "%25" | replace " " "%20" | replace "#" "%23" | replace "&" "%26" | replace "?" "%3F" | replace "+" "%2B" -}}
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
{{- $archBad := false -}}
{{- range $rule, $req := ($root.Values.ruleApplicability | default dict) -}}
{{-   if eq (include "cr.ruleActive" (dict "root" $root "rule" $rule)) "true" -}}
{{-     $reason := "" -}}
{{-     if hasKey $req "never" -}}
{{-       $reason = printf "never applicable (%s)" $req.never -}}
{{-     else if and (hasKey $req "arch") (not (has $arch $req.arch)) -}}
{{-       $reason = printf "not applicable on %s" $arch -}}
{{-       $archBad = true -}}
{{-     else if and (hasKey $req "hypershift") (not (has $root.Values.cluster.hypershift $req.hypershift)) -}}
{{-       $reason = printf "not applicable when cluster.hypershift is %v" $root.Values.cluster.hypershift -}}
{{-     end -}}
{{-     if $reason -}}
{{-       $bad = append $bad (printf "  %s - %s" $rule $reason) -}}
{{-     end -}}
{{-   end -}}
{{- end -}}
{{- if $bad -}}
{{- $hint := "Disable them in .Values.rules, or change the cluster facts they depend on. See RULES.md for the applicability of every rule." -}}
{{- if $archBad -}}
{{- $hint = printf "Disable them in .Values.rules, or apply the generated overlay for this architecture: -f values-%s.yaml from the chart you are installing (the umbrella ships its own, with the values nested per subchart). See RULES.md for the applicability of every rule." $arch -}}
{{- end -}}
{{- fail (printf "%d active rule(s) are not applicable to this cluster:\n%s\n%s" (len $bad) (join "\n" (sortAlpha $bad)) $hint) -}}
{{- end -}}
{{- end -}}

{{/*
  Refuse to render a rule whose upstream dependency is switched off. Directional
  on purpose: the operator will not apply a remediation with an unmet
  dependency, but the reverse - the dependency applied without the rule that
  needs it - is perfectly fine and must not fail.
*/}}
{{- define "cr.dependencyPreflight" -}}
{{- $root := . -}}
{{- $bad := list -}}
{{- range $rule, $deps := ($root.Values.ruleDependencies | default dict) -}}
{{-   if eq (include "cr.ruleActive" (dict "root" $root "rule" $rule)) "true" -}}
{{-     range $dep := $deps -}}
{{-       if ne (include "cr.ruleActive" (dict "root" $root "rule" $dep)) "true" -}}
{{-         $bad = append $bad (printf "  %s requires %s, which is not active" $rule $dep) -}}
{{-       end -}}
{{-     end -}}
{{-   end -}}
{{- end -}}
{{- if $bad -}}
{{- fail (printf "%d active rule(s) have an unmet dependency:\n%s\nUpstream marks these with complianceascode.io/depends-on; enable the dependency, or disable the rule that needs it." (len $bad) (join "\n" (sortAlpha $bad))) -}}
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

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
{{-   $profileMap := (index $root.Values "profileRules") | default dict -}}
{{-   range $profile, $enabled := $root.Values.profiles -}}
{{-     if $enabled -}}
{{-       $ruleList := (index $profileMap $profile) | default (list) -}}
{{-       if not (kindIs "slice" $ruleList) -}}{{- $ruleList = list -}}{{- end -}}
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
{{- $hypershiftBad := false -}}
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
{{-       $hypershiftBad = $root.Values.cluster.hypershift -}}
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
{{- else if $hypershiftBad -}}
{{- $hint = "Disable them in .Values.rules, or change the cluster facts they depend on. For a hosted cluster the generated overlay does the former: -f values-hypershift.yaml from the chart you are installing. See RULES.md for the applicability of every rule." -}}
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

{{/*
  Refuse a rule whose upstream fix cannot work as written. These are already
  shipped disabled and marked in RULES.md, but opting one in rendered an object
  the API server accepts and then prunes - success reported, nothing changed.
*/}}
{{- define "cr.brokenPreflight" -}}
{{- $root := . -}}
{{- $bad := list -}}
{{- range $rule, $why := ($root.Values.brokenRules | default dict) -}}
{{-   if eq (include "cr.ruleActive" (dict "root" $root "rule" $rule)) "true" -}}
{{-     $bad = append $bad (printf "  %s - %s" $rule $why) -}}
{{-   end -}}
{{- end -}}
{{- if $bad -}}
{{- fail (printf "%d active rule(s) reproduce an upstream fix that cannot work:\n%s\nPrefer the non-broken alternative in the same group; see RULES.md." (len $bad) (join "\n" (sortAlpha $bad))) -}}
{{- end -}}
{{- end -}}

{{/*
  Refuse an output mode that does not fit the cluster. Each wrong pairing would
  otherwise be accepted by the API server and then do nothing: a hosted cluster
  has no Machine Config Operator to read a MachineConfig, and a standalone
  cluster has no NodePool to read the ConfigMap.
*/}}
{{- define "cr.nodeOutputPreflight" -}}
{{- $nodepool := eq .Values.node.output "nodepool" -}}
{{- if and $nodepool (not .Values.cluster.hypershift) -}}
{{- fail "node.output=nodepool needs cluster.hypershift=true: a standalone cluster has no NodePool, so the ConfigMap would never be read." -}}
{{- end -}}
{{- if and .Values.node.enabled (not $nodepool) .Values.cluster.hypershift -}}
{{- fail "cluster.hypershift=true needs node.output=nodepool: a hosted cluster has no Machine Config Operator, so a MachineConfig applied to the guest would never be read." -}}
{{- end -}}
{{- if and $nodepool .Values.tailoredProfile.enabled -}}
{{- fail "tailoredProfile.enabled cannot be combined with node.output=nodepool: the ConfigMap belongs on the management cluster and the TailoredProfile on the hosted cluster. Render it separately for the guest with node.enabled=false and the default node.output." -}}
{{- end -}}
{{- if and $nodepool (not .Values.node.enabled) -}}
{{- range $key, $obj := (.Values.extraManifests | default dict) -}}
{{- if ne (dig "enabled" true $obj) false -}}
{{- fail (printf "extraManifests.%s renders nowhere: node.output=nodepool only renders them into the ConfigMap, and node.enabled is false." $key) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and .Values.cluster.hypershift (not $nodepool) -}}
{{- include "cr.guestExtrasPreflight" . -}}
{{- end -}}
{{- end -}}

{{/*
  On the guest of a hosted cluster nothing reads these, the same reason the
  output guards refuse the chart's own objects.
*/}}
{{- define "cr.guestExtrasPreflight" -}}
{{- range $key, $obj := (.Values.extraManifests | default dict) -}}
{{- if and (ne (dig "enabled" true $obj) false) (has $obj.kind (list "MachineConfig" "KubeletConfig" "ContainerRuntimeConfig")) -}}
{{- fail (printf "extraManifests.%s (%s) would never be read on the guest of a hosted cluster, which has no Machine Config Operator. A MachineConfig goes through node.output=nodepool; anything else through a ConfigMap of your own." $key $obj.kind) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The name to reference from NodePool.spec.config: per release, so per cluster. */}}
{{- define "cr.nodePoolConfigMap" -}}
{{- .Values.node.nodePool.configMapName | default (printf "%s-hardening" .Release.Name) -}}
{{- end -}}

{{/* The same refusal for the platform chart, see cr.nodeOutputPreflight. */}}
{{- define "cr.platformOutputPreflight" -}}
{{- $output := .Values.platform.output -}}
{{- if and (ne $output "cluster") (not .Values.cluster.hypershift) -}}
{{- fail (printf "platform.output=%s needs cluster.hypershift=true: a standalone cluster has no hosted control plane." $output) -}}
{{- end -}}
{{- if and (eq $output "cluster") .Values.cluster.hypershift -}}
{{- fail "cluster.hypershift=true needs platform.output=hostedcluster or guest: the hosted control plane owns APIServer/cluster and OAuth/cluster, and rejects edits to them from the guest." -}}
{{- end -}}
{{- if eq $output "hostedcluster" -}}
{{- if .Values.tailoredProfile.enabled -}}
{{- fail "tailoredProfile.enabled cannot be combined with platform.output=hostedcluster: this output goes to the management cluster and the TailoredProfile to the hosted cluster. Render it with platform.output=guest." -}}
{{- end -}}
{{- range $key, $obj := (.Values.extraManifests | default dict) -}}
{{- if ne (dig "enabled" true $obj) false -}}
{{- fail (printf "extraManifests.%s cannot be combined with platform.output=hostedcluster: this output goes to the management cluster. Render it with platform.output=guest." $key) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $output "guest" -}}
{{- include "cr.guestExtrasPreflight" . -}}
{{- end -}}
{{- end -}}

{{/*
  Objects you add yourself, rendered verbatim with the chart's labels.
  Deliberately not upstream content: everything else in templates/ comes from
  the pinned ComplianceAsCode release, and this is the one place for a control
  upstream ships no remediation for.

  A map, not a list, so a second values file can switch one entry off without
  restating the rest - Helm replaces lists and merges maps, the same reason
  mustMergeOverwrite forces whole-list comparisons elsewhere. Each entry takes
  an optional `enabled` (default true), which is what makes these togglable the
  way `rules` is for upstream rules.

  `kinds`, when not empty, means the entries go into the NodePool ConfigMap: only
  those kinds are accepted, a role other than worker is refused because the
  controller would silently overwrite it, and the release name stays out, see
  _labels_block.

  Note the `{{ end -}}` without a left trim after the object: a `{{- end` there
  eats the newline before the next `---`, so every entry after the first was
  glued onto its predecessor and four objects parsed as one document. helm
  template still printed four `kind:` lines, so only a YAML parse catches it -
  there is a test.
*/}}
{{- define "cr.extraManifests" -}}
{{- $root := .root -}}
{{- $kinds := .kinds -}}
{{- range $key := (keys ($root.Values.extraManifests | default dict) | sortAlpha) -}}
{{- $obj := index $root.Values.extraManifests $key -}}
{{- if ne (dig "enabled" true $obj) false -}}
{{- if not $obj.kind }}
{{- fail (printf "extraManifests.%s has no kind" $key) }}
{{- end }}
{{- if not $obj.apiVersion }}
{{- fail (printf "extraManifests.%s (%s) has no apiVersion" $key $obj.kind) }}
{{- end }}
{{- if not (dig "metadata" "name" "" $obj) }}
{{- fail (printf "extraManifests.%s (%s) has no metadata.name" $key $obj.kind) }}
{{- end }}
{{- if and $kinds (not (has $obj.kind $kinds)) }}
{{- fail (printf "extraManifests.%s (%s) cannot go into the NodePool ConfigMap, which takes %s. Reference a ConfigMap of your own from the NodePool for it; a KubeletConfig only if the chart renders none, since a NodePool takes one." $key $obj.kind (join ", " $kinds)) }}
{{- end }}
{{- $role := dig "metadata" "labels" "machineconfiguration.openshift.io/role" "worker" $obj }}
{{- if and $kinds (ne $role "worker") }}
{{- fail (printf "extraManifests.%s has role %s, but a NodePool only has workers and would apply it to them regardless." $key $role) }}
{{- end }}
{{- $labels := mergeOverwrite (dict
      "app.kubernetes.io/name" $root.Chart.Name
      "app.kubernetes.io/instance" ($root.Release.Name | trunc 63 | trimSuffix "-")
      "app.kubernetes.io/component" "local"
      "app.kubernetes.io/part-of" "compliance-hardening"
      "app.kubernetes.io/managed-by" $root.Release.Service)
      (dig "metadata" "labels" dict $obj) -}}
{{- if $kinds -}}{{- $labels = omit $labels "app.kubernetes.io/instance" -}}{{- end -}}
{{- $out := omit (deepCopy $obj) "enabled" -}}
{{- $out = set $out "metadata" (set (deepCopy $obj.metadata) "labels" $labels) -}}
---
{{ $out | toYaml }}
{{ end -}}
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

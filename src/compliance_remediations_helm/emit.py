"""Emit Helm charts from parsed content.

Produces two standalone charts under ``charts_dir``:
  * compliance-platform  - ocp4 config objects (no reboot)
  * compliance-node       - MachineConfig/KubeletConfig (reboots, per MCP role)

And (task 7) an umbrella ``compliance-hardening`` that depends on both.

Merge strategy:
  * One target Kubernetes object == one template file.
  * Each contributing rule's fragment is a named template, gated by its own
    toggle; fragments deep-merge at render time (mustMergeOverwrite).
  * If a target object has conflicting rules (shared discriminated-union subtree
    or same leaf/different value), the template emits a Helm ``fail`` guard that
    aborts rendering when more than one of the conflicting rules is active.

Activation logic (see _helpers.tpl):
  * explicit override in .Values.rules wins,
  * else active if any enabled profile selects the rule.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import applicability
from .collisions import MergeGroup, build_groups
from .parser import Content, rules_with_fixes
from .resolver import resolve_defaults, rewrite_placeholders

PLATFORM_CHART = "compliance-platform"
NODE_CHART = "compliance-node"
UMBRELLA_CHART = "compliance-hardening"

DEFAULT_OCP_VERSION = "4.20"


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
_YAML11_BOOL_NULL = frozenset({
    # YAML 1.1 booleans/null that would otherwise be typed, not strings.
    "y", "n", "yes", "no", "true", "false", "on", "off", "null", "none", "~",
})


def _yaml_scalar(v: str) -> str:
    lower = v.strip().lower()
    needs_quote = (
        v == ""
        or bool(re.search(r"[:#\{\}\[\],&*!|>'\"%@`]", v))
        or v.strip() != v
        # YAML 1.1 booleans/null (yes/no/on/off/true/false/null/~, any case)
        or lower in _YAML11_BOOL_NULL
        # numeric-looking (int/float/hex/octal) so it is preserved as a string
        or bool(re.fullmatch(r"[+-]?(\d[\d_]*(\.\d*)?|\.\d+|0x[0-9a-fA-F]+)", v.strip()))
        # leading-zero tokens (e.g. file modes like 0755) stay strings
        or bool(re.fullmatch(r"0\d+", v.strip()))
    )
    if needs_quote:
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return v


def _strip_doc_separators(y: str) -> str:
    return re.sub(r"(?m)^---\s*$", "", y).strip("\n")


def _fragment_body(doc_yaml: str) -> str:
    """Content body (spec/data/...) with the apiVersion/kind/metadata header removed."""
    y = _strip_doc_separators(doc_yaml)
    out: list[str] = []
    capturing = False
    for line in y.splitlines():
        if not capturing and re.match(
            r"^(spec|data|rules|parameters|projectRequestTemplate|objects):", line
        ):
            capturing = True
        if capturing:
            out.append(line)
    return "\n".join(out).strip("\n")


def _tpl_name(obj_slug: str, rule_helm_name: str, idx: int) -> str:
    # Helm named templates (define) are chart-global. A rule may contribute
    # fixes to more than one target object, so the object slug MUST be part of
    # the name; otherwise two files define the same name and the last one wins,
    # silently corrupting the rendered object.
    slug = re.sub(r"[^a-z0-9]+", "-", rule_helm_name.lower()).strip("-")
    return f"cr.frag.{obj_slug}.{slug}.{idx}"


def _ocp_semver_expr(constraint: str) -> str:
    m = re.match(r"(<=|>=|<|>|=)?\s*(.+)", constraint.strip())
    op = m.group(1) or ">="
    ver = m.group(2)
    # Normalize .Values.cluster.ocpVersion to major.minor.0 so both "4.20" and a
    # full "4.20.1" (as emitted by `oc get clusterversion`) yield valid semver.
    norm = ('(printf "%s.%s.0" '
            '(.Values.cluster.ocpVersion | toString | splitList "." | first) '
            '(index (.Values.cluster.ocpVersion | toString | splitList ".") 1))')
    return f'semverCompare "{op}{ver}" {norm}'


# --------------------------------------------------------------------------- #
# static chart files
# --------------------------------------------------------------------------- #
def chart_yaml(name: str, description: str, content_version: str,
               chart_version: str = "0.0.0") -> str:
    return f"""\
apiVersion: v2
name: {name}
description: {description}
type: application
version: {chart_version}
appVersion: "{content_version}"
keywords:
  - compliance
  - openshift
  - hardening
  - openscap
"""


README_GOTMPL = """\
{{ template "chart.header" . }}
{{ template "chart.description" . }}

{{ template "chart.versionBadge" . }}
{{ template "chart.appVersionBadge" . }}

## Values

{{ template "chart.valuesTable" . }}

## Rules

See [`RULES.md`](../../RULES.md) for the full rule → profile matrix.

{{ template "helm-docs.versionFooter" . }}
"""


HELPERS_TPL = """\
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
{{- fail (printf "%d active rule(s) are not applicable to this cluster:\\n%s\\n%s" (len $bad) (join "\\n" (sortAlpha $bad)) $hint) -}}
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
"""


# --------------------------------------------------------------------------- #
# values.yaml (helm-docs format: `# --` annotations)
# --------------------------------------------------------------------------- #
def _profile_rules_block(contents: list[Content], layer: str) -> str:
    lines = [
        "# profileRules maps each profile to the fix-carrying rules it selects",
        "# (auto-generated; regenerated by the generator).",
        "# @ignored",
        "profileRules:",
    ]
    for content in contents:
        fixset = set(rules_with_fixes(content))
        for pid in sorted(content.profiles):
            prof = content.profiles[pid]
            selected = sorted({
                f"{content.product}-{r}"
                for r in prof.selected_rules
                if r in fixset and _rule_layer(content.rules[r]) == layer
            })
            if selected:
                lines.append(f"  {pid}:")
                lines.extend(f"    - {r}" for r in selected)
            else:
                lines.append(f"  {pid}: []")
    return "\n".join(lines)


def _rule_layer(rule) -> str:
    from .classify import layer_for_kind
    for fix in rule.fixes:
        m = re.search(r"(?m)^\s*kind:\s*(\S+)", fix.yaml)
        if m:
            return layer_for_kind(m.group(1))
    return "platform"


# Tie-breaker preference when several equally-selected alternatives exist.
# `not_old` maps to the Red Hat-recommended Intermediate TLS profile.
_WINNER_PREFERENCE = ("_not_old", "_intermediate", "_modern")


def _profile_selection_counts(contents: list[Content]) -> dict[str, int]:
    """helm_name -> number of profiles (across all products) that select it."""
    counts: dict[str, int] = {}
    for content in contents:
        fixset = set(rules_with_fixes(content))
        for prof in content.profiles.values():
            for r in prof.selected_rules:
                if r in fixset:
                    hn = f"{content.product}-{r}"
                    counts[hn] = counts.get(hn, 0) + 1
    return counts


def default_disabled_rules(contents: list[Content]) -> dict[str, str]:
    """Pick a default winner for each conflict group and return the losers to
    pre-disable in values.yaml, mapped to a short reason. Overridable by users.

    Winner selection is **profile-aware**: the alternative that the most
    profiles actually select wins, so whitelisting a profile keeps the control
    that profile requests. `_WINNER_PREFERENCE` only breaks ties among
    equally-selected candidates. A rule that no profile selects is never chosen
    as winner over one that is, and the winner is never left with 0 profiles
    when a profile-selected alternative exists.
    """
    counts = _profile_selection_counts(contents)
    disabled: dict[str, str] = {}
    for g in build_groups(*contents)[0]:
        for c in g.conflicts():
            rules = list(c.rules)

            def rank(r: str) -> tuple:
                # 1) most profile selections first (negate for ascending sort)
                # 2) then _WINNER_PREFERENCE order
                # 3) then name for determinism
                pref_idx = next(
                    (i for i, p in enumerate(_WINNER_PREFERENCE) if p in r),
                    len(_WINNER_PREFERENCE),
                )
                return (-counts.get(r, 0), pref_idx, r)

            winner = sorted(rules, key=rank)[0]
            for r in rules:
                if r != winner:
                    disabled[r] = f"alternative of {winner} on {g.key.kind}/{g.key.name}"
    return disabled


def _profile_variables_block(contents: list[Content], layer: str) -> str:
    """Map each profile to the variables its fix-rules reference (scopes TP setValues)."""
    from .resolver import _VAR_RE
    lines = [
        "# profileVariables maps each profile to the XCCDF variables its rules use",
        "# (auto-generated; scopes TailoredProfile setValues).",
        "# @ignored",
        "profileVariables:",
    ]
    for content in contents:
        fixset = rules_with_fixes(content)
        for pid in sorted(content.profiles):
            prof = content.profiles[pid]
            used: set[str] = set()
            for r in prof.selected_rules:
                rule = fixset.get(r)
                if rule and _rule_layer(rule) == layer:
                    for fix in rule.fixes:
                        used.update(_VAR_RE.findall(fix.yaml))
            if used:
                lines.append(f"  {pid}:")
                lines.extend(f"    - {v}" for v in sorted(used))
            else:
                lines.append(f"  {pid}: []")
    return "\n".join(lines)


def _profiles_with_layer(contents: list[Content], layer: str) -> list[str]:
    out: list[str] = []
    for content in contents:
        fixset = set(rules_with_fixes(content))
        for pid, prof in content.profiles.items():
            if any(r in fixset and _rule_layer(content.rules[r]) == layer
                   for r in prof.selected_rules):
                out.append(pid)
    return sorted(out)


def _variables_block(contents: list[Content]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for content in contents:
        merged.update(resolve_defaults(content))
    return merged


def _indent_block(lines: list[str], spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(f"{pad}{line}" if line else line for line in lines)


def _rule_applicability_block(appl: dict, layer_rules: set) -> str:
    """The applicability map the preflight helper consults.

    Same shape as profileRules: generated data, hidden from helm-docs, keyed by
    the product-namespaced rule name.
    """
    lines = [
        "# ruleApplicability records, per constrained rule, which cluster facts",
        "# it requires. Consulted by cr.applicabilityPreflight",
        "# (auto-generated; regenerated by the generator).",
        "# @ignored",
        "ruleApplicability:",
    ]
    emitted = 0
    for name in sorted(appl):
        if name not in layer_rules:
            continue
        app = appl[name]
        lines.append(f"  {name}:")
        if app.never:
            reason = "; ".join(app.reasons) or "not applicable to any supported target"
            lines.append(f"    never: {_yaml_scalar(reason)}")
        else:
            arch = app.constraints.get(applicability.AXIS_ARCH)
            if arch is not None:
                lines.append(f"    arch: [{', '.join(sorted(arch))}]")
            hs = app.constraints.get(applicability.AXIS_HYPERSHIFT)
            if hs is not None:
                lines.append(f"    hypershift: [{', '.join(str(v).lower() for v in sorted(hs, key=repr))}]")
        emitted += 1
    if not emitted:
        return "\n".join(lines[:-1] + ["ruleApplicability: {}"])
    return "\n".join(lines)


def _cluster_block(indent: str = "") -> list[str]:
    """Facts about the target cluster, used to evaluate rule applicability.

    These are the CPE leaves the user can declare at install time. Everything
    else in an upstream `<platform>` expression is an assumption documented in
    applicability.FACTS. Emitted into both charts even though today only the
    node chart consults `architecture` and only the platform chart consults
    `hypershift`: the schema forbids unknown keys inside `cluster`, so a shared
    values file has to validate against either chart.
    """
    lines = [
        "# -- Facts about the target cluster. Rules that upstream marks as not",
        "# applicable to this cluster are refused rather than silently shipped.",
        "cluster:",
        "  # -- Target OpenShift version; selects version-dependent remediations.",
        "  # Find yours: oc get clusterversion version -o jsonpath='{.status.desired.version}'",
        f'  ocpVersion: "{DEFAULT_OCP_VERSION}"',
        "  # -- Node architecture of the MachineConfigPools listed in node.roles.",
        "  # x86_64 | aarch64 | ppc64le | s390x (amd64 and arm64 are accepted too).",
        "  # Find yours: make show-node-arch",
        "  architecture: x86_64",
        "  # -- Set true on a HyperShift hosted cluster (hosted control plane).",
        "  hypershift: false",
    ]
    return [f"{indent}{line}" if line else line for line in lines]


PREFLIGHT_TPL = """\
{{- /*
  Applicability preflight. Renders nothing; aborts when an active rule is one
  the Compliance Operator would report as notapplicable for this cluster.
*/ -}}
{{- include "cr.applicabilityPreflight" . -}}
"""


def _excluded_for_arch(appl: dict, layer_rules: set, arch: str) -> dict[str, str]:
    """helm_name -> reason, for rules this architecture cannot use."""
    out: dict[str, str] = {}
    for name in sorted(appl):
        if name not in layer_rules:
            continue
        app = appl[name]
        if app.never:
            continue
        allowed = app.constraints.get(applicability.AXIS_ARCH)
        if allowed is not None and arch not in allowed:
            out[name] = f"not applicable on {arch}"
    return out


def _arch_overlay(arch: str, excluded: dict[str, str], content_version: str) -> str:
    """A ready-made values file for a non-default architecture.

    The preflight refuses non-applicable rules rather than skipping them, so a
    profile that selects any of them needs them switched off. Hand-maintaining
    that list would go stale on every content bump; generating it does not.
    """
    lines = [
        f"# Overlay for {arch} nodes.",
        f"# Generated from ComplianceAsCode/content v{content_version}.",
        "#",
        f"# Upstream marks these rules as not applicable on {arch}, so the chart",
        "# refuses to render them. Apply this file to switch them off in one go:",
        f"#   helm install <release> <chart> -f values-{arch}.yaml",
        "cluster:",
        f"  architecture: {arch}",
        "rules:",
    ]
    for name, why in excluded.items():
        lines.append(f"  {name}: false  # {why}")
    return "\n".join(lines) + "\n"


def values_yaml(contents: list[Content], layer: str, content_version: str,
                appl: dict | None = None) -> str:
    appl = appl if appl is not None else applicability.build_map(contents)
    profiles = _profiles_with_layer(contents, layer)
    variables = _variables_block(contents)
    out = [
        f"# Values for the {PLATFORM_CHART if layer == 'platform' else NODE_CHART} chart.",
        f"# Generated from ComplianceAsCode/content v{content_version}.",
        "",
        *_cluster_block(),
        "",
        "# -- Whitelist whole compliance profiles (product-namespaced, e.g. ocp4-cis).",
        "profiles:",
    ]
    for p in profiles:
        out.append(f"  {p}: false")
    if layer == "node":
        out += [
            "",
            "# -- Node remediations trigger MachineConfigPool rollouts (node reboots).",
            "# Disabled by default; opt in explicitly.",
            "node:",
            "  # -- Master enable switch for node remediations.",
            "  enabled: false",
            "  # -- MachineConfigPool roles to target. On combined master+worker nodes",
            "  # (SNO/OKD) the node lands in the master pool, so include master there.",
            "  roles:",
            "    - worker",
            "    - master",
        ]
    out += [
        "",
        "# -- Per-rule override / blacklist. Explicit value wins over profiles.",
        "# Key is the product-namespaced rule name, e.g. ocp4-audit_profile_set: false",
        "# Pre-populated below with two kinds of entry: for each group of",
        "# mutually-exclusive alternatives the losers are disabled so whitelisting a",
        "# whole profile renders out of the box (flip these to choose a different",
        "# alternative), and rules upstream marks as never applicable to this target.",
    ]
    disabled = dict(default_disabled_rules(contents))
    disabled.update(applicability.never_applicable_rules(appl))
    layer_rules = {r.helm_name for c in contents for r in rules_with_fixes(c).values()
                   if _rule_layer(r) == layer}
    layer_disabled = {r: why for r, why in disabled.items() if r in layer_rules}
    if layer_disabled:
        out.append("rules:")
        for r in sorted(layer_disabled):
            out.append(f"  {r}: false  # {layer_disabled[r]}")
    else:
        out.append("rules: {}")
    out += [
        "",
        "# -- Optionally render a matching TailoredProfile per enabled profile so the",
        "# Compliance Operator scans exactly this selection.",
        "tailoredProfile:",
        "  enabled: false",
        "",
        "# -- Namespace the Compliance Operator watches for TailoredProfiles.",
        "complianceNamespace: openshift-compliance",
        "",
        "# -- Tunable XCCDF variables (pre-filled with upstream defaults).",
        "variables:",
    ]
    # Only variables referenced by this layer's rules matter, but emitting all
    # is harmless and keeps both charts consistent.
    out.extend(f"  {n}: {_yaml_scalar(variables[n])}" for n in sorted(variables))
    out += ["", _profile_rules_block(contents, layer)]
    out += ["", _profile_variables_block(contents, layer)]
    out += ["", _rule_applicability_block(appl, layer_rules)]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# object templates
# --------------------------------------------------------------------------- #
def object_template(group: MergeGroup) -> str:
    key = group.key
    all_rules = group.rule_ids
    rules_literal = " ".join(f'"{r}"' for r in all_rules)
    is_node = key.layer == "node"
    conflicts = group.conflicts()

    lines: list[str] = []

    # Per-rule fragment named templates.
    for idx, doc in enumerate(group.docs):
        body = _fragment_body(doc.yaml)
        if not body:
            continue
        body = rewrite_placeholders(body)
        name = _tpl_name(key.slug(), doc.rule_id, idx)
        lines.append(f'{{{{- define "{name}" -}}}}')
        lines.append(body)
        lines.append("{{- end -}}")
        lines.append("")

    comment = f"{key.kind}/{key.name} - rule(s): {', '.join(all_rules)}"
    lines.append(f"{{{{- /* {comment} */ -}}}}")

    gate = f'eq (include "cr.anyActive" (dict "root" . "rules" (list {rules_literal}))) "true"'
    if is_node:
        gate = f'and (.Values.node.enabled) ({gate})'
    lines.append(f"{{{{- if {gate} -}}}}")

    # Conflict fail-guards: abort if >1 of a conflicting rule set is active.
    for c in conflicts:
        clit = " ".join(f'"{r}"' for r in c.rules)
        lines.append(
            '{{- if gt (int (include "cr.countActive" '
            f'(dict "root" . "rules" (list {clit})))) 1 -}}}}'
        )
        msg = (f"Conflicting compliance rules active for {key.kind}/{key.name} "
               f"at {c.path}: {', '.join(c.rules)}. These are mutually-exclusive "
               f"alternatives - enable only one.")
        lines.append(f'{{{{- fail {_go_str(msg)} -}}}}')
        lines.append("{{- end -}}")

    lines.append("{{- $merged := dict -}}")
    for idx, doc in enumerate(group.docs):
        if not _fragment_body(doc.yaml):
            continue
        name = _tpl_name(key.slug(), doc.rule_id, idx)
        cond = f'eq (include "cr.ruleActive" (dict "root" . "rule" "{doc.rule_id}")) "true"'
        if doc.ocp_version:
            cond = f'and ({cond}) ({_ocp_semver_expr(doc.ocp_version)})'
        lines.append(f"{{{{- if {cond} -}}}}")
        lines.append(f'{{{{- $frag := include "{name}" . | fromYaml -}}}}')
        lines.append("{{- $merged = mustMergeOverwrite $merged $frag -}}")
        lines.append("{{- end -}}")

    # Every fragment gated off leaves $merged empty, and `$merged | toYaml`
    # then writes a bare `{}` at document level - invalid YAML, which Helm
    # reports as "did not find expected key" without naming a cause. Fail with
    # the reason instead: an active rule that cannot be rendered is an error,
    # not something to paper over.
    msg = (f"No remediation applies to {key.kind}/{key.name} at "
           f"cluster.ocpVersion %s. Every fix variant of the active rule(s) "
           f"({', '.join(all_rules)}) is constrained to a different OpenShift "
           f"version. Disable the rule(s) or set a supported cluster.ocpVersion.")
    lines.append("{{- if not $merged -}}")
    lines.append(f'{{{{- fail (printf {_go_str(msg)} '
                 '(.Values.cluster.ocpVersion | toString)) -}}')
    lines.append("{{- end -}}")

    # Render the object, one per node role for node objects.
    if is_node:
        lines.append("{{- range $role := (.Values.node.roles | uniq) }}")
        lines.append("---")
        lines.append(f"apiVersion: {key.api_version}")
        lines.append(f"kind: {key.kind}")
        lines.append("metadata:")
        lines.append(f'  name: {{{{ printf "%s-%s" {_go_str(key.name)} $role }}}}')
        lines.append("  labels:")
        lines.append('    app.kubernetes.io/managed-by: {{ $.Release.Service | quote }}')
        lines.append('    compliance.openshift.io/managed: "true"')
        lines.append('    machineconfiguration.openshift.io/role: {{ $role | quote }}')
        lines.append("{{ $merged | toYaml }}")
        lines.append("{{- end }}")
    else:
        lines.append("---")
        lines.append(f"apiVersion: {key.api_version}")
        lines.append(f"kind: {key.kind}")
        lines.append("metadata:")
        lines.append(f"  name: {key.name}")
        if key.namespace:
            lines.append(f"  namespace: {key.namespace}")
        lines.append("  labels:")
        lines.append('    app.kubernetes.io/managed-by: {{ .Release.Service | quote }}')
        lines.append('    compliance.openshift.io/managed: "true"')
        lines.append("{{ $merged | toYaml }}")
    lines.append("{{- end -}}")
    return "\n".join(lines) + "\n"


def _go_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------- #
# TailoredProfile layer (optional)
# --------------------------------------------------------------------------- #
def tailored_profile_template(contents: list[Content], layer: str) -> str:
    """Render one TailoredProfile per enabled base profile of this layer.

    Gated by .Values.tailoredProfile.enabled. disableRules come from blacklisted
    rules the profile selects; setValues come from the variables the profile's
    rules actually reference, product-prefixed and hyphenated to match what the
    Compliance Operator expects (e.g. ocp4-var-openshift-audit-profile). A
    product-type annotation (Node/Platform) routes the scan correctly.
    """
    profiles = _profiles_with_layer(contents, layer)
    product_type = "Node" if layer == "node" else "Platform"
    lines = [
        "{{- /* Optional TailoredProfiles: one per enabled base profile. */ -}}",
        "{{- if .Values.tailoredProfile.enabled -}}",
        f"{{{{- $profiles := list {' '.join(_go_str(p) for p in profiles)} -}}}}",
        "{{- $root := . -}}",
        "{{- range $profile := $profiles -}}",
        '{{- if index $root.Values.profiles $profile -}}',
        "{{- $ruleList := index $root.Values.profileRules $profile | default (list) -}}",
        "{{- $varList := index $root.Values.profileVariables $profile | default (list) -}}",
        '{{- $product := (splitList "-" $profile | first) -}}',
        "---",
        "apiVersion: compliance.openshift.io/v1alpha1",
        "kind: TailoredProfile",
        "metadata:",
        '  name: {{ printf "hardening-%s" $profile }}',
        "  namespace: {{ $root.Values.complianceNamespace | quote }}",
        "  labels:",
        '    app.kubernetes.io/managed-by: {{ $root.Release.Service | quote }}',
        "  annotations:",
        f'    compliance.openshift.io/product-type: "{product_type}"',
        "spec:",
        '  extends: {{ $profile | quote }}',
        '  title: {{ printf "Hardening-managed selection of %s" $profile | quote }}',
        '  description: >-',
        "    Rule selection managed by the compliance-hardening Helm chart.",
        "  {{- $disabled := list -}}",
        "  {{- range $rule := $ruleList -}}",
        '  {{- if hasKey $root.Values.rules $rule -}}',
        "  {{- if not (index $root.Values.rules $rule) -}}",
        "  {{- $disabled = append $disabled $rule -}}",
        "  {{- end -}}{{- end -}}{{- end -}}",
        "  {{- if $disabled }}",
        "  disableRules:",
        "  {{- range $rule := $disabled }}",
        '    - name: {{ $rule | replace "_" "-" | quote }}',
        '      rationale: "Disabled via compliance-hardening chart values"',
        "  {{- end }}",
        "  {{- end }}",
        "  {{- if $varList }}",
        "  setValues:",
        "  {{- range $var := $varList }}",
        "  {{- if hasKey $root.Values.variables $var }}",
        '    - name: {{ printf "%s-%s" $product ($var | replace "_" "-") | quote }}',
        "      value: {{ index $root.Values.variables $var | quote }}",
        '      rationale: "Set via compliance-hardening chart values"',
        "  {{- end }}",
        "  {{- end }}",
        "  {{- end }}",
        "{{- end -}}",
        "{{- end -}}",
        "{{- end -}}",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #
def generate_charts(contents: dict[str, Content], charts_dir: Path, version: str,
                    chart_version: str = "0.0.0") -> dict:
    """Generate both standalone charts + the umbrella. Returns a stats dict.

    ``chart_version`` is the released Helm chart version (from the VERSION
    file, maintained by semantic-release); ``version`` is the upstream content
    version and becomes appVersion.
    """
    content_list = list(contents.values())
    groups, unparseable = build_groups(*content_list)

    appl = applicability.build_map(content_list)
    stats = {"platform": 0, "node": 0, "unparseable": [d.rule_id for d in unparseable],
             "conflicts": [], "dropped": [],
             "applicability": applicability.summarize(appl)}

    _write_layer_chart(charts_dir / PLATFORM_CHART, PLATFORM_CHART,
                       "OpenShift platform compliance remediations (no reboot).",
                       content_list, groups, "platform", version, stats, appl,
                       chart_version)
    _write_layer_chart(charts_dir / NODE_CHART, NODE_CHART,
                       "OpenShift node compliance remediations (MachineConfig/KubeletConfig; reboots).",
                       content_list, groups, "node", version, stats, appl,
                       chart_version)
    _write_umbrella_chart(charts_dir / UMBRELLA_CHART, version, chart_version)

    for g in groups:
        for c in g.conflicts():
            stats["conflicts"].append(f"{g.key.kind}/{g.key.name}:{c.path}")
    return stats


def _write_umbrella_chart(chart_dir: Path, version: str,
                          chart_version: str = "0.0.0") -> None:
    """Umbrella wrapper depending on both subcharts. No `global`: values are
    prefixed per subchart. Subcharts remain standalone-installable."""
    chart_dir.mkdir(parents=True, exist_ok=True)
    (chart_dir / "templates").mkdir(parents=True, exist_ok=True)
    # .helmignore keeps subchart tests out of the packaged umbrella.
    (chart_dir / ".helmignore").write_text("tests/\n", encoding="utf-8")

    chart = f"""\
apiVersion: v2
name: {UMBRELLA_CHART}
description: >-
  Umbrella chart bundling OpenShift compliance remediations: platform config
  (no reboot) and node MachineConfig/KubeletConfig (reboots, opt-in).
type: application
version: {chart_version}
appVersion: "{version}"
dependencies:
  - name: {PLATFORM_CHART}
    version: "{chart_version}"
    repository: "file://../{PLATFORM_CHART}"
  - name: {NODE_CHART}
    version: "{chart_version}"
    repository: "file://../{NODE_CHART}"
"""
    (chart_dir / "Chart.yaml").write_text(chart, encoding="utf-8")

    values = f"""\
# Umbrella values. Configure each subchart under its own prefix (no global).
# Subcharts are also installable standalone.

# -- Platform remediations (safe cluster config, no reboot).
{PLATFORM_CHART}:
{_indent_block(_cluster_block(), 2)}
  profiles: {{}}
  rules: {{}}
  tailoredProfile:
    enabled: false

# -- Node remediations (MachineConfig/KubeletConfig; trigger reboots).
{NODE_CHART}:
{_indent_block(_cluster_block(), 2)}
  node:
    enabled: false
    roles:
      - worker
      - master
  profiles: {{}}
  rules: {{}}
  tailoredProfile:
    enabled: false
"""
    (chart_dir / "values.yaml").write_text(values, encoding="utf-8")


def _write_layer_chart(chart_dir: Path, name: str, description: str,
                       contents: list[Content], groups, layer: str,
                       version: str, stats: dict, appl: dict,
                       chart_version: str = "0.0.0") -> None:
    import shutil
    tpl = chart_dir / "templates"
    # Clean only templates/ so hand-written tests/ and Chart metadata survive.
    if tpl.exists():
        shutil.rmtree(tpl)
    tpl.mkdir(parents=True, exist_ok=True)
    (chart_dir / "Chart.yaml").write_text(
        chart_yaml(name, description, version, chart_version), encoding="utf-8")
    (chart_dir / "values.yaml").write_text(
        values_yaml(contents, layer, version, appl), encoding="utf-8")
    (chart_dir / "values.schema.json").write_text(
        values_schema(contents, layer), encoding="utf-8")
    (chart_dir / "README.md.gotmpl").write_text(README_GOTMPL, encoding="utf-8")
    (tpl / "_helpers.tpl").write_text(HELPERS_TPL, encoding="utf-8")
    (tpl / "applicability.yaml").write_text(PREFLIGHT_TPL, encoding="utf-8")

    # One ready-made overlay per architecture that has exclusions. Stale
    # overlays are removed so a content bump cannot leave one behind.
    layer_rules = {r.helm_name for c in contents for r in rules_with_fixes(c).values()
                   if _rule_layer(r) == layer}
    for arch in applicability.ARCHITECTURES:
        overlay = chart_dir / f"values-{arch}.yaml"
        excluded = _excluded_for_arch(appl, layer_rules, arch)
        if excluded:
            overlay.write_text(_arch_overlay(arch, excluded, version), encoding="utf-8")
        elif overlay.exists():
            overlay.unlink()

    for g in groups:
        if g.key.layer != layer:
            continue
        if not any(_fragment_body(d.yaml) for d in g.docs):
            # No recognized content body (e.g. an unexpected top-level key from
            # a future content release). Record it so it is not silently lost.
            for rid in g.rule_ids:
                stats.setdefault("dropped", []).append(
                    f"{rid} -> {g.key.kind}/{g.key.name}")
            continue
        (tpl / f"{g.key.slug()}.yaml").write_text(object_template(g), encoding="utf-8")
        stats[layer] += 1

    # Optional TailoredProfile layer.
    (tpl / "tailoredprofile.yaml").write_text(
        tailored_profile_template(contents, layer), encoding="utf-8")


# --------------------------------------------------------------------------- #
# values.schema.json
# --------------------------------------------------------------------------- #
def values_schema(contents: list[Content], layer: str) -> str:
    """Emit a JSON Schema constraining profiles/rules to known keys.

    Helm validates values against values.schema.json at lint/template/install
    time, so a typo like ``profiles.ocp4-ciss`` fails loudly instead of being a
    silent no-op.
    """
    import json

    profiles = _profiles_with_layer(contents, layer)
    rule_names = sorted({
        r.helm_name for c in contents for r in rules_with_fixes(c).values()
        if _rule_layer(r) == layer
    })
    var_names = sorted(_variables_block(contents))

    profile_props = {p: {"type": "boolean"} for p in profiles}
    rule_props = {r: {"type": "boolean"} for r in rule_names}
    var_props = {v: {"type": ["string", "number"]} for v in var_names}

    schema = {
        "$schema": "https://json-schema.org/draft-07/schema#",
        "title": f"{PLATFORM_CHART if layer == 'platform' else NODE_CHART} values",
        "type": "object",
        "properties": {
            "cluster": {
                "type": "object",
                "properties": {
                    "ocpVersion": {
                        "type": "string",
                        "pattern": r"^[0-9]+\.[0-9]+(\.[0-9]+)?$",
                    },
                    "architecture": {
                        "type": "string",
                        "enum": sorted(applicability.ARCHITECTURES)
                                + sorted(applicability.ARCH_ALIASES),
                    },
                    "hypershift": {"type": "boolean"},
                },
                # `required` is not cosmetic: a null architecture would make
                # every membership test false and silently disable every
                # arch-constrained rule. Helm has to reject that at lint time.
                "required": ["ocpVersion", "architecture", "hypershift"],
                "additionalProperties": False,
            },
            "complianceNamespace": {"type": "string"},
            "tailoredProfile": {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
                "additionalProperties": False,
            },
            # Reject unknown profile / rule keys (typo protection).
            "profiles": {
                "type": "object",
                "properties": profile_props,
                "additionalProperties": False,
            },
            "rules": {
                "type": "object",
                "properties": rule_props,
                "additionalProperties": False,
            },
            "variables": {
                "type": "object",
                "properties": var_props,
                "additionalProperties": False,
            },
            # profileRules / profileVariables are generator-managed data maps.
            "profileRules": {"type": "object"},
            "profileVariables": {"type": "object"},
        },
        "additionalProperties": True,
    }
    if layer == "node":
        schema["properties"]["node"] = {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "roles": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        }
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


# --------------------------------------------------------------------------- #
# RULES.md matrix
# --------------------------------------------------------------------------- #
def rules_matrix(contents: dict[str, Content], version: str,
                 appl: dict | None = None) -> str:
    """Build a markdown matrix: rule | target object | severity | layer |
    product | applicability | profiles, with alternatives and non-applicable
    rules marked."""
    content_list = list(contents.values())
    groups, _ = build_groups(*content_list)
    appl = appl if appl is not None else applicability.build_map(content_list)

    # rule helm-name -> target object + conflict flag
    target_of: dict[str, str] = {}
    conflicting: set[str] = set()
    for g in groups:
        for d in g.docs:
            target_of.setdefault(d.rule_id, f"{g.key.kind}/{g.key.name}")
        for c in g.conflicts():
            conflicting.update(c.rules)

    # Detect upstream-broken fixes: a tlsSecurityProfile written with a
    # capitalized `Custom:` block but no sibling `type:` - the OpenShift API
    # ignores it, so selecting this alternative is a silent no-op.
    # Rules upstream restricts to the master pool. The layer split routes them
    # into the node chart but still renders them for every role in node.roles,
    # so report it rather than leaving the divergence invisible.
    master_only: set[str] = set()
    for content in content_list:
        for rule in rules_with_fixes(content).values():
            if any(r.lstrip("#") == "ocp4-master-node" for r in rule.all_platforms):
                master_only.add(rule.helm_name)

    broken: set[str] = set()
    for content in content_list:
        for rule in rules_with_fixes(content).values():
            for fix in rule.fixes:
                y = fix.yaml
                if re.search(r"(?m)^\s*Custom:\s*$", y) and not re.search(
                    r"(?m)^\s*type:\s*Custom\s*$", y
                ):
                    broken.add(rule.helm_name)

    # rule helm-name -> sorted profile list
    profiles_of: dict[str, list[str]] = {}
    for content in content_list:
        fixset = set(rules_with_fixes(content))
        for pid, prof in content.profiles.items():
            for r in prof.selected_rules:
                if r in fixset:
                    hn = f"{content.product}-{r}"
                    profiles_of.setdefault(hn, [])
                    if pid not in profiles_of[hn]:
                        profiles_of[hn].append(pid)

    rows = []
    for content in content_list:
        for _rid, rule in sorted(rules_with_fixes(content).items()):
            hn = rule.helm_name
            layer = _rule_layer(rule)
            target = target_of.get(hn, "?")
            profs = ", ".join(sorted(profiles_of.get(hn, [])))
            marks = []
            if hn in conflicting:
                marks.append("⚠️ alt")
            if hn in broken:
                marks.append("⛔ broken")
            app = appl.get(hn)
            if app is not None and app.never:
                marks.append("⛔ n/a")
            mark = (" " + " ".join(marks)) if marks else ""
            applies = applicability.describe(app) if app is not None else "-"
            if hn in master_only:
                applies = "master pool only" if applies == "-" \
                    else f"{applies}; master pool only"
            rows.append(
                f"| `{hn}`{mark} | `{target}` | {rule.severity or '-'} | "
                f"{layer} | {content.product} | {applies} | {profs} |"
            )

    header = [
        "# Rules matrix",
        "",
        f"Generated from ComplianceAsCode/content v{version}. Do not edit by hand; "
        "regenerate with `make generate` (or `compliance-remediations-gen`).",
        "",
        "One row per rule that carries a Kubernetes remediation. Rules marked "
        "**⚠️ alt** are mutually-exclusive alternatives: enabling more than one "
        "that targets the same object makes the chart fail - pick one. Rules "
        "marked **⛔ broken** reproduce an upstream fix that the OpenShift API "
        "ignores (e.g. a `Custom:` TLS block without `type: Custom`) - selecting "
        "them is a no-op; prefer the non-broken alternative in the same group.",
        "",
        "The **Applicability** column carries the upstream `<platform>` constraint. "
        "The Compliance Operator evaluates these at scan time and reports a "
        "non-applicable rule as `notapplicable`, generating no remediation; the "
        "charts refuse to render one instead of shipping it. Architecture and "
        "HyperShift are declared via `cluster.architecture` and "
        "`cluster.hypershift`; for a non-default architecture apply the generated "
        "`values-<arch>.yaml` overlay. Rules marked **⛔ n/a** are never "
        "applicable to RHCOS/OKD at all and ship disabled - enable one explicitly "
        "only if you know the assumption behind it does not hold for you.",
        "",
        "| Rule | Target object | Severity | Layer | Product | Applicability | Profiles |",
        "|------|---------------|----------|-------|---------|---------------|----------|",
    ]
    return "\n".join(header + rows) + "\n"

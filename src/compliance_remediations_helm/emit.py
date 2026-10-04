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

import json
import re
from pathlib import Path

from . import applicability, classify, resolver
from .collisions import MergeGroup, build_groups
from .parser import Content, rules_with_fixes
from .resolver import resolve_defaults, rewrite_placeholders

PLATFORM_CHART = "compliance-platform"
NODE_CHART = "compliance-node"
UMBRELLA_CHART = "compliance-hardening"

DEFAULT_OCP_VERSION = "4.20"
DEFAULT_ARCHITECTURE = "x86_64"


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

See [`RULES.md`](../../RULES.md) for the full rule-to-profile matrix.

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
{{- fail (printf "%d active rule(s) are not applicable to this cluster:\\n%s\\n%s" (len $bad) (join "\\n" (sortAlpha $bad)) $hint) -}}
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
{{- fail (printf "%d active rule(s) have an unmet dependency:\\n%s\\nUpstream marks these with complianceascode.io/depends-on; enable the dependency, or disable the rule that needs it." (len $bad) (join "\\n" (sortAlpha $bad))) -}}
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
{{- fail (printf "%d active rule(s) reproduce an upstream fix that cannot work:\\n%s\\nPrefer the non-broken alternative in the same group; see RULES.md." (len $bad) (join "\\n" (sortAlpha $bad))) -}}
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
    layer_profiles = set(_profiles_with_layer(contents, layer))
    for content in contents:
        fixset = set(rules_with_fixes(content))
        for pid in sorted(p for p in content.profiles if p in layer_profiles):
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
    """Map each profile to the variables its fix-rules reference (scopes TP setValues).

    Uses the same extraction as the rest of the generator: matching only the
    plain `{{.var_x}}` form missed every percent-encoded reference - 22 of the
    40 variables - so a TailoredProfile left those unset and the operator
    scanned against upstream defaults while the chart applied ours.
    """
    lines = [
        "# profileVariables maps each profile to the XCCDF variables its rules use",
        "# (auto-generated; scopes TailoredProfile setValues).",
        "# @ignored",
        "profileVariables:",
    ]
    layer_profiles = set(_profiles_with_layer(contents, layer))
    for content in contents:
        fixset = rules_with_fixes(content)
        for pid in sorted(p for p in content.profiles if p in layer_profiles):
            prof = content.profiles[pid]
            used: set[str] = set()
            for r in prof.selected_rules:
                rule = fixset.get(r)
                if rule and _rule_layer(rule) == layer:
                    for fix in rule.fixes:
                        used.update(resolver.variables_in_fix(fix.yaml))
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


def rule_dependencies(contents: list[Content], layer_rules: set) -> dict[str, list[str]]:
    """helm_name -> the rules upstream says must be applied with it.

    Only dependencies that are themselves fix-carrying rules in this layer can
    be checked: cr.ruleActive resolves a rule through profileRules and the
    rules override, and both only carry rules this chart emits. A dependency
    outside that set is reported by the CLI rather than silently dropped.
    """
    out: dict[str, list[str]] = {}
    for content in contents:
        for rule in rules_with_fixes(content).values():
            if rule.helm_name not in layer_rules:
                continue
            deps = [f"{content.product}-{d}" for d in rule.depends_on]
            checkable = [d for d in deps if d in layer_rules]
            if checkable:
                out[rule.helm_name] = sorted(checkable)
    return out


def unverifiable_dependencies(contents: list[Content]) -> list[str]:
    """Dependencies no chart can check.

    Two ways that happens: the dependency carries no Kubernetes fix, so no
    chart emits it at all; or it is emitted but in the *other* layer, and
    cr.ruleActive only ever resolves rules of its own chart. The layer split is
    this generator's own invention, so upstream has no reason to respect it -
    and RULES.md prints `requires <rule>` either way, which would be a claim
    the preflight cannot keep.
    """
    by_layer: dict[str, set[str]] = {}
    for content in contents:
        for rule in rules_with_fixes(content).values():
            by_layer.setdefault(_rule_layer(rule), set()).add(rule.helm_name)
    emitted = set().union(*by_layer.values()) if by_layer else set()

    missing = []
    for content in contents:
        for rule in rules_with_fixes(content).values():
            layer = _rule_layer(rule)
            for dep in rule.depends_on:
                name = f"{content.product}-{dep}"
                if name not in emitted:
                    missing.append(f"{rule.helm_name} -> {name} (no Kubernetes fix)")
                elif name not in by_layer.get(layer, set()):
                    missing.append(
                        f"{rule.helm_name} ({layer}) -> {name} (other layer)")
    return sorted(missing)


def _broken_rules_block(broken: dict[str, str], layer_rules: set) -> str:
    lines = [
        "# brokenRules records rules whose upstream fix cannot work as written",
        "# (auto-generated; regenerated by the generator).",
        "# @ignored",
        "brokenRules:",
    ]
    emitted = [n for n in sorted(broken) if n in layer_rules]
    if not emitted:
        return "\n".join(lines[:-1] + ["brokenRules: {}"])
    for name in emitted:
        lines.append(f"  {name}: {_yaml_scalar(broken[name])}")
    return "\n".join(lines)


def _rule_dependencies_block(deps: dict[str, list[str]]) -> str:
    lines = [
        "# ruleDependencies records which rules upstream marks as required by",
        "# another (complianceascode.io/depends-on). Consulted by",
        "# cr.dependencyPreflight (auto-generated; regenerated by the generator).",
        "# @ignored",
        "ruleDependencies:",
    ]
    if not deps:
        return "\n".join(lines[:-1] + ["ruleDependencies: {}"])
    for name in sorted(deps):
        lines.append(f"  {name}:")
        lines.extend(f"    - {d}" for d in deps[name])
    return "\n".join(lines)


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
        if not app.gated:
            # Role-only restrictions are handled by not rendering the object
            # for that role, the way the operator never produces the
            # remediation for a pool it did not scan. Nothing to refuse.
            continue
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


# Rules that ship disabled and need an explicit opt-in, because applying them
# by whitelisting a profile can take a node or a cluster down. This is our
# judgement, not an upstream constraint - unlike applicability, nothing in the
# content says these should not be applied. Each entry carries the reason, it
# appears in RULES.md, and flipping it to true is one line.
#
# The bar is deliberately high: only rules whose failure mode is loss of the
# node or of the access needed to fix it. Everything else stays on, because a
# chart that silently waters down the profile it claims to implement is worse
# than one that reboots a node.
OPT_IN_RULES: dict[str, str] = {
    "ocp4-kubelet_enable_protect_kernel_defaults":
        "kubelet refuses to start if the kernel parameters it expects are not "
        "already set; nodes go NotReady pool by pool",
    "rhcos4-service_sshd_disabled":
        "masks sshd.service and sshd.socket, removing the recovery path into "
        "a node when the API is not enough",
    "rhcos4-coreos_nousb_kernel_argument":
        "boots with nousb; on bare metal that disables USB keyboards, so the "
        "console stops being a way back in",
    "rhcos4-coreos_page_poison_kernel_argument":
        "page_poison=1 carries a measurable runtime cost - a deliberate "
        "trade-off rather than something to inherit from a profile",
}


def broken_rules(contents: list[Content]) -> dict[str, str]:
    """helm_name -> why the fix cannot work as written.

    Upstream writes `tlsSecurityProfile` with a capitalized `Custom:` block and
    no sibling `type:`. `Custom` is not a field - the API server prunes it
    against the structural schema - so the object applies cleanly and changes
    nothing. Validated against the genuine CRDs from openshift/api release-4.20
    and independently with kubeconform:

        at '/spec/tlsSecurityProfile': additional properties 'Custom' not allowed
    """
    out: dict[str, str] = {}
    for content in contents:
        for rule in rules_with_fixes(content).values():
            for fix in rule.fixes:
                y = fix.yaml
                if re.search(r"(?m)^\s*Custom:\s*$", y) and not re.search(
                    r"(?m)^\s*type:\s*Custom\s*$", y
                ):
                    out[rule.helm_name] = (
                        "upstream writes tlsSecurityProfile.Custom, which is not "
                        "a field; the API server prunes it and the remediation "
                        "does nothing")
    return out


def _labels_block(ref: str, component: str, role: str | None = None) -> list[str]:
    """The metadata.labels block every rendered object carries.

    `ref` is the Go template root expression at the call site, without the
    trailing dot: "$" inside a `range`, "" at the top level, "$root" in the
    TailoredProfile loop.

    Only the Kubernetes recommended set, deliberately. A marker of our own
    under `compliance.openshift.io/` squats in the Compliance Operator's key
    space, and it answered none of the questions one actually has in a cluster
    where our object names collide with the operator's by design: which chart,
    which release, what kind of object. `part-of` is the selector, and a
    literal rather than a template so it reads the same standalone and under
    the umbrella. No `version` label: it would rewrite the labels of every
    object on every release without making anything selectable.

    `role` adds the MCO pool selector. That one is functional, not
    descriptive - without it a MachineConfig belongs to no pool.
    """
    lines = [
        "  labels:",
        f"    app.kubernetes.io/name: {{{{ {ref}.Chart.Name | quote }}}}",
        f"    app.kubernetes.io/instance: "
        f'{{{{ {ref}.Release.Name | trunc 63 | trimSuffix "-" | quote }}}}',
        f"    app.kubernetes.io/component: {component}",
        f"    app.kubernetes.io/part-of: {UMBRELLA_CHART}",
        f"    app.kubernetes.io/managed-by: {{{{ {ref}.Release.Service | quote }}}}",
    ]
    if role is not None:
        lines.append(
            f"    machineconfiguration.openshift.io/role: {{{{ {role} | quote }}}}")
    return lines


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
        "  # Only the node chart has arch-constrained rules; it is declared here",
        "  # too so one values file validates against either chart.",
        "  # x86_64 | aarch64 | ppc64le | s390x (amd64 and arm64 are accepted too).",
        "  # Find yours: make show-node-arch",
        f"  architecture: {DEFAULT_ARCHITECTURE}",
        "  # -- Set true on a HyperShift hosted cluster (hosted control plane).",
        "  # Only the platform chart has a hypershift-constrained rule.",
        "  hypershift: false",
    ]
    return [f"{indent}{line}" if line else line for line in lines]


def _file_entries(doc_yaml: str) -> dict[str, str]:
    """path -> contents.source, for every file an Ignition fix writes.

    Regex rather than a YAML parse because the generator is stdlib-only, and
    all this needs is to compare two sources for equality.
    """
    body = _fragment_body(doc_yaml)
    m = re.search(r"(?m)^\s*files:\s*$", body)
    if not m:
        return {}
    out: dict[str, str] = {}
    for item in re.split(r"(?m)^\s+-\s", body[m.end():])[1:]:
        path = re.search(r"(?m)^\s*path:\s*(\S+)", item)
        source = re.search(r"(?m)^\s*source:\s*(.+)$", item)
        if path and source:
            out[path.group(1)] = source.group(1).strip()
    return out


def cross_object_file_conflicts(groups, layer: str) -> list[dict]:
    """Paths that two different objects write with different content.

    The collision detector works inside one object. Across objects the MCO
    decides, and it merges alphanumerically, so the later MachineConfig wins
    silently. Upstream's sshd drop-ins make this reachable: `enable` and
    `disable` variants of the same setting are separate rules writing the same
    file, which makes them mutually-exclusive alternatives that no per-object
    check can see.

    The conflict is between *content groups*, not between every rule touching
    the path - 31 rules write the same /etc/ssh/sshd_config and are perfectly
    fine together. Each group carries the version constraints of the fragments
    in it, so a guard only fires in the window where they actually render.
    """
    by_path: dict[str, dict[str, dict[str, set]]] = {}
    for g in groups:
        if g.key.layer != layer:
            continue
        for doc in g.docs:
            for path, source in _file_entries(doc.yaml).items():
                group = by_path.setdefault(path, {}).setdefault(
                    source, {"rules": set(), "versions": set()})
                group["rules"].add(doc.rule_id)
                group["versions"].add(doc.ocp_version)

    out: list[dict] = []
    for path, by_source in sorted(by_path.items()):
        if len(by_source) < 2:
            continue
        groups_here = [
            {"rules": sorted(v["rules"]), "versions": sorted(x for x in v["versions"] if x)}
            for v in by_source.values()
        ]
        # A path only conflicts if two different rules disagree. One rule with
        # two version variants of the same file is the version gate doing its
        # job, not an alternative.
        if len({r for grp in groups_here for r in grp["rules"]}) < 2:
            continue
        out.append({"path": path, "groups": sorted(
            groups_here, key=lambda g: g["rules"])})
    return out


def preflight_template(conflicts: list[dict]) -> str:
    """The preflight: applicability, dependencies, and cross-object files."""
    lines = [
        "{{- /*",
        "  Preflight. Renders nothing; aborts when an active rule is one the",
        "  Compliance Operator would refuse to apply - because it does not apply",
        "  to this cluster, or because a rule it depends on is switched off - or",
        "  when two active rules would write the same file differently.",
        "*/ -}}",
        '{{- include "cr.applicabilityPreflight" . -}}',
        '{{- include "cr.dependencyPreflight" . -}}',
        '{{- include "cr.brokenPreflight" . -}}',
    ]
    for conflict in conflicts:
        path = conflict["path"]
        groups = conflict["groups"]
        # Active in more than one content group == the MCO would have to pick.
        active = []
        for idx, grp in enumerate(groups):
            rule_list = " ".join(_go_str(r) for r in grp["rules"])
            lines.append(
                f'{{{{- $g{idx} := int (include "cr.countActive" '
                f'(dict "root" . "rules" (list {rule_list}))) -}}}}')
            active.append(f"(gt $g{idx} 0)")
        versions = sorted({v for grp in groups for v in grp["versions"]})
        cond = " ".join(active)
        cond = f"and {cond}" if len(active) == 2 else "and " + " ".join(active)
        for v in versions:
            cond = f"and ({cond}) ({_ocp_semver_expr(v)})"
        names = " / ".join(", ".join(g["rules"]) for g in groups)
        msg = (f"Conflicting compliance rules active: {names} write {path} with "
               f"different content. They are separate objects, so nothing on the "
               f"cluster would reject this - the MachineConfig Operator merges "
               f"alphanumerically and the last one silently wins. Enable only "
               f"one side.")
        lines.append(f"{{{{- if {cond} -}}}}")
        lines.append(f"{{{{- fail {_go_str(msg)} -}}}}")
        lines.append("{{- end -}}")
    return "\n".join(lines) + "\n"




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


def _arch_overlay(arch: str, per_chart: dict, content_version: str,
                 nested: bool = False) -> str:
    """A ready-made values file for a non-default architecture.

    The preflight refuses non-applicable rules rather than skipping them, so a
    profile that selects any of them needs them switched off. Hand-maintaining
    that list would go stale on every content bump; generating it does not.

    ``nested`` produces the umbrella form, with every key under its subchart
    prefix. Without it the umbrella silently ignores the file - the values sit
    at the wrong level - and the render fails again with the same message that
    told you to apply it.
    """
    lines = [
        f"# Overlay for {arch} nodes"
        + (" (umbrella chart)." if nested else "."),
        f"# Generated from ComplianceAsCode/content v{content_version}.",
        "#",
        f"# Upstream marks these rules as not applicable on {arch}, so the chart",
        "# refuses to render them. Apply this file to switch them off in one go:",
        f"#   helm install <release> <chart> -f values-{arch}.yaml",
    ]
    indent = "  " if nested else ""
    for chart_name, excluded in sorted(per_chart.items()):
        if nested:
            lines.append(f"{chart_name}:")
        lines.append(f"{indent}cluster:")
        lines.append(f"{indent}  architecture: {arch}")
        if excluded:
            lines.append(f"{indent}rules:")
            for name, why in excluded.items():
                lines.append(f"{indent}  {name}: false  # {why}")
        if not nested:
            break
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
        "# Pre-populated below with three kinds of entry: for each group of",
        "# mutually-exclusive alternatives the losers are disabled so whitelisting a",
        "# whole profile renders out of the box (flip these to choose a different",
        "# alternative), rules upstream marks as never applicable to this target,",
        "# and rules that need an explicit opt-in because applying them can take a",
        "# node down. See RULES.md for which is which.",
    ]
    disabled = dict(default_disabled_rules(contents))
    disabled.update(applicability.never_applicable_rules(appl))
    disabled.update({r: f"opt-in: {why}" for r, why in OPT_IN_RULES.items()})
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
    out += ["", _rule_dependencies_block(rule_dependencies(contents, layer_rules))]
    out += ["", _broken_rules_block(broken_rules(contents), layer_rules)]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# object templates
# --------------------------------------------------------------------------- #
def object_template(group: MergeGroup, appl: dict | None = None) -> str:
    appl = appl or {}
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
        # sprig's fromYaml returns {"Error": "..."} instead of failing, and
        # merging that replaces the object's spec with an Error field while the
        # render exits 0 - the remediation silently gone. A variable value
        # containing YAML punctuation is enough to trigger it.
        lines.append('{{- if hasKey $frag "Error" -}}')
        lines.append(f'{{{{- fail (printf {_go_str("Rendering " + doc.rule_id + " for " + key.kind + "/" + key.name + " produced invalid YAML: %s. Check the variables it interpolates.")} $frag.Error) -}}}}')
        lines.append("{{- end -}}")
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

    # A consolidated object only holds together while the fixes it merges stay
    # identical. Check it here rather than letting the conflict detector report
    # it as "mutually-exclusive alternatives", which it is not.
    if key.name in set(classify.CONSOLIDATED_NAMES.values()):
        bodies = {_fragment_body(d.yaml) for d in group.docs if _fragment_body(d.yaml)}
        if len(bodies) > 1:
            raise ValueError(
                f"{key.kind}/{key.name} consolidates rules whose fixes are no "
                f"longer identical ({', '.join(sorted(group.rule_ids))}). Drop "
                f"them from classify.CONSOLIDATED_NAMES so each gets its own "
                f"object again."
            )

    # Node roles this object applies to, if upstream restricts it. Mirrors the
    # operator: it scans per pool and derives the MachineConfig role from the
    # scan's node selector, so a master-only remediation never reaches a
    # worker. We render per role, so the equivalent is to skip the roles it
    # does not apply to.
    role_sets = {frozenset(appl[d.rule_id].roles)
                 if d.rule_id in appl else frozenset()
                 for d in group.docs if _fragment_body(d.yaml)}
    roles = next(iter(role_sets)) if len(role_sets) == 1 else frozenset()
    if len(role_sets) > 1:
        raise ValueError(
            f"{key.kind}/{key.name} mixes rules with different node-role "
            f"restrictions ({sorted(tuple(sorted(r)) for r in role_sets)}). "
            f"Rendering it per role would need the fragment merge moved inside "
            f"the role loop; teach object_template that before this ships."
        )

    # Render the object, one per node role for node objects.
    if is_node:
        lines.append("{{- range $role := (.Values.node.roles | uniq) }}")
        if roles:
            role_list = " ".join(_go_str(r) for r in sorted(roles))
            lines.append(f"{{{{- if has $role (list {role_list}) }}}}")
        body = "$merged"
        if key.kind == "KubeletConfig":
            # A KubeletConfig without a pool selector matches NO pool - the MCO
            # treats a nil selector as "nothing, not everything" and its
            # kubelet-config controller errors out - so the object would be
            # created and then do nothing at all. The label is the one the
            # operator sets and the one the MCO puts on the built-in pools.
            # Merged per role rather than into $merged, because the label name
            # contains the role.
            lines.append(
                "{{- $selector := dict \"spec\" (dict "
                "\"machineConfigPoolSelector\" (dict \"matchLabels\" (dict "
                "(printf \"pools.operator.machineconfiguration.openshift.io/%s\" $role) "
                "\"\"))) -}}")
            lines.append("{{- $obj := mustMergeOverwrite (deepCopy $merged) $selector }}")
            body = "$obj"
        lines.append("---")
        lines.append(f"apiVersion: {key.api_version}")
        lines.append(f"kind: {key.kind}")
        lines.append("metadata:")
        lines.append(f'  name: {{{{ printf "%s-%s" {_go_str(key.name)} $role }}}}')
        lines.extend(_labels_block("$", "remediation", role="$role"))
        lines.append(f"{{{{ {body} | toYaml }}}}")
        if roles:
            lines.append("{{- end }}")
        lines.append("{{- end }}")
    else:
        lines.append("---")
        lines.append(f"apiVersion: {key.api_version}")
        lines.append(f"kind: {key.kind}")
        lines.append("metadata:")
        lines.append(f"  name: {key.name}")
        if key.namespace:
            lines.append(f"  namespace: {key.namespace}")
        lines.extend(_labels_block("", "remediation"))
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
        '{{- if index ($root.Values.profiles | default dict) $profile -}}',
        "{{- $ruleList := (index ($root.Values.profileRules | default dict) "
        "$profile) | default (list) -}}",
        "{{- $varList := (index ($root.Values.profileVariables | default dict) "
        "$profile) | default (list) -}}",
        '{{- $product := (splitList "-" $profile | first) -}}',
        # No right-trim on the line before "---": it would swallow the newline
        # and glue this document onto the previous one, so any two enabled
        # profiles of a layer produced invalid YAML.
        '{{- $name := printf "hardening-%s" ($profile | replace "_" "-") }}',
        "---",
        "apiVersion: compliance.openshift.io/v1alpha1",
        "kind: TailoredProfile",
        "metadata:",
        '  name: {{ $name }}',
        "  namespace: {{ $root.Values.complianceNamespace | quote }}",
        *_labels_block("$root", "tailored-profile"),
        "  annotations:",
        f'    compliance.openshift.io/product-type: "{product_type}"',
        "spec:",
        '  extends: {{ $profile | replace "_" "-" | quote }}',
        '  title: {{ printf "Hardening-managed selection of %s" $profile | quote }}',
        '  description: >-',
        "    Rule selection managed by the compliance-hardening Helm chart.",
        "  {{- $disabled := list -}}",
        "  {{- range $rule := $ruleList -}}",
        '  {{- $overrides := $root.Values.rules | default dict -}}',
        '  {{- if hasKey $overrides $rule -}}',
        "  {{- if not (index $overrides $rule) -}}",
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
        "  {{- if hasKey ($root.Values.variables | default dict) $var }}",
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
             "applicability": applicability.summarize(appl),
             "unverifiable_dependencies": unverifiable_dependencies(content_list),
             "missing_values": resolver.missing_values(content_list)}

    _write_layer_chart(charts_dir / PLATFORM_CHART, PLATFORM_CHART,
                       "OpenShift platform compliance remediations (no reboot).",
                       content_list, groups, "platform", version, stats, appl,
                       chart_version)
    _write_layer_chart(charts_dir / NODE_CHART, NODE_CHART,
                       "OpenShift node compliance remediations (MachineConfig/KubeletConfig; reboots).",
                       content_list, groups, "node", version, stats, appl,
                       chart_version)
    # Umbrella overlays: the same exclusions, nested per subchart. Without
    # these the documented `-f values-<arch>.yaml` is a no-op for umbrella
    # users, and the render fails again with the message that pointed at it.
    umbrella_overlays: dict[str, dict] = {}
    for layer, chart_name in (("platform", PLATFORM_CHART), ("node", NODE_CHART)):
        layer_rules = {r.helm_name for c in content_list
                       for r in rules_with_fixes(c).values()
                       if _rule_layer(r) == layer}
        for arch in applicability.ARCHITECTURES:
            excluded = _excluded_for_arch(appl, layer_rules, arch)
            if excluded or arch != DEFAULT_ARCHITECTURE:
                umbrella_overlays.setdefault(arch, {})[chart_name] = excluded
    umbrella_overlays = {
        arch: per_chart for arch, per_chart in umbrella_overlays.items()
        if any(per_chart.values())
    }
    _write_umbrella_chart(charts_dir / UMBRELLA_CHART, version, chart_version,
                          umbrella_overlays)

    for g in groups:
        for c in g.conflicts():
            stats["conflicts"].append(f"{g.key.kind}/{g.key.name}:{c.path}")
    return stats


def _write_umbrella_chart(chart_dir: Path, version: str,
                          chart_version: str = "0.0.0",
                          overlays: dict | None = None) -> None:
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
  # -- Whitelist whole compliance profiles; see the subchart's own values for
  # the full list of keys.
  profiles: {{}}
  # -- Per-rule override / blacklist. The subchart's defaults still apply, so
  # its pre-disabled alternatives and opt-in rules stay disabled.
  rules: {{}}
  # -- Tunable XCCDF variables, same keys as the subchart's values.
  variables: {{}}
  # -- Namespace the Compliance Operator watches for TailoredProfiles.
  complianceNamespace: openshift-compliance
  tailoredProfile:
    # -- Render a matching TailoredProfile per enabled profile.
    enabled: false

# -- Node remediations (MachineConfig/KubeletConfig; trigger reboots).
{NODE_CHART}:
{_indent_block(_cluster_block(), 2)}
  node:
    # -- Master enable switch for node remediations (triggers reboots).
    enabled: false
    # -- MachineConfigPool roles to target.
    roles:
      - worker
      - master
  # -- Whitelist whole compliance profiles; see the subchart's own values for
  # the full list of keys.
  profiles: {{}}
  # -- Per-rule override / blacklist. The subchart's defaults still apply, so
  # its pre-disabled alternatives and opt-in rules stay disabled.
  rules: {{}}
  # -- Tunable XCCDF variables, same keys as the subchart's values.
  variables: {{}}
  # -- Namespace the Compliance Operator watches for TailoredProfiles.
  complianceNamespace: openshift-compliance
  tailoredProfile:
    # -- Render a matching TailoredProfile per enabled profile.
    enabled: false
"""
    (chart_dir / "values.yaml").write_text(values, encoding="utf-8")

    # Without a schema here a misspelled subchart prefix is silently dropped:
    # the release installs, reports success, and has nothing enabled. Helm
    # still validates each subchart's own values against its own schema, so
    # this only needs to police the top level.
    (chart_dir / "values.schema.json").write_text(json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            PLATFORM_CHART: {"type": "object"},
            NODE_CHART: {"type": "object"},
            "global": {"type": "object"},
        },
        "additionalProperties": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for arch in applicability.ARCHITECTURES:
        overlay = chart_dir / f"values-{arch}.yaml"
        per_chart = (overlays or {}).get(arch)
        if per_chart:
            overlay.write_text(_arch_overlay(arch, per_chart, version, nested=True),
                               encoding="utf-8")
        elif overlay.exists():
            overlay.unlink()


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
    (tpl / "preflight.yaml").write_text(
        preflight_template(cross_object_file_conflicts(groups, layer)),
        encoding="utf-8")

    # One ready-made overlay per architecture that has exclusions. Stale
    # overlays are removed so a content bump cannot leave one behind.
    layer_rules = {r.helm_name for c in contents for r in rules_with_fixes(c).values()
                   if _rule_layer(r) == layer}
    for arch in applicability.ARCHITECTURES:
        overlay = chart_dir / f"values-{arch}.yaml"
        excluded = _excluded_for_arch(appl, layer_rules, arch)
        if excluded:
            overlay.write_text(_arch_overlay(arch, {name: excluded}, version),
                               encoding="utf-8")
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
        (tpl / f"{g.key.slug()}.yaml").write_text(
            object_template(g, appl), encoding="utf-8")
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
    # A variable value is interpolated into YAML, and for the encoded payloads
    # into a data URI. cr.enc handles the URI side; this forbids what would
    # break the YAML side before it silently truncates a config file: a `#`
    # starts a comment, quotes and backslashes break the scalar, and leading or
    # trailing whitespace is never intended. Internal spaces are allowed - and
    # encoded where they matter. Go's regexp has no lookaround, hence the
    # character classes. Built with a raw string so the escapes survive into
    # the JSON unchanged.
    inner = r"[^\n\t#'\"\\]"
    edge = r"[^\s#'\"\\]"
    var_pattern = rf"^{edge}({inner}*{edge})?$"
    # A bare `~`, `null`, `no` or `y` passes the pattern and then changes the
    # YAML *type* in the fragments that interpolate a variable unquoted:
    # `streamingConnectionIdleTimeout: null`, `memory.available: false`. Valid
    # YAML, so neither the fromYaml guard nor the empty-merge guard notices,
    # and the control is simply not implemented. Same list _yaml_scalar quotes
    # against, plus the indicator characters that start a non-scalar node.
    # Only the tokens YAML actually retypes. `none` is NOT one of them - it
    # parses as the string "none" - and banning it made `None`, a documented
    # value of APIServer.spec.audit.profile, unreachable. _YAML11_BOOL_NULL is
    # the right list for *quoting* (conservative); it is too wide for a ban.
    retyping = _YAML11_BOOL_NULL - {"none"}
    forbidden = sorted({*retyping,
                        *(w.upper() for w in retyping),
                        *(w.capitalize() for w in retyping)})
    unquoted = resolver.unquoted_scalar_variables(contents)
    numeric = resolver.numeric_variables(contents)
    var_props = {
        # A trailing % is allowed: auditd takes a percentage for space_left,
        # and the upstream selectors offer only digits, so deriving from the
        # datastream alone would have rejected a value the tool accepts.
        v: ({"type": ["string", "number"], "pattern": r"^\d+%?$"}
            if v in numeric
            else {"type": ["string", "number"], "pattern": var_pattern,
                  **({"not": {"enum": forbidden}} if v in unquoted else {})})
        for v in var_names
    }

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
                        # The documented `oc get clusterversion` returns
                        # 4.20.0-ec.2 on any pre-GA cluster, and the templates
                        # only ever use major.minor - so rejecting the suffix
                        # blocked an install over something we discard anyway.
                        "pattern": r"^[0-9]+\.[0-9]+(\.[0-9]+)?([-+].*)?$",
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
            # The generated data maps. Declared *and* required: Helm's
            # `--set X=null` deletes a key, and every preflight reads its map
            # with `| default dict`, so a deleted map turned the guard into a
            # silent no-op. `required` makes that a schema error instead.
            "profileRules": {"type": "object"},
            "profileVariables": {"type": "object"},
            "ruleApplicability": {"type": "object"},
            "ruleDependencies": {"type": "object"},
            "brokenRules": {"type": "object"},
            # Helm injects `global` into a subchart's values.
            "global": {"type": "object"},
        },
        "required": ["profiles", "rules", "variables", "profileRules",
                     "profileVariables", "ruleApplicability",
                     "ruleDependencies", "brokenRules"],
        # Closed, like every nested block: an umbrella-shaped values file
        # applied to a subchart was silently discarded, arch stayed x86_64 and
        # rules upstream marks notapplicable shipped with no error.
        "additionalProperties": False,
    }
    if layer == "node":
        schema["properties"]["node"] = {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                # Without minItems an empty list renders zero manifests and
                # exits 0 - every node remediation silently dropped.
                "roles": {"type": "array", "items": {"type": "string"},
                          "minItems": 1},
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

    # Cross-object alternatives: two rules writing one file differently. Mark
    # only the genuinely pairwise ones. /etc/ssh/sshd_config is written by 31
    # rules with identical content plus one that differs, and marking all 32
    # would be noise - the legend covers that case in prose instead.
    for layer in ("platform", "node"):
        for conflict in cross_object_file_conflicts(groups, layer):
            if all(len(grp["rules"]) == 1 for grp in conflict["groups"]):
                for grp in conflict["groups"]:
                    conflicting.update(grp["rules"])

    broken = broken_rules(content_list)

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
            if hn in OPT_IN_RULES:
                marks.append("⚠️ opt-in")
            mark = (" " + " ".join(marks)) if marks else ""
            # Node objects are rendered once per role with the role appended,
            # so the bare name is not what you would look up on a cluster.
            if layer == "node":
                target = f"{target}-<role>"
            applies = applicability.describe(app) if app is not None else "-"
            deps = sorted(f"{content.product}-{d}" for d in rule.depends_on)
            if deps:
                needs = "requires " + ", ".join(f"`{d}`" for d in deps)
                applies = needs if applies == "-" else f"{applies}; {needs}"
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
        "that targets the same object makes the chart fail - pick one. The same "
        "applies across objects: upstream's sshd drop-ins put the `enable` and "
        "`disable` variant of a setting in separate rules writing the same "
        "file, and since nothing on the cluster would reject that (the "
        "MachineConfig Operator merges alphanumerically and the last one wins) "
        "the chart refuses instead. Below OpenShift 4.13 the sshd rules write "
        "the whole `sshd_config` rather than drop-ins, where "
        "`rhcos4-disable_host_auth` conflicts with the rest of the family. "
        "Rules "
        "marked **⛔ broken** reproduce an upstream fix that the OpenShift API "
        "ignores (e.g. a `Custom:` TLS block without `type: Custom`) - selecting "
        "them is a no-op; prefer the non-broken alternative in the same group. "
        "A rule that **requires** another is one upstream marks with "
        "`complianceascode.io/depends-on`: the operator will not apply it while "
        "the dependency is unmet, and neither will the chart - disabling the "
        "dependency while the rule stays active aborts the render. "
        "Rules marked **⚠️ opt-in** ship disabled even though a profile selects "
        "them, because applying them can take a node down - the reason is in "
        "`values.yaml` next to the entry, and enabling one is a single line.",
        "",
        "The **Applicability** column carries the upstream `<platform>` constraint. "
        "The Compliance Operator evaluates these at scan time and reports a "
        "non-applicable rule as `notapplicable`, generating no remediation; the "
        "charts refuse to render one instead of shipping it. Architecture and "
        "HyperShift are declared via `cluster.architecture` and "
        "`cluster.hypershift`; for a non-default architecture apply the generated "
        "`values-<arch>.yaml` overlay. A rule restricted to one MachineConfigPool "
        "(\"master pool only\") is simply not rendered for the other roles in "
        "`node.roles`, mirroring the operator: it scans per pool and takes the "
        "MachineConfig role from the scan's node selector, so such a remediation "
        "never reaches a worker there. Rules marked **⛔ n/a** are never "
        "applicable to RHCOS/OKD at all and ship disabled - enable one explicitly "
        "only if you know the assumption behind it does not hold for you.",
        "",
        "| Rule | Target object | Severity | Layer | Product | Applicability | Profiles |",
        "|------|---------------|----------|-------|---------|---------------|----------|",
    ]
    return "\n".join(header + rows) + "\n"

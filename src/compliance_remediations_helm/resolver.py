"""Resolve XCCDF variables referenced in fix payloads.

Fix YAML contains placeholders like ``{{.var_oauth_inactivity_timeout}}``.
These collide with Helm's own ``{{ }}`` syntax, so we must rewrite them.

Strategy:
  * Collect every ``var_*`` referenced across all k8s fixes.
  * Resolve each to a default value (Value default, optionally overridden by a
    profile's refine-value selector). This default is emitted into values.yaml
    under ``variables:`` so the user can tune it.
  * Rewrite the placeholder in the fix YAML to a Helm reference:
    ``{{ .Values.variables.<name> }}``.
"""
from __future__ import annotations

import re

from .parser import Content, Value

_VAR_RE = re.compile(r"\{\{\s*\.(var_\w+)\s*\}\}")


def referenced_variables(content: Content) -> set[str]:
    names: set[str] = set()
    for rule in content.rules.values():
        for fix in rule.fixes:
            names.update(_VAR_RE.findall(fix.yaml))
    return names


def _resolve_value(value: Value, selector: str | None) -> str:
    if selector and selector in value.selectors:
        return value.selectors[selector]
    if value.default is not None:
        return value.default
    # Fall back to any selector if no bare default exists.
    if value.selectors:
        return next(iter(value.selectors.values()))
    return ""


def _find_value(content: Content, name: str) -> Value | None:
    # Value ids are stored without the "var_" prefix in some content, with it
    # in others. Try both.
    return content.values.get(name) or content.values.get(name[len("var_"):])


def resolve_defaults(content: Content, default_profile: str | None = None) -> dict[str, str]:
    """Return {var_name: default_value}.

    Default selection, in order of precedence:
      1. If ``default_profile`` is given and refines the variable, use that.
      2. Otherwise use the value the **majority of profiles that refine this
         variable** select. This aligns the chart's shipped default with what
         the compliance profiles (and thus the scanner) actually expect, rather
         than the bare - often weaker - upstream Value default.
      3. Fall back to the bare Value default.

    Rationale: several variables have a bare default that is weaker than every
    profile's refinement (e.g. audit profile ``Default`` vs ``WriteRequestBodies``,
    OAuth token maxage 24h vs 8h). Shipping the bare default would understate the
    selected profile's intent and make the operator's re-scan report drift.
    """
    explicit: dict[str, str] = {}
    if default_profile and default_profile in content.profiles:
        explicit = content.profiles[default_profile].refined_values

    resolved: dict[str, str] = {}
    for name in sorted(referenced_variables(content)):
        value = _find_value(content, name)
        if value is None:
            resolved[name] = ""
            continue
        vid = value.value_id

        # 1) explicit default profile wins
        selector = explicit.get(vid) or explicit.get(name)
        if selector:
            resolved[name] = _resolve_value(value, selector)
            continue

        # 2) most-common refinement across all profiles that set this variable
        counts: dict[str, int] = {}
        for prof in content.profiles.values():
            sel = prof.refined_values.get(vid) or prof.refined_values.get(name)
            if sel and sel in value.selectors:
                counts[sel] = counts.get(sel, 0) + 1
        if counts:
            # highest count wins; ties broken deterministically by selector name
            best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            resolved[name] = value.selectors[best]
            continue

        # 3) bare default
        resolved[name] = _resolve_value(value, None)
    return resolved


def rewrite_placeholders(fix_yaml: str) -> str:
    """Prepare fix YAML for Helm templating.

    Two kinds of double-brace occur in fix payloads:
      * XCCDF variable refs, e.g. ``{{.var_oauth_inactivity_timeout}}`` - these
        become Helm value refs ``{{ .Values.variables.var_x }}``.
      * Literal braces in data (e.g. audit rule ``data:,{{ -a%20... }}``) -         these must be escaped so Helm does not evaluate them.

    Implemented as a single left-to-right pass so escaped output is never
    re-processed.
    """
    out: list[str] = []
    i = 0
    n = len(fix_yaml)
    while i < n:
        two = fix_yaml[i:i + 2]
        if two == "{{":
            m = _VAR_RE.match(fix_yaml, i)
            if m:
                out.append(f"{{{{ .Values.variables.{m.group(1)} }}}}")
                i = m.end()
            else:
                # literal '{{' -> Helm-escaped literal
                out.append('{{ "{{" }}')
                i += 2
        elif two == "}}":
            out.append('{{ "}}" }}')
            i += 2
        else:
            out.append(fix_yaml[i])
            i += 1
    return "".join(out)

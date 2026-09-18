"""Resolve XCCDF variables referenced in fix payloads.

Upstream fixes carry ``{{ ... }}`` blocks. These are not literal content: they
are the Compliance Operator's remediation-templating directive (see
``parseValues`` in the operator's ``pkg/utils/parse_arf_result.go``). The
operator strips the markers, trims whitespace, URL-decodes the block, runs the
result as a Go template against the XCCDF variable values, and re-encodes it
with ``url.PathEscape``. Two shapes occur:

  * Plain, outside an Ignition payload::

        {{.var_oauth_inactivity_timeout}}

  * URL-encoded, inside an Ignition ``data:,`` URI, where the variable
    reference is itself percent-encoded::

        source: data:,{{ flush%20%3D%20%7B%7B.var_auditd_flush%7D%7D }}

Both must be rewritten to Helm references. Emitting the markers as literal text
would write ``{{ ... }}`` and unsubstituted ``{{.var_x}}`` into the file the
MachineConfig lays down on the node.

Strategy:
  * Collect every variable referenced across all k8s fixes, in both shapes.
  * Resolve each to a default value (Value default, optionally overridden by a
    profile's refine-value selector). This default is emitted into values.yaml
    under ``variables:`` so the user can tune it.
  * Rewrite the placeholder in the fix YAML to a Helm reference:
    ``{{ .Values.variables.<name> }}``, keeping the surrounding payload
    percent-encoded exactly as upstream ships it.
"""
from __future__ import annotations

import re
import urllib.parse

from .parser import Content, Value

# A remediation-templating block. Same pattern the operator uses: the payload
# inside is percent-encoded, so it never contains a literal "}".
_BLOCK_RE = re.compile(r"\{\{[^}]*\}\}")
# Variable reference, plain and percent-encoded. Not every variable carries the
# "var_" prefix (e.g. sshd_idle_timeout_value), so match any identifier.
_VAR_RE = re.compile(r"\{\{\s*\.(\w+)\s*\}\}")
# A percent-encoded Go-template action inside a block payload. Most are a bare
# variable reference, a few use control flow (the chrony rules loop over the
# NTP server list).
_ENC_ACTION_RE = re.compile(r"%7B%7B(.*?)%7D%7D", re.IGNORECASE | re.DOTALL)
# The inner form of a plain block, after markers are stripped and trimmed.
_PLAIN_INNER_RE = re.compile(r"\.(\w+)")
# A variable reference inside a decoded action: ".name", but not ".Values.name"
# or "$name".
_DOT_REF_RE = re.compile(r"(?<![\w.$])\.(\w+)")
# Bare identifiers in a decoded action, i.e. neither ".ref" nor "$var".
_BARE_WORD_RE = re.compile(r"(?<![.$\w])([A-Za-z_]\w*)")
# Go-template constructs the operator uses that we can express in Helm.
# "toArrayByComma" is an operator-provided func; sprig's splitList is the
# equivalent (`x | splitList ","` calls splitList(",", x)).
_SUPPORTED_WORDS = {"range", "end", "toArrayByComma"}
_TO_ARRAY_RE = re.compile(r"\s*\|\s*toArrayByComma")


def _block_variables(block: str) -> set[str]:
    """Variable names referenced by one ``{{ ... }}`` block."""
    inner = block[2:-2].strip()
    plain = _PLAIN_INNER_RE.fullmatch(inner)
    if plain:
        return {plain.group(1)}
    names: set[str] = set()
    for encoded in _ENC_ACTION_RE.findall(inner):
        names.update(_DOT_REF_RE.findall(urllib.parse.unquote(encoded)))
    return names


def referenced_variables(content: Content) -> set[str]:
    names: set[str] = set()
    for rule in content.rules.values():
        for fix in rule.fixes:
            for block in _BLOCK_RE.findall(fix.yaml):
                names.update(_block_variables(block))
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


def _helm_ref(name: str) -> str:
    return f"{{{{ .Values.variables.{name} }}}}"


def _translate_action(encoded: str) -> str:
    """Translate one percent-encoded Go-template action into a Helm action.

    The operator decodes the action and runs it as a Go template against the
    XCCDF values. Helm is Go templates too, so the translation is mechanical:
    ``.var_x`` becomes ``.Values.variables.var_x`` and the operator's
    ``toArrayByComma`` becomes sprig's ``splitList``. Whitespace is left alone
    (no ``{{-``/``-}}``) so the rendered bytes match what the operator emits.

    An action using a construct we have not taught this function raises, rather
    than emitting a payload with an unevaluated template in it - that is the
    failure mode this whole path exists to prevent. If upstream content starts
    using one, `make generate` fails loudly and the translation gets extended.
    """
    body = urllib.parse.unquote(encoded).strip()
    unsupported = sorted(set(_BARE_WORD_RE.findall(body)) - _SUPPORTED_WORDS)
    if unsupported:
        raise ValueError(
            f"unsupported Go-template construct in remediation payload: "
            f"{', '.join(unsupported)} (action: {body!r})"
        )
    body = _DOT_REF_RE.sub(r".Values.variables.\1", body)
    body = _TO_ARRAY_RE.sub(' | splitList ","', body)
    return "{{ " + " ".join(body.split()) + " }}"


def _rewrite_block(block: str) -> str:
    """Rewrite one ``{{ ... }}`` remediation-templating block.

    Mirrors the operator's ``parseValues``: strip the two-character markers,
    trim surrounding whitespace, then substitute the template actions. The
    payload keeps the percent-encoding it arrives with - the operator re-encodes
    its own substituted result the same way (``url.PathEscape``), so the bytes
    Ignition writes to disk are identical.
    """
    inner = block[2:-2].strip()
    plain = _PLAIN_INNER_RE.fullmatch(inner)
    if plain:
        return _helm_ref(plain.group(1))
    return _ENC_ACTION_RE.sub(lambda m: _translate_action(m.group(1)), inner)


def rewrite_placeholders(fix_yaml: str) -> str:
    """Prepare fix YAML for Helm templating.

    Every ``{{ ... }}`` is a remediation-templating directive, never literal
    content: either a bare variable reference or a percent-encoded Ignition
    payload with encoded references inside. Both are rewritten to Helm value
    refs and the markers are dropped.

    A stray brace pair that is not a well-formed block is escaped so Helm does
    not try to evaluate it. Implemented as a single left-to-right pass so
    rewritten output is never re-processed.
    """
    out: list[str] = []
    i = 0
    n = len(fix_yaml)
    while i < n:
        two = fix_yaml[i:i + 2]
        if two == "{{":
            m = _BLOCK_RE.match(fix_yaml, i)
            if m:
                out.append(_rewrite_block(m.group(0)))
                i = m.end()
            else:
                # unterminated '{{' -> Helm-escaped literal
                out.append('{{ "{{" }}')
                i += 2
        elif two == "}}":
            out.append('{{ "}}" }}')
            i += 2
        else:
            out.append(fix_yaml[i])
            i += 1
    return "".join(out)

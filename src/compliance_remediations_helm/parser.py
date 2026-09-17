"""Parse an XCCDF datastream into rules, fixes, profiles, and variables.

Stdlib-only (xml.etree.ElementTree). We deliberately ignore XML namespaces by
matching on local tag names, which keeps the code robust across XCCDF versions.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

K8S_FIX_SYSTEM = "urn:xccdf:fix:script:kubernetes"

_RULE_PREFIX = "content_rule_"
_VALUE_PREFIX = "content_value_"
_PROFILE_PREFIX = "content_profile_"


def _local(tag: str) -> str:
    return tag.split("}")[-1]


@dataclass
class FixVariant:
    """One YAML fix payload, optionally constrained to an OCP version range."""

    yaml: str
    ocp_version: str | None = None  # e.g. "<4.13.0" or ">=4.13.0"


@dataclass
class Rule:
    rule_id: str          # short name, e.g. "api_server_encryption_provider_cipher"
    xccdf_id: str         # full XCCDF id
    product: str = "ocp4"  # "ocp4" or "rhcos4"
    title: str = ""
    severity: str = ""
    fixes: list[FixVariant] = field(default_factory=list)

    @property
    def helm_name(self) -> str:
        # OpenShift naming: <product>-<rule_with_underscores>
        return f"{self.product}-{self.rule_id}"

    @property
    def has_fix(self) -> bool:
        return bool(self.fixes)


@dataclass
class Value:
    value_id: str
    default: str | None
    selectors: dict[str, str] = field(default_factory=dict)


@dataclass
class Profile:
    profile_id: str
    title: str
    selected_rules: list[str] = field(default_factory=list)
    refined_values: dict[str, str] = field(default_factory=dict)  # value_id -> selector


@dataclass
class Content:
    rules: dict[str, Rule]
    values: dict[str, Value]
    profiles: dict[str, Profile]
    product: str = "ocp4"


_OCP_VERSION_RE = re.compile(r"complianceascode\.io/ocp-version:\s*'([^']+)'")


def _split_fix_by_ocp_version(text: str) -> list[FixVariant]:
    """A single <fix> may contain multiple YAML docs, some annotated with an
    OCP version constraint. Group them into variants.

    We split on YAML document separators and attach the ocp-version annotation
    found within each document (if any).
    """
    text = text.strip()
    # Normalise: ensure we can split on leading '---'.
    docs = re.split(r"(?m)^---\s*$", text)
    variants: list[FixVariant] = []
    for doc in docs:
        doc = doc.strip("\n")
        if not doc.strip():
            continue
        m = _OCP_VERSION_RE.search(doc)
        variants.append(FixVariant(yaml=doc, ocp_version=m.group(1) if m else None))
    if not variants:
        variants.append(FixVariant(yaml=text, ocp_version=None))
    return variants


def parse(datastream_path: Path, product: str = "ocp4") -> Content:
    root = ET.parse(datastream_path).getroot()

    rules: dict[str, Rule] = {}
    values: dict[str, Value] = {}
    profiles: dict[str, Profile] = {}

    for el in root.iter():
        tag = _local(el.tag)

        if tag == "Rule":
            xccdf_id = el.get("id", "")
            rule_id = xccdf_id.split(_RULE_PREFIX)[-1]
            rule = Rule(rule_id=rule_id, xccdf_id=xccdf_id, product=product,
                        severity=el.get("severity", ""))
            for c in el:
                ct = _local(c.tag)
                if ct == "title":
                    rule.title = "".join(c.itertext()).strip()
                elif ct == "fix" and c.get("system") == K8S_FIX_SYSTEM:
                    fix_text = "".join(c.itertext())
                    rule.fixes.extend(_split_fix_by_ocp_version(fix_text))
            rules[rule_id] = rule

        elif tag == "Value":
            value_id = el.get("id", "").split(_VALUE_PREFIX)[-1]
            default = None
            selectors: dict[str, str] = {}
            for c in el:
                if _local(c.tag) == "value":
                    sel = c.get("selector")
                    if sel:
                        selectors[sel] = (c.text or "").strip()
                    else:
                        default = (c.text or "").strip()
            values[value_id] = Value(value_id=value_id, default=default, selectors=selectors)

        elif tag == "Profile":
            short_id = el.get("id", "").split(_PROFILE_PREFIX)[-1]
            # Namespace the profile key with the product (operator-aligned):
            #   ocp4-cis, rhcos4-moderate
            profile_key = f"{product}-{short_id}"
            prof = Profile(profile_id=profile_key, title="")
            for c in el:
                ct = _local(c.tag)
                if ct == "title":
                    prof.title = "".join(c.itertext()).strip()
                elif ct == "select" and c.get("selected") == "true":
                    prof.selected_rules.append(c.get("idref", "").split(_RULE_PREFIX)[-1])
                elif ct == "refine-value":
                    vid = c.get("idref", "").split(_VALUE_PREFIX)[-1]
                    sel = c.get("selector", "")
                    if vid and sel:
                        prof.refined_values[vid] = sel
            profiles[profile_key] = prof

    return Content(rules=rules, values=values, profiles=profiles, product=product)


def rules_with_fixes(content: Content) -> dict[str, Rule]:
    return {rid: r for rid, r in content.rules.items() if r.has_fix}

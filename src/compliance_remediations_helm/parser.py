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


@dataclass(frozen=True)
class FactRef:
    """A leaf of a CPE applicability expression: one OVAL definition.

    ``name`` is the definition id with the ``oval:ssg-`` prefix and ``:def:N``
    suffix stripped, e.g. ``proc_sys_kernel_osrelease_arch_aarch64``.
    """

    name: str


@dataclass(frozen=True)
class LogicalTest:
    """An inner node of a CPE applicability expression."""

    operator: str                      # "AND" or "OR"
    negate: bool
    children: tuple = ()               # tuple[LogicalTest | FactRef, ...]


@dataclass
class Rule:
    rule_id: str          # short name, e.g. "api_server_encryption_provider_cipher"
    xccdf_id: str         # full XCCDF id
    product: str = "ocp4"  # "ocp4" or "rhcos4"
    title: str = ""
    severity: str = ""
    fixes: list[FixVariant] = field(default_factory=list)
    # CPE applicability, as "#id" references into Content.platforms. Rules
    # inherit from their ancestor <Group>s, and some carry a constraint only
    # that way (the usbguard family is arch-constrained purely by its group).
    platforms: list[str] = field(default_factory=list)
    group_platforms: list[str] = field(default_factory=list)

    @property
    def helm_name(self) -> str:
        # OpenShift naming: <product>-<rule_with_underscores>
        return f"{self.product}-{self.rule_id}"

    @property
    def all_platforms(self) -> list[str]:
        """Own plus inherited references, deduplicated, order-stable."""
        seen: dict[str, None] = {}
        for ref in (*self.platforms, *self.group_platforms):
            seen.setdefault(ref, None)
        return list(seen)

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
    # CPE applicability expressions, keyed by id *without* the leading "#".
    platforms: dict[str, LogicalTest] = field(default_factory=dict)


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


def _parse_logical_test(el) -> LogicalTest:
    """Parse one <cpe-lang:logical-test> subtree."""
    children: list = []
    for c in el:
        ct = _local(c.tag)
        if ct == "logical-test":
            children.append(_parse_logical_test(c))
        elif ct == "check-fact-ref":
            ref = c.get("id-ref", "")
            name = re.sub(r":def:\d+$", "", ref)
            name = name.split("oval:ssg-")[-1]
            children.append(FactRef(name))
        elif ct == "fact-ref":
            # A bare CPE name (product applicability). The product is already
            # decided by which datastream we parsed, so it is not a fact we
            # need to evaluate.
            continue
        else:
            raise ValueError(f"unexpected element in CPE expression: {ct}")
    return LogicalTest(
        operator=(el.get("operator") or "AND").upper(),
        negate=(el.get("negate") == "true"),
        children=tuple(children),
    )


def _group_platform_index(root) -> dict[str, list[str]]:
    """XCCDF rule id -> platform refs inherited from ancestor <Group>s.

    Recurses only through Benchmark/Group/Rule so it never walks the OVAL,
    OCIL or CPE components. Benchmark-level refs are deliberately excluded:
    those are CPE product names, and the product is the datastream we chose.
    """
    index: dict[str, list[str]] = {}

    def walk(el, inherited: list[str]) -> None:
        for c in el:
            ct = _local(c.tag)
            if ct == "Group":
                own = [g.get("idref") for g in c
                       if _local(g.tag) == "platform" and g.get("idref")]
                walk(c, inherited + own)
            elif ct == "Rule" and inherited:
                rid = c.get("id", "").split(_RULE_PREFIX)[-1]
                index[rid] = list(inherited)

    # The Benchmark sits inside a <component>, so locate it first and deep-walk
    # only its Group/Rule subtree.
    for el in root.iter():
        if _local(el.tag) == "Benchmark":
            walk(el, [])
    return index


def parse(datastream_path: Path, product: str = "ocp4") -> Content:
    root = ET.parse(datastream_path).getroot()

    rules: dict[str, Rule] = {}
    values: dict[str, Value] = {}
    profiles: dict[str, Profile] = {}
    platforms: dict[str, LogicalTest] = {}
    group_platforms = _group_platform_index(root)

    for el in root.iter():
        tag = _local(el.tag)

        if tag == "Rule":
            xccdf_id = el.get("id", "")
            rule_id = xccdf_id.split(_RULE_PREFIX)[-1]
            rule = Rule(rule_id=rule_id, xccdf_id=xccdf_id, product=product,
                        severity=el.get("severity", ""),
                        group_platforms=group_platforms.get(rule_id, []))
            for c in el:
                ct = _local(c.tag)
                if ct == "title":
                    rule.title = "".join(c.itertext()).strip()
                elif ct == "platform" and c.get("idref"):
                    rule.platforms.append(c.get("idref"))
                elif ct == "fix" and c.get("system") == K8S_FIX_SYSTEM:
                    fix_text = "".join(c.itertext())
                    rule.fixes.extend(_split_fix_by_ocp_version(fix_text))
            rules[rule_id] = rule

        elif tag == "platform" and el.get("id"):
            # Namespaces are stripped by _local(), so <xccdf:platform idref>
            # and <cpe-lang:platform id> arrive under the same tag name. The
            # attribute is the only discriminator: "id" defines an expression,
            # "idref" references one.
            platforms[el.get("id")] = _parse_logical_test(el)

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

    return Content(rules=rules, values=values, profiles=profiles, product=product,
                   platforms=platforms)


def rules_with_fixes(content: Content) -> dict[str, Rule]:
    return {rid: r for rid, r in content.rules.items() if r.has_fix}

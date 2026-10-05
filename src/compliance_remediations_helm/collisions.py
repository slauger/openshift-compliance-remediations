"""Detect and group remediations that target the same Kubernetes object.

Multiple rules may patch the same object (e.g. several rules all edit
APIServer/cluster). Emitting them as separate Helm files would create duplicate
resources that collide on apply. We group them by (apiVersion, kind, namespace,
name) so the emitter can merge them into a single object while keeping each
rule individually togglable.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from . import classify
from .parser import Content

_KIND_RE = re.compile(r"(?m)^\s*kind:\s*(\S+)\s*$")
_APIVERSION_RE = re.compile(r"(?m)^\s*apiVersion:\s*(\S+)\s*$")
# name: at metadata indentation (2 spaces or 4 spaces); first name in doc.
_NAME_RE = re.compile(r"(?m)^\s{2,4}name:\s*(\S+)\s*$")
_NAMESPACE_RE = re.compile(r"(?m)^\s{2,4}namespace:\s*(\S+)\s*$")


@dataclass(frozen=True)
class ObjectKey:
    api_version: str
    kind: str
    namespace: str
    name: str

    @property
    def layer(self) -> str:
        return classify.layer_for_kind(self.kind)

    def slug(self) -> str:
        base = f"{self.kind}-{self.name}".lower()
        if self.namespace:
            base = f"{self.namespace}-{base}"
        return re.sub(r"[^a-z0-9-]+", "-", base).strip("-")


@dataclass
class FixDoc:
    """One YAML document produced by a rule, with its identity resolved."""

    rule_id: str
    key: ObjectKey
    yaml: str
    ocp_version: str | None = None


@dataclass
class MergeGroup:
    key: ObjectKey
    docs: list[FixDoc] = field(default_factory=list)

    @property
    def rule_ids(self) -> list[str]:
        seen: list[str] = []
        for d in self.docs:
            if d.rule_id not in seen:
                seen.append(d.rule_id)
        return seen

    @property
    def is_collision(self) -> bool:
        return len(self.rule_ids) > 1

    def conflicts(self) -> list[Conflict]:
        """Shared-leaf conflicts between rules in this group.

        Two rules conflict when they write the **same leaf path** with different
        values, or write different immediate children under a subtree that is
        structurally exclusive (a `type`-discriminated union like
        tlsSecurityProfile). Disjoint leaves (e.g. tokenConfig.a vs
        tokenConfig.b) merge cleanly and are NOT conflicts.
        """
        return _detect_conflicts(self.docs)


@dataclass
class Conflict:
    """A leaf/subtree written incompatibly by more than one rule."""

    path: str
    rules: list[str]


class YamlShapeError(ValueError):
    """A fix body did not match the YAML subset this module parses."""


_KEY_RE = re.compile(r"^([\w.\-/]+):(.*)$")
_BLOCK_START_RE = re.compile(r"^[|>][+-]?\d*$")
# Top-level keys that hold the object's content. Everything else at the top
# level (apiVersion, kind, metadata) is identity, not content: comparing it
# would make every rule targeting one object conflict on its own name.
#
# The single definition: emit builds its body-stripping regex from this and
# scripts/validate_payloads.py imports it, because three hand-kept copies of
# one vocabulary is three chances to drift.
BODY_ROOTS = ("spec", "data", "rules", "parameters", "projectRequestTemplate", "objects")


def _indent_of(raw: str) -> int:
    return len(raw) - len(raw.lstrip())


def _skip_blank(lines: list[str], i: int) -> int:
    while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
        i += 1
    return i


def _read_block_scalar(lines: list[str], i: int, key_indent: int) -> tuple[str, int]:
    """Consume a `|`/`>` scalar as opaque text.

    Everything more-indented than the owning key is content, never structure,
    so a `foo: bar` line inside a script or config blob cannot become a leaf.
    """
    out: list[str] = []
    while i < len(lines):
        raw = lines[i]
        if not raw.strip():
            out.append("")
            i += 1
            continue
        if _indent_of(raw) <= key_indent:
            break
        out.append(raw.strip())
        i += 1
    return "|" + "\\n".join(out).strip(), i


def _read_value(lines: list[str], i: int, key_indent: int, where: str):
    """Parse the block that belongs to a key sitting at `key_indent`."""
    i = _skip_blank(lines, i)
    if i >= len(lines):
        return None, i
    raw = lines[i]
    indent = _indent_of(raw)
    if raw.strip().startswith("-"):
        # A block sequence may be indented at its key's own column or deeper.
        # Accepting only "deeper" is what attached every `files:` list to
        # `storage` instead: ComplianceAsCode writes `files:` and `- contents:`
        # at the same indent.
        if indent >= key_indent:
            return _read_sequence(lines, i, indent, where)
        return None, i
    if indent > key_indent:
        return _read_mapping(lines, i, indent, where)
    return None, i


def _read_sequence(lines: list[str], i: int, indent: int, where: str):
    items: list = []
    while True:
        i = _skip_blank(lines, i)
        if i >= len(lines):
            break
        raw = lines[i]
        if _indent_of(raw) != indent or not raw.strip().startswith("-"):
            break
        rest = raw.strip()[1:].lstrip()
        if not rest:
            item, i = _read_value(lines, i + 1, indent, where)
            items.append(item)
        elif _KEY_RE.match(rest):
            # `- key: value` starts a mapping item whose keys sit at the
            # column of `key`. Blank out the dash and parse it as an ordinary
            # mapping, so the item's keys nest under the item - not onto the
            # list's own path, last-wins, which dropped every file but one.
            item_indent = len(raw) - len(rest)
            lines[i] = " " * item_indent + rest
            item, i = _read_mapping(lines, i, item_indent, where)
            items.append(item)
        else:
            items.append(rest)
            i += 1
    return items, i


def _read_mapping(lines: list[str], i: int, indent: int, where: str):
    out: dict = {}
    while True:
        i = _skip_blank(lines, i)
        if i >= len(lines):
            break
        raw = lines[i]
        line_indent = _indent_of(raw)
        stripped = raw.strip()
        if line_indent < indent or stripped.startswith("-"):
            break
        if line_indent > indent:
            raise YamlShapeError(
                f"{where}: line indented {line_indent} where {indent} was expected: {stripped!r}")
        m = _KEY_RE.match(stripped)
        if not m:
            raise YamlShapeError(f"{where}: not a mapping key: {stripped!r}")
        key, val = m.group(1), m.group(2).strip()
        i += 1
        if _BLOCK_START_RE.match(val):
            out[key], i = _read_block_scalar(lines, i, line_indent)
        elif not val:
            out[key], i = _read_value(lines, i, line_indent, where)
        else:
            out[key] = val
    return out, i


def _canonical(node) -> str:
    """Order-insensitive, lossless-enough serialization of a subtree.

    Used as the value of a list leaf, so two rules writing the same list in a
    different order compare equal while any difference in content does not.
    """
    if isinstance(node, dict):
        return "{" + ",".join(f"{k}={_canonical(v)}" for k, v in sorted(node.items())) + "}"
    if isinstance(node, list):
        return "[" + ",".join(sorted(_canonical(v) for v in node)) + "]"
    return "" if node is None else str(node)


def _flatten(node, path: str, out: dict[str, str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _flatten(v, f"{path}.{k}" if path else k, out)
        return
    if isinstance(node, list):
        # A list is one leaf at its own path, serialized whole. Helm's
        # mustMergeOverwrite *replaces* lists rather than concatenating them,
        # so two rules writing the same list path differently are alternatives
        # no matter which entries differ - per-entry leaves would under-report
        # exactly that.
        if node:
            out[path] = _canonical(node)
        return
    if node is None or node in ("{}", "[]"):
        return
    out[path] = str(node)


def _leaf_paths(doc_yaml: str, where: str = "<doc>") -> dict[str, str]:
    """Map dotted leaf path -> value, for the content below the object root.

    Parses the document into nested dicts/lists first, then flattens it. The
    previous version flattened in a single line-wise pass, which mis-handled
    sequences three ways at once: a list attached to its grandparent, an item
    was serialized as its first line only, and an item's keys were flattened
    onto the list's own path with last-wins - so a three-file MachineConfig
    came out as one file plus a path that does not exist.

    Deliberately strict: the pinned content has no line this parser cannot
    place, so anything it cannot place is a content change that needs looking
    at rather than guessing about.
    """
    lines = doc_yaml.splitlines()
    doc, consumed = _read_mapping(lines, 0, 0, where)
    # Nothing may be left over: silently stopping early would quietly shrink
    # the leaf map, and a smaller leaf map means fewer conflicts detected.
    rest = _skip_blank(lines, consumed)
    if rest < len(lines):
        raise YamlShapeError(f"{where}: unparsed trailing content: {lines[rest].strip()!r}")
    # A document with no recognized body yields no leaves, on purpose: emit
    # reports it as a dropped fix rather than emitting it, so there is nothing
    # to compare and nothing to fail about here.
    out: dict[str, str] = {}
    for root in BODY_ROOTS:
        if root in doc:
            _flatten(doc[root], root, out)
    return out


# Subtrees that are discriminated unions: if two rules both write under such a
# path but with differing content, they are mutually-exclusive alternatives.
_UNION_SUBTREES = ("spec.tlsSecurityProfile",)


def _detect_conflicts(docs: list[FixDoc]) -> list[Conflict]:
    # 1) same leaf path, different value.
    # Merge, do not overwrite: a rule may contribute several docs to one object
    # - every kubelet_eviction_* rule emits two or three - and assigning per
    # rule id kept only the last, hiding 15 of the 22 leaf paths in the
    # consolidated KubeletConfig group from conflict detection entirely.
    #
    # Where a rule's own version variants write one path differently, the last
    # wins here. That is harmless: conflicts are only ever reported between
    # *different* rules, and only one variant renders at a given
    # cluster.ocpVersion anyway.
    leaf_by_rule: dict[str, dict[str, str]] = {}
    for d in docs:
        leaf_by_rule.setdefault(d.rule_id, {}).update(_leaf_paths(d.yaml, d.rule_id))

    conflicts: dict[str, set[str]] = defaultdict(set)

    # same-leaf/different-value
    all_paths: dict[str, dict[str, str]] = defaultdict(dict)
    for rid, leaves in leaf_by_rule.items():
        for path, val in leaves.items():
            all_paths[path][rid] = val
    for path, rule_vals in all_paths.items():
        if len(rule_vals) > 1 and len({v for v in rule_vals.values()}) > 1:
            conflicts[path].update(rule_vals)

    # 2) union subtrees: >1 rule writes anything under the union path -> conflict.
    for union in _UNION_SUBTREES:
        writers = {
            rid for rid, leaves in leaf_by_rule.items()
            if any(p == union or p.startswith(union + ".") for p in leaves)
        }
        if len(writers) > 1:
            conflicts[union].update(writers)

    return [Conflict(path=p, rules=sorted(r)) for p, r in sorted(conflicts.items())]


def _object_key(doc_yaml: str, rule_id: str) -> ObjectKey | None:
    kind = _KIND_RE.search(doc_yaml)
    api = _APIVERSION_RE.search(doc_yaml)
    if not (kind and api):
        return None
    name_m = _NAME_RE.search(doc_yaml)
    ns = _NAMESPACE_RE.search(doc_yaml)
    kind_v = kind.group(1)
    if name_m:
        name_v = name_m.group(1)
    elif classify.layer_for_kind(kind_v) == "node":
        # Node objects (KubeletConfig/MachineConfig) omit a name in the
        # datastream; synthesise one per rule (operator does the same).
        name_v = classify.synthesize_name(kind_v, rule_id)
    else:
        return None
    return ObjectKey(
        api_version=api.group(1),
        kind=kind_v,
        namespace=ns.group(1) if ns else "",
        name=name_v,
    )


def build_groups(*contents: Content) -> tuple[list[MergeGroup], list[FixDoc]]:
    """Return (merge_groups, unparseable_docs) across one or more products.

    Each MergeGroup maps one target object to the rule docs that produce it.
    Passing multiple Contents lets the same target object (rare across
    products) merge correctly.
    """
    groups: dict[ObjectKey, MergeGroup] = {}
    unparseable: list[FixDoc] = []

    for content in contents:
        for rule in content.rules.values():
            if not rule.has_fix:
                continue
            for fix in rule.fixes:
                key = _object_key(fix.yaml, rule.rule_id)
                if key is None:
                    unparseable.append(
                        FixDoc(rule.helm_name, ObjectKey("", "", "", ""), fix.yaml, fix.ocp_version))
                    continue
                grp = groups.setdefault(key, MergeGroup(key=key))
                grp.docs.append(FixDoc(rule.helm_name, key, fix.yaml, fix.ocp_version))

    ordered = sorted(groups.values(), key=lambda g: (g.key.kind, g.key.namespace, g.key.name))
    return ordered, unparseable


def summarize(groups: list[MergeGroup]) -> str:
    collisions = [g for g in groups if g.is_collision]
    lines = [f"{len(groups)} target objects, {len(collisions)} with collisions:"]
    for g in collisions:
        lines.append(f"  {g.key.kind}/{g.key.name} <- {len(g.rule_ids)} rules: "
                     f"{', '.join(g.rule_ids)}")
        for c in g.conflicts():
            lines.append(f"      CONFLICT on {c.path}: {', '.join(c.rules)} "
                         f"(alternatives - enable only one)")
    return "\n".join(lines)

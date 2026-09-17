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


def _leaf_paths(doc_yaml: str) -> dict[str, str]:
    """Map full dotted leaf path -> value, for content below the object root.

    Single structural pass over the raw body lines, tracking the key path
    stack. Scalar leaves map to their value. List items (``- ...``) attach to
    the path of their *immediate* parent key (by indentation), so a list is
    serialized against its true path - not first-match, and not aggregated onto
    ancestor keys. This makes two rules writing different lists to the same
    path collide, while disjoint list-bearing subtrees stay independent.
    """
    leaves: dict[str, str] = {}
    lists: dict[str, list[str]] = {}
    stack: list[tuple[int, str]] = []  # (indent, key)

    in_body = False
    block_scalar: tuple[int, str, list[str]] | None = None  # (key_indent, path, lines)
    lines_iter = doc_yaml.splitlines()
    for raw in lines_iter:
        # Inside a block scalar (| or >): consume every line more-indented than
        # the owning key as opaque scalar content, never as YAML structure.
        # This prevents a "foo: bar" line inside a script/config blob from being
        # misread as a nested key (false conflict) or masking a real one.
        if block_scalar is not None:
            key_indent, bpath, blines = block_scalar
            if not raw.strip():
                blines.append("")
                continue
            indent = len(raw) - len(raw.lstrip())
            if indent > key_indent:
                blines.append(raw.strip())
                continue
            # block scalar ended; record its serialized content as the leaf
            leaves[bpath] = "|" + "\\n".join(blines).strip()
            block_scalar = None
            # fall through to process the current line normally

        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        if stripped.startswith("- "):
            # List item belongs to the deepest key on the stack whose indent is
            # smaller than the item's indent (its parent key). The parent path
            # is that key plus all shallower ancestors.
            parent_keys = [k for ind, k in stack if ind < indent]
            if parent_keys:
                lists.setdefault(".".join(parent_keys), []).append(stripped)
            continue

        m = re.match(r"^(\s*)([\w.-]+):(.*)$", raw)
        if not m:
            continue
        key, val = m.group(2), m.group(3).strip()
        if not in_body and key in ("spec", "data", "rules", "parameters",
                                   "projectRequestTemplate", "objects"):
            in_body = True
        if not in_body:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        path = ".".join(k for _, k in stack)
        # Block scalar start: value is | or > (with optional chomping/indent
        # indicators like |-, >-, |2). Begin consuming its indented content.
        if re.match(r"^[|>][+-]?\d*\s*$", val):
            block_scalar = (indent, path, [])
            continue
        if val and val not in ("{}", "[]"):
            leaves[path] = val

    if block_scalar is not None:
        _, bpath, blines = block_scalar
        leaves[bpath] = "|" + "\\n".join(blines).strip()

    for path, items in lists.items():
        leaves[path] = "[" + ",".join(sorted(items)) + "]"
    return leaves


# Subtrees that are discriminated unions: if two rules both write under such a
# path but with differing content, they are mutually-exclusive alternatives.
_UNION_SUBTREES = ("spec.tlsSecurityProfile",)


def _detect_conflicts(docs: list[FixDoc]) -> list[Conflict]:
    # 1) same leaf path, different value.
    leaf_by_rule: dict[str, dict[str, str]] = {}
    for d in docs:
        leaf_by_rule[d.rule_id] = _leaf_paths(d.yaml)

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

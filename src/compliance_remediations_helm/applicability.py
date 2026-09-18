"""Decide which rules apply to the cluster the charts are rendered for.

Upstream rules carry XCCDF ``<platform>`` references into CPE applicability
expressions. The Compliance Operator evaluates them at scan time against the
live system: a rule whose expression is false is reported ``notapplicable`` and
no ``ComplianceRemediation`` is generated for it. A Helm chart cannot inspect
the system, so we split the leaves of those expressions in two:

  * **Facts the user declares** at install time - node architecture, whether
    the cluster is HyperShift-hosted. These become axes, and a rule that is
    active but not applicable aborts the render.
  * **Facts we assume** for RHCOS/OKD, each with a written justification. The
    safe direction is ``True``: assuming a fact holds leaves today's behaviour
    (ship the remediation; the operator reports ``notapplicable`` if it does
    not). Assuming ``False`` *disables* a rule, so it is only allowed where
    the fact is verifiably impossible on the target.

The vocabulary is closed. A leaf we have not classified raises, rather than
being silently treated as true - same stance as the resolver takes on unknown
Go-template constructs, and for the same reason: quietly guessing lands wrong
content on a node.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .parser import FactRef, LogicalTest, rules_with_fixes

AXIS_ARCH = "arch"
AXIS_HYPERSHIFT = "hypershift"

# Canonical `uname -m` spellings, sorted for deterministic output.
ARCHITECTURES = ("aarch64", "ppc64le", "s390x", "x86_64")
# Kubernetes reports the Go spellings; accept and normalize them.
ARCH_ALIASES = {"amd64": "x86_64", "arm64": "aarch64"}

DOMAINS: dict[str, frozenset] = {
    AXIS_ARCH: frozenset(ARCHITECTURES),
    AXIS_HYPERSHIFT: frozenset((True, False)),
}


class UnsupportedFact(ValueError):
    """A CPE leaf that is not in the closed vocabulary."""


class NonSeparableApplicability(ValueError):
    """An expression that per-axis constraints cannot express faithfully."""


@dataclass(frozen=True)
class Fact:
    why: str                                  # mandatory: the justification
    const: bool | None = None                 # assumed fact
    axis: str | None = None                   # declared fact
    true_when: frozenset = frozenset()        # values of `axis` where it holds


def _arch(*names: str) -> frozenset:
    return frozenset(names)


_ALL_BUT = {a: frozenset(x for x in ARCHITECTURES if x != a) for a in ARCHITECTURES}

# Exactly the leaves reachable from fix-carrying rules. Restricting it to those
# matters: across all rules the datastreams use ~85 leaves, most of them on
# check-only rules that never become chart objects.
FACTS: dict[str, Fact] = {
    # -- declared facts (axes) ------------------------------------------------
    "installed_app_is_ocp4_on_hypershift_hosted": Fact(
        why="cluster runs as a HyperShift hosted cluster",
        axis=AXIS_HYPERSHIFT, true_when=frozenset((True,))),
    "proc_sys_kernel_osrelease_arch_aarch64": Fact(
        why="nodes are aarch64",
        axis=AXIS_ARCH, true_when=_arch("aarch64")),
    "proc_sys_kernel_osrelease_arch_s390x": Fact(
        why="nodes are s390x",
        axis=AXIS_ARCH, true_when=_arch("s390x")),
    # The negation is baked into this leaf name and it is used with
    # negate="false", so a leaf cannot be modelled as a plain boolean.
    "proc_sys_kernel_osrelease_arch_not_s390x": Fact(
        why="nodes are not s390x",
        axis=AXIS_ARCH, true_when=_ALL_BUT["s390x"]),

    # -- assumed true ---------------------------------------------------------
    "system_with_kernel": Fact(
        why="RHCOS nodes run a kernel (not a container image build)",
        const=True),
    "installed_app_is_ocp4_node": Fact(
        why="node-layer rules are routed to the node chart by kind",
        const=True),
    "node_is_ocp4_master_node": Fact(
        why="node-layer rules are routed to the node chart by kind; the pool "
            "restriction is reported in RULES.md, not enforced",
        const=True),
    "package_audit": Fact(why="audit ships in RHCOS", const=True),
    "package_autofs": Fact(why="autofs ships in RHCOS", const=True),
    "package_chrony": Fact(why="chrony ships in RHCOS", const=True),
    "package_logrotate": Fact(why="logrotate ships in RHCOS", const=True),
    "package_pam": Fact(why="pam ships in RHCOS", const=True),
    "package_systemd": Fact(why="systemd ships in RHCOS", const=True),
    "package_usbguard": Fact(
        # Not on a stock node - but rhcos4-package_usbguard_installed, in this
        # same chart, installs it. Assuming False here would disable rules that
        # profiles select.
        why="usbguard is installed by rhcos4-package_usbguard_installed",
        const=True),
    "installed_env_has_grub2_package": Fact(
        why="the affected fixes are MachineConfig kernelArguments, which the "
            "MCO applies regardless of bootloader packaging",
        const=True),
    "ipv6_enabled": Fact(
        why="the IPv6 module is present on RHCOS; the sysctl drop-ins are "
            "inert when IPv6 is disabled, not harmful",
        const=True),

    # -- assumed false: verifiably impossible on the target -------------------
    "package_ntp": Fact(
        why="RHCOS uses chrony, not ntp",
        const=False),
    "package_openssh-server_le_7_0": Fact(
        why="RHCOS ships OpenSSH 8 or newer",
        const=False),
    "package_openssh-server_le_7_5": Fact(
        why="RHCOS ships OpenSSH 8 or newer",
        const=False),
    "system_boot_mode_is_non_uefi": Fact(
        why="UEFI boot is assumed; enable the rule explicitly for BIOS nodes",
        const=False),
}


@dataclass
class Applicability:
    never: bool = False
    # axis -> allowed values, present only where narrower than the full domain
    constraints: dict[str, frozenset] = field(default_factory=dict)
    platform_ids: tuple = ()
    reasons: tuple = ()

    @property
    def unconstrained(self) -> bool:
        return not self.never and not self.constraints


def _fact(name: str, where: str) -> Fact:
    try:
        return FACTS[name]
    except KeyError:
        raise UnsupportedFact(
            f"unclassified CPE fact {name!r} (reached from {where}). Add it to "
            f"applicability.FACTS with a justification - assuming it true "
            f"would ship content the operator reports as notapplicable, "
            f"assuming it false would silently disable a control."
        ) from None


def _evaluate(node, assignment: dict, where: str) -> bool:
    if isinstance(node, FactRef):
        fact = _fact(node.name, where)
        if fact.const is not None:
            return fact.const
        return assignment[fact.axis] in fact.true_when
    results = [_evaluate(c, assignment, where) for c in node.children]
    value = all(results) if node.operator == "AND" else any(results)
    return not value if node.negate else value


def _referenced(node, out: list) -> list:
    if isinstance(node, FactRef):
        out.append(node.name)
    else:
        for c in node.children:
            _referenced(c, out)
    return out


def reduce(exprs, platform_ids=(), where="<unknown>") -> Applicability:
    """Reduce CPE expressions to per-axis constraints.

    The axis space is 4 architectures x 2 HyperShift states, so enumerate all
    eight assignments and evaluate exactly rather than simplifying symbolically.
    That handles double negation, constant-folded ORs and negation-in-the-leaf
    uniformly, and yields both the Helm guard and the RULES.md text from one
    computation.
    """
    axes = sorted(DOMAINS)
    values = [sorted(DOMAINS[a], key=repr) for a in axes]
    satisfying = []
    for combo in itertools.product(*values):
        assignment = dict(zip(axes, combo))
        if all(_evaluate(e, assignment, where) for e in exprs):
            satisfying.append(combo)

    names: list[str] = []
    for e in exprs:
        _referenced(e, names)

    if not satisfying:
        reasons = tuple(dict.fromkeys(
            FACTS[n].why for n in names
            if n in FACTS and FACTS[n].const is False))
        return Applicability(never=True, platform_ids=tuple(platform_ids),
                             reasons=reasons)

    projection = {
        axis: frozenset(combo[i] for combo in satisfying)
        for i, axis in enumerate(axes)
    }
    # A per-axis guard can only be faithful if the satisfying set is the full
    # product of its projections. Nothing in today's content is non-separable;
    # this is three lines of insurance against approximating an expression.
    product = set(itertools.product(*(sorted(projection[a], key=repr) for a in axes)))
    if set(satisfying) != product:
        raise NonSeparableApplicability(
            f"applicability of {where} couples {', '.join(axes)} and cannot be "
            f"expressed as independent per-axis constraints"
        )

    constraints = {a: p for a, p in projection.items() if p != DOMAINS[a]}
    reasons = tuple(dict.fromkeys(
        FACTS[n].why for n in names
        if n in FACTS and FACTS[n].axis in constraints))
    return Applicability(constraints=constraints, platform_ids=tuple(platform_ids),
                         reasons=reasons)


def build_map(contents) -> dict[str, Applicability]:
    """helm_name -> Applicability, for every fix-carrying rule."""
    out: dict[str, Applicability] = {}
    for content in contents:
        for rule_id in sorted(rules_with_fixes(content)):
            rule = content.rules[rule_id]
            refs = rule.all_platforms
            if not refs:
                continue
            exprs: list[LogicalTest] = []
            ids: list[str] = []
            for ref in refs:
                if not ref.startswith("#"):
                    if ref.startswith("cpe:/"):
                        # Bare CPE product name; the product is the datastream.
                        continue
                    raise UnsupportedFact(
                        f"unexpected platform reference {ref!r} on {rule_id}")
                pid = ref[1:]
                if pid not in content.platforms:
                    raise UnsupportedFact(
                        f"platform {ref!r} referenced by {rule_id} is not "
                        f"defined in the datastream")
                exprs.append(content.platforms[pid])
                ids.append(pid)
            if not exprs:
                continue
            app = reduce(exprs, ids, where=rule.helm_name)
            if not app.unconstrained:
                out[rule.helm_name] = app
    return out


def never_applicable_rules(appl: dict[str, Applicability]) -> dict[str, str]:
    """helm_name -> reason, same shape as emit.default_disabled_rules()."""
    return {
        name: "; ".join(app.reasons) or "not applicable to any supported target"
        for name, app in sorted(appl.items()) if app.never
    }


def describe(app: Applicability) -> str:
    """One-line human form for the RULES.md column."""
    if app.never:
        return f"never applicable ({'; '.join(app.reasons)})" if app.reasons \
            else "never applicable"
    parts = []
    allowed = app.constraints.get(AXIS_ARCH)
    if allowed is not None:
        excluded = sorted(set(ARCHITECTURES) - allowed)
        if len(excluded) <= len(allowed):
            parts.append("not " + ", ".join(excluded))
        else:
            parts.append(", ".join(sorted(allowed)) + " only")
    hs = app.constraints.get(AXIS_HYPERSHIFT)
    if hs is not None:
        parts.append("hypershift only" if True in hs else "not hypershift")
    return "; ".join(parts) or "-"


def summarize(appl: dict[str, Applicability]) -> dict[str, int]:
    return {
        "arch": sum(1 for a in appl.values() if AXIS_ARCH in a.constraints),
        "hypershift": sum(1 for a in appl.values()
                          if AXIS_HYPERSHIFT in a.constraints),
        "never": sum(1 for a in appl.values() if a.never),
    }

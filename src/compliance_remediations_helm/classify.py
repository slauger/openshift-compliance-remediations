"""Classify remediation objects into layers.

The ocp4 datastream mixes two kinds of remediation:

  * Platform config objects (APIServer, OAuth, IngressController, Project,
    Template, PrometheusRule, ...). These carry an explicit metadata.name and
    are safe, non-disruptive cluster config - the v1 scope.

  * Node objects (KubeletConfig, MachineConfig). These have no metadata.name in
    the datastream (the operator synthesises one) and drive MachineConfigPool
    rollouts (node reboots). These are the v2 / node layer.
"""
from __future__ import annotations

# Kinds that represent node-level remediation (reboots / MachineConfigPool).
NODE_KINDS = {"MachineConfig", "KubeletConfig"}


def layer_for_kind(kind: str) -> str:
    return "node" if kind in NODE_KINDS else "platform"


def synthesize_name(kind: str, rule_id: str) -> str:
    """Match the operator's naming convention for node objects that omit a name.

    The Compliance Operator names generated node remediations after the check,
    prefixed with a MachineConfig ordering number. We mirror that so results
    map recognisably.
    """
    slug = rule_id.replace("_", "-")
    if kind == "KubeletConfig":
        return f"compliance-{slug}"
    # MachineConfig files are ordered; 75- keeps them late in the merge.
    return f"75-ocp4-{slug}"

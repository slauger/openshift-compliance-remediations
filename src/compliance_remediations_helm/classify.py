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


# The operator consolidates every kubelet remediation for a pool into one
# KubeletConfig named after the pool, rather than one per rule
# (verifyAndCompleteKC in its complianceremediation controller). The role
# suffix is appended at render time, giving compliance-operator-kubelet-worker
# and -master - the same objects the operator would create.
KUBELET_CONFIG_NAME = "compliance-operator-kubelet"


def synthesize_name(kind: str, rule_id: str) -> str:
    """Match the operator's naming convention for node objects that omit a name.

    The Compliance Operator names generated MachineConfig remediations after
    the check, prefixed with an ordering number. KubeletConfig is different:
    there is one object per MachineConfigPool that every kubelet rule merges
    into, so the name does not depend on the rule.
    """
    if kind == "KubeletConfig":
        return KUBELET_CONFIG_NAME
    slug = rule_id.replace("_", "-")
    # MachineConfig files are ordered; 75- keeps them late in the merge.
    return f"75-ocp4-{slug}"

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

# Rule families whose upstream fixes are byte-identical because each rule ships
# the whole configuration file rather than just its own setting. The operator
# emits one remediation per rule and therefore N MachineConfigs writing the
# same paths with the same bytes; we emit one. Enabling any single rule of the
# family still renders the full configuration, exactly as before - the object
# is gated on any of them being active.
#
# This is the one place we knowingly diverge from the operator's per-check
# naming, and object_template asserts the fragments really are identical, so a
# content release that makes them differ fails the build instead of silently
# picking one.
CONSOLIDATED_FAMILIES: dict[str, tuple] = {
    # The sshd family is the first consolidation whose members are *not*
    # identical: below 4.13 all 31 write the same whole sshd_config, from
    # 4.13 each writes its own drop-in. The render merges storage.files by
    # path, so the disjoint drop-ins combine and the six enable/disable
    # pairs that share a drop-in become ordinary in-object conflicts.
    #
    # disable_host_auth is deliberately NOT a member: its <=4.12 whole-file
    # payload differs from the other 31, so folding it in would make every
    # render below 4.13 fail. Kept separate, it stays the one legitimate
    # cross-object sshd guard.
    "75-ocp4-sshd": (
        "sshd_allow_only_protocol2",
        "sshd_disable_compression",
        "sshd_disable_empty_passwords",
        "sshd_disable_gssapi_auth",
        "sshd_disable_kerb_auth",
        "sshd_disable_pubkey_auth",
        "sshd_disable_rhosts",
        "sshd_disable_rhosts_rsa",
        "sshd_disable_root_login",
        "sshd_disable_root_password_login",
        "sshd_disable_tcp_forwarding",
        "sshd_disable_user_known_hosts",
        "sshd_disable_x11_forwarding",
        "sshd_do_not_permit_user_env",
        "sshd_enable_gssapi_auth",
        "sshd_enable_pam",
        "sshd_enable_pubkey_auth",
        "sshd_enable_strictmodes",
        "sshd_enable_warning_banner",
        "sshd_enable_warning_banner_net",
        "sshd_enable_x11_forwarding",
        "sshd_print_last_log",
        "sshd_set_idle_timeout",
        "sshd_set_keepalive",
        "sshd_set_login_grace_time",
        "sshd_set_loglevel_info",
        "sshd_set_loglevel_verbose",
        "sshd_set_max_auth_tries",
        "sshd_set_max_sessions",
        "sshd_set_maxstartups",
        "sshd_use_priv_separation",
    ),
    "75-ocp4-chrony": (
        "chronyd_client_only",
        "chronyd_no_chronyc_network",
        "chronyd_or_ntpd_set_maxpoll",
        "chronyd_or_ntpd_specify_multiple_servers",
        "chronyd_or_ntpd_specify_remote_server",
    ),
    "75-ocp4-auditd": (
        "auditd_data_disk_error_action",
        "auditd_data_disk_error_action_stig",
        "auditd_data_disk_full_action",
        "auditd_data_disk_full_action_stig",
        "auditd_data_retention_admin_space_left_action",
        "auditd_data_retention_flush",
        "auditd_data_retention_max_log_file",
        "auditd_data_retention_max_log_file_action",
        "auditd_data_retention_max_log_file_action_stig",
        "auditd_data_retention_num_logs",
        "auditd_data_retention_space_left",
        "auditd_data_retention_space_left_action",
        "auditd_freq",
        "auditd_local_events",
        "auditd_log_format",
        "auditd_name_format",
        "auditd_write_logs",
    ),
    "75-ocp4-audit-rules-unsuccessful-file-modification": (
        "audit_rules_unsuccessful_file_modification_creat",
        "audit_rules_unsuccessful_file_modification_ftruncate",
        "audit_rules_unsuccessful_file_modification_open",
        "audit_rules_unsuccessful_file_modification_open_by_handle_at",
        "audit_rules_unsuccessful_file_modification_open_by_handle_at_o_creat",
        "audit_rules_unsuccessful_file_modification_open_by_handle_at_o_trunc_write",
        "audit_rules_unsuccessful_file_modification_open_o_creat",
        "audit_rules_unsuccessful_file_modification_open_o_trunc_write",
        "audit_rules_unsuccessful_file_modification_openat",
        "audit_rules_unsuccessful_file_modification_openat_o_creat",
        "audit_rules_unsuccessful_file_modification_openat_o_trunc_write",
        "audit_rules_unsuccessful_file_modification_truncate",
    ),
    "75-ocp4-coredump": (
        "coredump_disable_backtraces",
        "coredump_disable_storage",
    ),
}

CONSOLIDATED_NAMES: dict[str, str] = {
    rule: name for name, rules in CONSOLIDATED_FAMILIES.items() for rule in rules
}


def synthesize_name(kind: str, rule_id: str) -> str:
    """Match the operator's naming convention for node objects that omit a name.

    The Compliance Operator names generated MachineConfig remediations after
    the check, prefixed with an ordering number. KubeletConfig is different:
    there is one object per MachineConfigPool that every kubelet rule merges
    into, so the name does not depend on the rule.
    """
    if kind == "KubeletConfig":
        return KUBELET_CONFIG_NAME
    if rule_id in CONSOLIDATED_NAMES:
        return CONSOLIDATED_NAMES[rule_id]
    slug = rule_id.replace("_", "-")
    # MachineConfig files are ordered; 75- keeps them late in the merge.
    return f"75-ocp4-{slug}"

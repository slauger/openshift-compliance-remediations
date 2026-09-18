# compliance-node

OpenShift node compliance remediations (MachineConfig/KubeletConfig; reboots).

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square)
![AppVersion: 0.1.82](https://img.shields.io/badge/AppVersion-0.1.82-informational?style=flat-square)

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cluster | object | `{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"}` | Facts about the target cluster. Rules that upstream marks as not applicable to this cluster are refused rather than silently shipped. |
| cluster.architecture | string | `"x86_64"` | Node architecture of the MachineConfigPools listed in node.roles. x86_64 | aarch64 | ppc64le | s390x (amd64 and arm64 are accepted too). Find yours: make show-node-arch |
| cluster.hypershift | bool | `false` | Set true on a HyperShift hosted cluster (hosted control plane). |
| cluster.ocpVersion | string | `"4.20"` | Target OpenShift version; selects version-dependent remediations. Find yours: oc get clusterversion version -o jsonpath='{.status.desired.version}' |
| complianceNamespace | string | `"openshift-compliance"` | Namespace the Compliance Operator watches for TailoredProfiles. |
| node | object | `{"enabled":false,"roles":["worker","master"]}` | Node remediations trigger MachineConfigPool rollouts (node reboots). Disabled by default; opt in explicitly. |
| node.enabled | bool | `false` | Master enable switch for node remediations. |
| node.roles | list | `["worker","master"]` | MachineConfigPool roles to target. On combined master+worker nodes (SNO/OKD) the node lands in the master pool, so include master there. |
| profiles | object | `{"ocp4-bsi-node":false,"ocp4-bsi-node-2022":false,"ocp4-cis-node":false,"ocp4-cis-node-1-7":false,"ocp4-cis-node-1-9":false,"ocp4-cis-vm-extension-node":false,"ocp4-high-node":false,"ocp4-high-node-rev-4":false,"ocp4-moderate-node":false,"ocp4-moderate-node-rev-4":false,"ocp4-nerc-cip-node":false,"ocp4-pci-dss-node":false,"ocp4-pci-dss-node-3-2":false,"ocp4-pci-dss-node-4-0":false,"ocp4-stig-node":false,"ocp4-stig-node-v2r2":false,"ocp4-stig-node-v2r3":false,"rhcos4-anssi_bp28_enhanced":false,"rhcos4-anssi_bp28_high":false,"rhcos4-anssi_bp28_intermediary":false,"rhcos4-bsi":false,"rhcos4-bsi-2022":false,"rhcos4-e8":false,"rhcos4-high":false,"rhcos4-high-rev-4":false,"rhcos4-moderate":false,"rhcos4-moderate-rev-4":false,"rhcos4-nerc-cip":false,"rhcos4-stig":false,"rhcos4-stig-v2r2":false,"rhcos4-stig-v2r3":false}` | Whitelist whole compliance profiles (product-namespaced, e.g. ocp4-cis). |
| rules | object | `{"rhcos4-kernel_module_vfat_disabled":false,"rhcos4-sshd_allow_only_protocol2":false,"rhcos4-sshd_use_priv_separation":false}` | Per-rule override / blacklist. Explicit value wins over profiles. Key is the product-namespaced rule name, e.g. ocp4-audit_profile_set: false Pre-populated below with two kinds of entry: for each group of mutually-exclusive alternatives the losers are disabled so whitelisting a whole profile renders out of the box (flip these to choose a different alternative), and rules upstream marks as never applicable to this target. |
| tailoredProfile | object | `{"enabled":false}` | Optionally render a matching TailoredProfile per enabled profile so the Compliance Operator scans exactly this selection. |
| variables | object | `{"sshd_idle_timeout_value":"300","sshd_max_auth_tries_value":"4","var_accounts_passwords_pam_faillock_dir":"/var/run/faillock","var_auditd_action_mail_acct":"root","var_auditd_disk_error_action":"syslog","var_auditd_disk_full_action":"syslog","var_auditd_flush":"incremental_async","var_auditd_max_log_file":"6","var_auditd_max_log_file_action":"rotate","var_auditd_num_logs":"5","var_auditd_space_left":"100","var_auditd_space_left_action":"syslog","var_event_record_qps":"50","var_kubelet_evictionhard_imagefs_available":"15%","var_kubelet_evictionhard_imagefs_inodesfree":"5%","var_kubelet_evictionhard_memory_available":"100Mi","var_kubelet_evictionhard_nodefs_available":"10%","var_kubelet_evictionhard_nodefs_inodesfree":"5%","var_kubelet_evictionsoft_imagefs_available":"20%","var_kubelet_evictionsoft_imagefs_inodesfree":"15%","var_kubelet_evictionsoft_memory_available":"500Mi","var_kubelet_evictionsoft_nodefs_available":"15%","var_kubelet_evictionsoft_nodefs_inodesfree":"10%","var_kubelet_tls_cipher_suites":"TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","var_kubelet_tls_min_version":"VersionTLS12","var_multiple_time_servers":"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org","var_oauth_inactivity_timeout":"10m0s","var_oauth_token_maxage":"28800","var_openshift_audit_profile":"WriteRequestBodies","var_rekey_limit_size":"512M","var_rekey_limit_time":"1h","var_sshd_disable_compression":"no","var_sshd_max_sessions":"10","var_sshd_priv_separation":"sandbox","var_sshd_set_keepalive":"0","var_sshd_set_login_grace_time":"60","var_sshd_set_maxstartups":"10:30:100","var_streaming_connection_timeouts":"4h0m0s","var_system_crypto_policy":"FIPS","var_time_service_set_maxpoll":"10"}` | Tunable XCCDF variables (pre-filled with upstream defaults). |

## Rules

See [`RULES.md`](../../RULES.md) for the full rule → profile matrix.

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)

# compliance-hardening

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.82](https://img.shields.io/badge/AppVersion-0.1.82-informational?style=flat-square)

Umbrella chart bundling OpenShift compliance remediations: platform config (no reboot) and node MachineConfig/KubeletConfig (reboots, opt-in).

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| file://../compliance-node | compliance-node | 0.1.0 |
| file://../compliance-platform | compliance-platform | 0.1.0 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| compliance-node | object | `{"cluster":{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"},"complianceNamespace":"openshift-compliance","node":{"enabled":false,"roles":["worker","master"]},"profiles":{},"rules":{},"tailoredProfile":{"enabled":false},"variables":{}}` | Node remediations (MachineConfig/KubeletConfig; trigger reboots). |
| compliance-node.cluster | object | `{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"}` | Facts about the target cluster. Rules that upstream marks as not applicable to this cluster are refused rather than silently shipped. |
| compliance-node.cluster.architecture | string | `"x86_64"` | Node architecture of the MachineConfigPools listed in node.roles. Only the node chart has arch-constrained rules; it is declared here too so one values file validates against either chart. x86_64 | aarch64 | ppc64le | s390x (amd64 and arm64 are accepted too). Find yours: make show-node-arch |
| compliance-node.cluster.hypershift | bool | `false` | Set true on a HyperShift hosted cluster (hosted control plane). Only the platform chart has a hypershift-constrained rule. |
| compliance-node.cluster.ocpVersion | string | `"4.20"` | Target OpenShift version; selects version-dependent remediations. Find yours: oc get clusterversion version -o jsonpath='{.status.desired.version}' |
| compliance-node.complianceNamespace | string | `"openshift-compliance"` | Namespace the Compliance Operator watches for TailoredProfiles. |
| compliance-node.node.enabled | bool | `false` | Master enable switch for node remediations (triggers reboots). |
| compliance-node.node.roles | list | `["worker","master"]` | MachineConfigPool roles to target. |
| compliance-node.profiles | object | `{}` | Whitelist whole compliance profiles; see the subchart's own values for the full list of keys. |
| compliance-node.rules | object | `{}` | Per-rule override / blacklist. The subchart's defaults still apply, so its pre-disabled alternatives and opt-in rules stay disabled. |
| compliance-node.tailoredProfile.enabled | bool | `false` | Render a matching TailoredProfile per enabled profile. |
| compliance-node.variables | object | `{}` | Tunable XCCDF variables, same keys as the subchart's values. |
| compliance-platform | object | `{"cluster":{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"},"complianceNamespace":"openshift-compliance","profiles":{},"rules":{},"tailoredProfile":{"enabled":false},"variables":{}}` | Platform remediations (safe cluster config, no reboot). |
| compliance-platform.cluster | object | `{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"}` | Facts about the target cluster. Rules that upstream marks as not applicable to this cluster are refused rather than silently shipped. |
| compliance-platform.cluster.architecture | string | `"x86_64"` | Node architecture of the MachineConfigPools listed in node.roles. Only the node chart has arch-constrained rules; it is declared here too so one values file validates against either chart. x86_64 | aarch64 | ppc64le | s390x (amd64 and arm64 are accepted too). Find yours: make show-node-arch |
| compliance-platform.cluster.hypershift | bool | `false` | Set true on a HyperShift hosted cluster (hosted control plane). Only the platform chart has a hypershift-constrained rule. |
| compliance-platform.cluster.ocpVersion | string | `"4.20"` | Target OpenShift version; selects version-dependent remediations. Find yours: oc get clusterversion version -o jsonpath='{.status.desired.version}' |
| compliance-platform.complianceNamespace | string | `"openshift-compliance"` | Namespace the Compliance Operator watches for TailoredProfiles. |
| compliance-platform.profiles | object | `{}` | Whitelist whole compliance profiles; see the subchart's own values for the full list of keys. |
| compliance-platform.rules | object | `{}` | Per-rule override / blacklist. The subchart's defaults still apply, so its pre-disabled alternatives and opt-in rules stay disabled. |
| compliance-platform.tailoredProfile.enabled | bool | `false` | Render a matching TailoredProfile per enabled profile. |
| compliance-platform.variables | object | `{}` | Tunable XCCDF variables, same keys as the subchart's values. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)

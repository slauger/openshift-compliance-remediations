# compliance-hardening

Umbrella chart bundling OpenShift compliance remediations: platform config (no node reboots) and node MachineConfig/KubeletConfig (reboots, opt-in).

![Version: 0.4.0](https://img.shields.io/badge/Version-0.4.0-informational?style=flat-square)
![AppVersion: 0.1.82](https://img.shields.io/badge/AppVersion-0.1.82-informational?style=flat-square)

## Install

This chart contains the platform objects, which are pre-existing cluster
singletons owned by cluster operators. Helm refuses to adopt them, so
`helm install` **fails** here - render and apply instead:

```sh
helm template compliance . | oc apply --server-side --force-conflicts -f -
```

Under Argo CD set `ServerSideApply=true` for the same reason. The node subchart
on its own does install normally. See the repository README for both paths.

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| file://../compliance-node | compliance-node | 0.4.0 |
| file://../compliance-platform | compliance-platform | 0.4.0 |

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
| compliance-platform | object | `{"cluster":{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"},"complianceNamespace":"openshift-compliance","profiles":{},"rules":{},"tailoredProfile":{"enabled":false},"variables":{}}` | Platform remediations (cluster config objects; no node reboots, but the audit-profile and encryption rules redeploy the kube-apiserver). |
| compliance-platform.cluster | object | `{"architecture":"x86_64","hypershift":false,"ocpVersion":"4.20"}` | Facts about the target cluster. Rules that upstream marks as not applicable to this cluster are refused rather than silently shipped. |
| compliance-platform.cluster.architecture | string | `"x86_64"` | Node architecture of the MachineConfigPools listed in node.roles. Only the node chart has arch-constrained rules; it is declared here too so one values file validates against either chart. x86_64 | aarch64 | ppc64le | s390x (amd64 and arm64 are accepted too). Find yours: make show-node-arch |
| compliance-platform.cluster.hypershift | bool | `false` | Set true on a HyperShift hosted cluster (hosted control plane). Only the platform chart has a hypershift-constrained rule. |
| compliance-platform.cluster.ocpVersion | string | `"4.20"` | Target OpenShift version; selects version-dependent remediations. Find yours: oc get clusterversion version -o jsonpath='{.status.desired.version}' |
| compliance-platform.complianceNamespace | string | `"openshift-compliance"` | Namespace the Compliance Operator watches for TailoredProfiles. |
| compliance-platform.profiles | object | `{}` | Whitelist whole compliance profiles; see the subchart's own values for the full list of keys. |
| compliance-platform.rules | object | `{}` | Per-rule override / blacklist. The subchart's defaults still apply, so its pre-disabled alternatives and opt-in rules stay disabled. |
| compliance-platform.tailoredProfile.enabled | bool | `false` | Render a matching TailoredProfile per enabled profile. |
| compliance-platform.variables | object | `{}` | Tunable XCCDF variables, same keys as the subchart's values. |

## Rules

See [`RULES.md`](../../RULES.md#coverage-per-profile) for how much of each profile
these charts can apply, and [the matrix](../../RULES.md#rules) for every rule with
its target object, applicability and profiles.

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)

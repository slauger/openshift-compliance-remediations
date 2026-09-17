# AGENTS.md

Guidance for AI agents (and humans) working on this repository.

## What this project is

A Python generator that extracts OpenShift compliance **remediations** from the upstream [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) SCAP datastreams and emits Helm charts. It reproduces, statically and reviewably, the same fixes the OpenShift Compliance Operator would apply at runtime, so hardening is managed declaratively in Git instead of approved per-scan.

## Architecture

- `src/compliance_remediations_helm/` - the generator (Python package).
  - `datastream.py` - download + SHA512-verify + extract the pinned datastreams.
  - `parser.py` - parse XCCDF into rules, fixes, profiles, variables.
  - `resolver.py` - resolve XCCDF variable defaults; rewrite `{{.var_x}}` for Helm.
  - `collisions.py` - group fixes by target object; detect merge conflicts.
  - `classify.py` - platform vs node classification; node name synthesis.
  - `emit.py` - render the charts, values, schema, TailoredProfiles, RULES.md.
  - `cli.py` - entry point `compliance-remediations-gen`.
- `config/content.yaml` - pinned content version + expected SHA512.
- `charts/` - GENERATED output (checked into Git).
- `tests/` - Python unit tests. Helm unit tests live in `charts/*/tests/`.

## Hard rules

- **Do not hand-edit `charts/` or `RULES.md`.** Both are generated. Change `src/` and run `make generate`. Manual edits are overwritten on the next generate.
- **Regeneration wipes only `charts/*/templates/`.** Hand-written `charts/*/tests/` and chart-root files (README.md.gotmpl, values.schema.json are regenerated) survive. Keep helm unit tests in `charts/*/tests/`.
- **stdlib-only.** The generator has no runtime dependencies. Do not add any.
- **ASCII only** in anything we author (code, comments, docs, generated messages). The only intentional non-ASCII are the `⚠️`/`⛔` markers in the generated `RULES.md`.
- **Verify via `make verify`** after any change (helm lint + helm unittest + python unittest + ruff). Do not rely on eyeballing the charts.
- **Determinism matters.** Generation must be byte-stable across runs so the GitOps diff reflects only real content changes. There is a test for this.

## Key design decisions

- **Rule is the unit; profiles are selectors.** A rule (and its remediation) is emitted once; profiles just list which rules they select. A rule is active if an enabled profile selects it, unless overridden in `.Values.rules`.
- **Namespaced profiles** match the operator: `ocp4-<profile>`, `rhcos4-<profile>`. Rule ids are `<product>-<rule_with_underscores>`; TailoredProfile references use the hyphenated operator form.
- **Merge + conflicts.** Several rules may target one object (e.g. `APIServer/cluster`). Disjoint contributions merge. Mutually-exclusive alternatives (e.g. two rules writing `spec.tlsSecurityProfile`) make the chart `fail` at render time; the generator pre-disables the non-winning alternatives in `values.yaml` so whitelisting a profile still renders. Winner selection is **profile-aware** (most-selected alternative wins); never elect an alternative no profile uses.
- **Two layers, one umbrella.** `compliance-platform` (no reboot) and `compliance-node` (MachineConfig/KubeletConfig, reboots, gated by `node.enabled`, emitted per role). `compliance-hardening` is a thin umbrella with per-subchart prefixed values (no `global`); subcharts install standalone.
- **Scope.** Only `ocp4` (platform) and `rhcos4` (node) datastreams are relevant for OpenShift. Other OS datastreams and `eks` are out of scope.

## Updating content

Bump `version` and `sha512` in `config/content.yaml` (the sha512 is published alongside the release asset), run `make generate`, and review the Git diff of `charts/` and `RULES.md`. The diff shows exactly which rules/fixes changed.

## Testing notes

- The charts target OpenShift/OKD CRDs (APIServer, MachineConfig, KubeletConfig, etc.). They cannot be applied to a vanilla Kubernetes cluster; use `helm template`/`lint`/`unittest` locally and apply on a real OpenShift/OKD cluster.
- On combined master+worker nodes (SNO / small OKD), the node lands in the master MachineConfigPool; set `node.roles` accordingly.

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

## Releasing

Releases are cut manually (`workflow_dispatch` on the release workflow), never on push: `charts/` must be generated and committed first, and the workflow enforces that with a drift check. semantic-release computes the version from conventional commits (`fix:` -> patch, `feat:` -> minor), writes it to `VERSION`, regenerates the charts so every `Chart.yaml` carries it, commits + tags, then packages, pushes, signs (cosign) and attests (SBOM) the OCI charts. The `VERSION` file is the single source of truth for the chart version - never edit it or `Chart.yaml` versions by hand. `0.0.0` means "unreleased working tree".

## Testing notes

Which layer covers what:

| Layer | Runs | Covers |
| --- | --- | --- |
| Offline unit tests (`tests/`, ungated classes) | always, no network | YAML scalar quoting, placeholder rewriting, block-scalar parsing, conflict detection on hand-built fixtures, name synthesis, dropped-body reporting |
| Datastream unit tests (classes wrapped in `_datastream.requires(...)`) | after `make fetch` | parse invariants, variable default resolution, conflict groups and winner selection against the pinned content |
| Determinism + drift | `make generate` + `git diff --exit-code charts/ RULES.md` in CI | byte-identical regeneration; every generator change surfaces as a reviewable diff of the committed output |
| helm-unittest (`charts/*/tests/`) | `make test` | rendered object shape per kind, and the fail path when mutually-exclusive alternatives are enabled together |

Conventions:

- Assertions against the datastream are **invariants, never exact counts**. A content bump must not require editing a number in `tests/`; if it does, the assertion was a change detector and the real intent belongs in the test instead. Exact counts live in the committed `charts/` diff, which is reviewed on every regeneration.
- The datastream tests skip when `.cache/` is absent so a fresh clone can still run the offline half. `make test-py` depends on `fetch` and sets `REQUIRE_DATASTREAM=1`, which turns that skip into a failure - a green `make test-py` always means the gated tests actually ran.
- The charts target OpenShift/OKD CRDs (APIServer, MachineConfig, KubeletConfig, etc.). They cannot be applied to a vanilla Kubernetes cluster; use `helm template`/`lint`/`unittest` locally and apply on a real OpenShift/OKD cluster.
- On combined master+worker nodes (SNO / small OKD), the node lands in the master MachineConfigPool; set `node.roles` accordingly.

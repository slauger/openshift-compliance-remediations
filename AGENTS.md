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

## Applicability

XCCDF `<platform>` constraints are parsed and enforced. The leaves of those CPE expressions are split in two: facts the user declares (`cluster.architecture`, `cluster.hypershift`) become gates, everything else is an assumption recorded in `applicability.FACTS` with a mandatory justification.

- **The vocabulary is closed.** A CPE leaf that is not classified raises, and `make generate` fails with its name. Guessing it true would ship content the operator reports as `notapplicable`; guessing it false would silently disable a control.
- **Assuming a fact holds is the safe direction.** `const=True` leaves today's behaviour. `const=False` disables a rule, so it is only allowed where the fact is verifiably impossible on the target - e.g. `package_openssh-server_le_7_5`, since RHCOS ships OpenSSH 8+. Note the counter-example: `package_usbguard` is assumed **true** even though a stock node lacks usbguard, because `rhcos4-package_usbguard_installed` in the same chart installs it.
- **Group inheritance is not optional.** Rules inherit `<platform>` from ancestor `<Group>`s, and four profile-selected usbguard rules are arch-constrained purely that way. Rule-level parsing alone misses them.
- **Reduction is by enumeration**, not symbolic simplification: the axis space is four architectures times two HyperShift states. A separability check refuses any expression a per-axis guard could only approximate.
- **KubeletConfig is consolidated per pool, not per rule.** `classify.synthesize_name` returns a constant for that kind, so every kubelet fix lands in one merge group rendered per role - mirroring the operator's `verifyAndCompleteKC`, which names the object `compliance-operator-kubelet-<pool>` and sets `spec.machineConfigPoolSelector`. The selector is the load-bearing part: without it the MCO matches no pool and the object silently does nothing. It is merged per role (the label contains the pool name), so the render deep-copies `$merged` inside the role loop.
- **A non-applicable active rule aborts the render**, centrally, listing every offender. Per-architecture overlays (`values-<arch>.yaml`) are generated so the remedy is one `-f`, not a hand-maintained list.

## Conflicts across objects

The collision detector works inside one object. Across objects the MCO decides: `MergeMachineConfigs` sorts alphanumerically, takes the first Ignition config as the base and merges the rest, so for a duplicate file path the later MachineConfig silently wins.

`cross_object_file_conflicts()` finds paths two different objects write differently and emits a `fail` guard per path into the generated `preflight.yaml`. Two things it gets right and a naive version would not:

- **Conflicts are between content groups, not rules.** 31 rules write the same `/etc/ssh/sshd_config` and are fine together; only the one that differs makes it a conflict.
- **Each guard carries its version window.** The drop-ins exist from 4.13, the whole-file variants only below it. Without `semverCompare` a guard would fire where the fragments do not even render - and break every profile.

`RULES.md` marks only the genuinely pairwise cases ⚠️ alt; marking all 32 sshd rules would be noise, so the legend covers that case in prose.

## Rule dependencies

`complianceascode.io/depends-on` is parsed onto `Rule.depends_on` and enforced by `cr.dependencyPreflight`, next to the applicability preflight in the same generated `preflight.yaml`.

- **Directional.** Only "rule active, dependency not" fails. The reverse is legitimate and must not - the operator would not complain either.
- **Only dependencies this chart emits can be checked.** `cr.ruleActive` resolves through `profileRules` and the `rules` override, and both only carry fix-carrying rules; a dependency outside that set would read as inactive and fail every render. `unverifiable_dependencies()` reports any such case through the CLI, and a datastream test asserts the list is empty, so it is not just a line of output nobody reads.

## Rules whose upstream fix cannot work

`broken_rules()` detects a `tlsSecurityProfile` written with a capitalized `Custom:` and no sibling `type:`. The API server prunes the unknown field, so the remediation applies and does nothing - validated against the genuine CRDs, not inferred.

They were already shipped disabled and marked in `RULES.md`, but that knowledge lived only in docs: opting one in rendered the broken object with no failure. `cr.brokenPreflight` refuses it now. The detection feeds both `RULES.md` and the generated `brokenRules` map, so the two cannot drift.

## Opt-in rules

`emit.OPT_IN_RULES` ships a rule disabled even though a profile selects it. This is **our** judgement, not an upstream constraint - nothing in the content says not to apply these - so the bar is high: only rules whose failure mode is loss of the node or of the access needed to fix it. Each entry carries its reason, which lands in `values.yaml` next to the entry and as **⚠️ opt-in** in `RULES.md`.

Resist growing this list. Disabling a rule that a compliance profile selects is a deviation from that profile; the chart's job is to implement the profile, not to second-guess it. "This reboots nodes" is not a reason - the whole node chart does that, which is why it is gated behind `node.enabled`.

## Testing notes

Which layer covers what:

| Layer | Runs | Covers |
| --- | --- | --- |
| Offline unit tests (`tests/`, ungated classes) | always, no network | YAML scalar quoting, placeholder rewriting, block-scalar parsing, conflict detection on hand-built fixtures, name synthesis, dropped-body reporting |
| Datastream unit tests (classes wrapped in `_datastream.requires(...)`) | after `make fetch` | parse invariants, variable default resolution, conflict groups and winner selection against the pinned content |
| Determinism + drift | `make generate` + `git diff --exit-code charts/ RULES.md` in CI | byte-identical regeneration; every generator change surfaces as a reviewable diff of the committed output |
| helm-unittest (`charts/*/tests/`) | `make test` | rendered object shape per kind, and the fail path when mutually-exclusive alternatives are enabled together |
| Applicability (`scripts/validate_payloads.py arch`, `charts/*/tests/applicability_test.yaml`) | `make validate-payloads` and `make test` | renders once per architecture with its overlay, proves the gate fires without it, and that the schema rejects a bad architecture |
| Cross-object files (`scripts/validate_payloads.py`) | `make validate-payloads` | no two MachineConfigs for one pool write the same path with different content - the collision detector only sees inside one object, and across objects the MCO silently takes the alphanumerically later one |
| Object-shape checks (`scripts/validate_payloads.py`) | `make validate-payloads` | every rendered document has a body, and every KubeletConfig a non-empty pool selector - a whole kind can otherwise be a no-op that passes every YAML-level check |
| Payload validation (`scripts/validate_payloads.py`) | `make validate-payloads` | every profile renders on its own; every Ignition `data:,` payload is decoded and run through the parser that owns that file on the node (`sshd -t`, sysctl/auditd syntax, `ignition-validate`) |

Conventions:

- Assertions against the datastream are **invariants, never exact counts**. A content bump must not require editing a number in `tests/`; if it does, the assertion was a change detector and the real intent belongs in the test instead. Exact counts live in the committed `charts/` diff, which is reviewed on every regeneration.
- **The generator is stdlib-only; the tests are not.** `dependencies = []` in `pyproject.toml` is about the shipped package - `src/` must import nothing outside the standard library. `tests/` and `scripts/` may use the `dev` extra, and `make test-py` installs it, because the tests that cover `scripts/validate_payloads.py` need the same PyYAML it does.
- The datastream tests skip when `.cache/` is absent so a fresh clone can still run the offline half. `make test-py` depends on `fetch` and sets `REQUIRE_DATASTREAM=1`, which turns that skip into a failure - a green `make test-py` always means the gated tests actually ran.
- A manifest can be valid YAML, a valid MachineConfig and still write a file the node rejects: the Ignition `data:,` payload is an opaque string to every YAML-level tool. That is what `validate_payloads.py` looks at, matrixed over `cluster.ocpVersion` because version-gated fix variants mean a payload can be correct at 4.18 and broken at 4.12. Checks whose tool is missing are reported as skipped, never silently passed.
- The charts target OpenShift/OKD CRDs (APIServer, MachineConfig, KubeletConfig, etc.). They cannot be applied to a vanilla Kubernetes cluster; use `helm template`/`lint`/`unittest` locally and apply on a real OpenShift/OKD cluster.
- On combined master+worker nodes (SNO / small OKD), the node lands in the master MachineConfigPool; set `node.roles` accordingly.

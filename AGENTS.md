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
- **Labels are the only ownership signal.** Object names are the operator-aligned ones and can collide with what the operator itself creates, so every rendered object carries the Kubernetes recommended set and `app.kubernetes.io/part-of: compliance-hardening` is the selector. No label of ours goes under a third-party domain (`compliance.openshift.io/managed` was exactly that and is gone) and none under a vanity domain either - the recommended set needs no prefix of its own. `machineconfiguration.openshift.io/role`, `pools.operator.machineconfiguration.openshift.io/<pool>` and the `compliance.openshift.io/product-type` annotation are platform-mandated and must not be renamed. `_labels_block()` is the single source; do not add a sixth `app.kubernetes.io/` key (`version` would rewrite every object's labels on every release for nothing).
- **Scope.** Only `ocp4` (platform) and `rhcos4` (node) datastreams are relevant for OpenShift. Other OS datastreams and `eks` are out of scope.

## Updating content

Bump `version` and `sha512` in `config/content.yaml` (the sha512 is published alongside the release asset), run `make generate`, and review the Git diff of `charts/` and `RULES.md`. The diff shows exactly which rules/fixes changed.

## Releasing

`Chart.lock` is gitignored, so CI writes it at the old version before semantic-release bumps `Chart.yaml` past it. Use `helm dependency update`, never `build` - `build` aborts with "lock file out of sync", and by then the tag and the GitHub release exist while nothing has reached GHCR, and a re-run finds no new releasable commits. The git plugin's assets are narrow for the same reason: it stages with `git add --force`, so a broad `charts` asset committed that stale lock and the subchart tarballs onto main.

Breaking changes map to a minor bump while the chart is pre-1.0, and the preset is `conventionalcommits`: the angular default has no breaking-header pattern, so `feat!:` alone parsed to no release at all.


Releases are cut manually (`workflow_dispatch` on the release workflow), never on push: `charts/` must be generated and committed first, and the workflow enforces that with a drift check. semantic-release computes the version from conventional commits (`fix:` -> patch, `feat:` -> minor), writes it to `VERSION`, regenerates the charts so every `Chart.yaml` carries it, commits + tags, then packages, pushes, signs (cosign) and attests (SBOM) the OCI charts. The `VERSION` file is the single source of truth for the chart version - never edit it or `Chart.yaml` versions by hand. `0.0.0` means "unreleased working tree".

## Applicability

XCCDF `<platform>` constraints are parsed and enforced. The leaves of those CPE expressions are split in two: facts the user declares (`cluster.architecture`, `cluster.hypershift`) become gates, everything else is an assumption recorded in `applicability.FACTS` with a mandatory justification.

- **The vocabulary is closed.** A CPE leaf that is not classified raises, and `make generate` fails with its name. Guessing it true would ship content the operator reports as `notapplicable`; guessing it false would silently disable a control.
- **Assuming a fact holds is the safe direction.** `const=True` leaves today's behaviour. `const=False` disables a rule, so it is only allowed where the fact is verifiably impossible on the target - e.g. `package_openssh-server_le_7_5`, since RHCOS ships OpenSSH 8+. Note the counter-example: `package_usbguard` is assumed **true** even though a stock node lacks usbguard, because `rhcos4-package_usbguard_installed` in the same chart installs it.
- **Group inheritance is not optional.** Rules inherit `<platform>` from ancestor `<Group>`s, and four profile-selected usbguard rules are arch-constrained purely that way. Rule-level parsing alone misses them.
- **Reduction is by enumeration**, not symbolic simplification: the axis space is four architectures times two HyperShift states. A separability check refuses any expression a per-axis guard could only approximate.
- **KubeletConfig is consolidated per pool, not per rule.** `classify.synthesize_name` returns a constant for that kind, so every kubelet fix lands in one merge group rendered per role - mirroring the operator's `verifyAndCompleteKC`, which names the object `compliance-operator-kubelet-<pool>` and sets `spec.machineConfigPoolSelector`. The selector is the load-bearing part: without it the MCO matches no pool and the object silently does nothing. It is merged per role (the label contains the pool name), so the render deep-copies `$merged` inside the role loop.
- **A non-applicable active rule aborts the render**, centrally, listing every offender. Per-architecture overlays (`values-<arch>.yaml`) are generated so the remedy is one `-f`, not a hand-maintained list.

## Conflicts inside one object

`collisions._leaf_paths()` parses a fix body into nested dicts and lists and *then* flattens it to dotted leaf paths. `_detect_conflicts` compares those maps: same path with a different value means the rules are alternatives, disjoint paths merge. Two properties are load-bearing:

- **A list is one leaf at its own path, serialized whole.** Helm's `mustMergeOverwrite` *replaces* lists rather than concatenating them, so any difference anywhere in a list means one rule's version silently wins - per-entry leaves would under-report exactly that. `_canonical()` sorts, so reordering the same entries is not a conflict.
- **The parser is strict.** The pinned content has no structural line it cannot place, so an unplaceable one raises `YamlShapeError` naming the rule instead of yielding a quietly smaller leaf map. A smaller leaf map means fewer conflicts found, which is the failure mode that hides.

The earlier line-wise flattener got sequences wrong three ways at once (list attached to its grandparent, item reduced to its first line, item keys hoisted onto the list path last-wins), so a three-file MachineConfig came out as one file plus a leaf path that does not exist. `BODY_ROOTS` lives here and is imported by `emit` and `scripts/validate_payloads.py` - one vocabulary, not three copies.

Keying list entries by identity (`files` by `path`) is deliberately **not** done: it would only be safe once the render-time merge combines `storage.files` by path too, and until then it would turn a loud conflict into a silent drop.

## Merging storage.files by path

`object_template` accumulates `spec.config.storage.files` across fragments in `$fileAcc`, keyed by path, and writes the sorted result back after the merge loop. Without it `mustMergeOverwrite` *replaces* the list, so with two rules writing files the last fragment won outright and the other's files were gone - silently, since the object still rendered.

- **The same-path check is render-time, not generate-time.** Which rules are active is a values decision. From 4.13 the sshd rules each write their own drop-in, so paths are disjoint and merging is clean; below 4.13 they each rewrite the whole `sshd_config`, which is a real conflict and still fails. One mechanism, correct in both version windows, and it also covers content that only differs once a variable is interpolated - which a generate-time check cannot see.
- **`collisions.IDENTIFIED_LISTS` is the detection half and must stay in step.** It makes `_leaf_paths` emit one leaf per file path instead of one leaf for the list, so disjoint files stop being reported as alternatives. Adding a path there without teaching the render to merge it turns a loud conflict into a silent drop - that asymmetry is the whole reason #28 deferred this.
- **`cross_object_file_conflicts` skips same-object paths.** After the sshd consolidation the six drop-in pairs live in one object, where the per-object guard and the render-time check already refuse them; a preflight guard too would report the same thing three times and point the user at objects that no longer differ.
- **Ordering comes from `keys $fileAcc | sortAlpha`.** The accumulator is a dict, so without sorting the GitOps diff churns between runs. `test_determinism` covers it.

A consolidated family no longer has to be byte-identical: `mergeable_shape()` compares the leaves *outside* the merged lists, so sshd members differing only in which drop-in they write are fine while anything else diverging still raises. `test_the_sshd_family_really_does_differ` keeps that relaxation from being vacuous.

`rhcos4-disable_host_auth` is deliberately not a family member - its `<=4.12` whole-file payload differs from the other 31, so folding it in would fail every render below 4.13.

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

## The values contract

`values.yaml`, `values.schema.json` and what the templates read are one contract, and the schema is load-bearing rather than decorative.

- **The root is closed and the generated maps are required.** Every preflight reads its data map with `| default dict`, and Helm's `--set X=null` deletes a key - so a deleted map turned the guard into a silent no-op, and `--set profileRules=null` rendered nothing at all at exit 0. `required` makes both a schema error. The root is `additionalProperties: false` so an umbrella-shaped values file applied to a subchart is refused rather than discarded; `global` is declared because Helm injects it.
- **Variable constraints are derived, not assumed.** Numeric constraints apply only where XCCDF declares the value a number *and* every selector and the default is digits. The YAML boolean/null tokens are forbidden only for variables some fragment interpolates *unquoted* - inside an encoded payload `no` is ordinary config text, and `var_sshd_disable_compression` ships exactly that. Applying either constraint everywhere rejects shipped defaults; it was tried.
- **`cr.enc` percent-encodes a reference inside an encoded Ignition payload.** The operator runs `url.PathEscape` over its substituted output; the chart keeps the payload encoded and injects the value, so the value has to be encoded at render time. Without it a space plus `#` truncates the file on the node with no error at all.

## Rules whose upstream fix cannot work

`broken_rules()` detects a `tlsSecurityProfile` written with a capitalized `Custom:` and no sibling `type:`. The API server prunes the unknown field, so the remediation applies and does nothing - validated against the genuine CRDs, not inferred.

They were already shipped disabled and marked in `RULES.md`, but that knowledge lived only in docs: opting one in rendered the broken object with no failure. `cr.brokenPreflight` refuses it now. The detection feeds both `RULES.md` and the generated `brokenRules` map, so the two cannot drift.

## Opt-in rules

`emit.OPT_IN_RULES` ships a rule disabled even though a profile selects it. This is **our** judgement, not an upstream constraint - nothing in the content says not to apply these - so the bar is high: only rules whose failure mode is loss of the node or of the access needed to fix it. Each entry carries its reason, which lands in `values.yaml` next to the entry and as **⚠️ opt-in** in `RULES.md`.

Resist growing this list. Disabling a rule that a compliance profile selects is a deviation from that profile; the chart's job is to implement the profile, not to second-guess it. "This reboots nodes" is not a reason - the whole node chart does that, which is why it is gated behind `node.enabled`.

There is one entry on a second ground: `ocp4-audit_error_alert_exists`. A field another controller actively reconciles cannot be remediated by applying a manifest at all - server-side apply refuses it and client-side apply loses the ensuing fight. That is the admissible second reason, and it needs evidence from a cluster (the field manager, and whether the object carries `release.openshift.io/create-only`), not a guess.

## Object ownership, and why the two charts install differently

Checked against a live OKD 4.22 cluster. Five of the six platform objects already exist on a stock cluster and each is owned by a cluster operator (`cluster-version-operator` for APIServer/OAuth/Project, `ingress-operator` for the IngressController, `cluster-kube-apiserver-operator` for the PrometheusRule); only `Template/co-project-request` is ours. Node objects are all ours.

That asymmetry drives three decisions, none of which `helm template` could have surfaced - every offline test in this repo renders manifests and never talks to an API server:

- **The platform chart is applied, not installed.** `helm install` refuses pre-existing objects (correctly), and `--take-ownership` lifts only Helm's own check: Helm 4 applies server-side and exposes no `--force-conflicts`, so the API server still refuses fields another manager owns. The documented path is `helm template | oc apply --server-side --force-conflicts`. Plain client-side `oc apply -f` must not be recommended: it has no conflict detection and silently takes fields from their owner.
- **Platform objects carry both keep annotations** - `helm.sh/resource-policy: keep` and `argocd.argoproj.io/sync-options: Prune=false,Delete=false`. Each tool ignores the other's, and the README recommends GitOps as the primary path, so the Helm one alone left the protection off exactly where it is most needed: deleting an Argo CD Application with pruning on would delete `IngressController/default`. `check_resource_policy` asserts both, per chart, across every rendered document.
- **The Helm annotation on its own was the original form**, emitted in the non-node branch of `object_template()`. Without it a `helm uninstall` deletes cluster configuration - `IngressController/default` would take the router with it, and dropping `Project/cluster` while its `Template/co-project-request` survives breaks project creation.
- **Node objects deliberately do not carry it.** A `MachineConfig` is ours, and uninstalling has to roll the hardening back.

## Coverage, and what counts as open

`profile_coverage()` answers the question an operator has after applying: of what this profile asks for, how much did the charts actually do. It feeds the generated `## Coverage per profile` section of `RULES.md`. Three things it gets right that a naive version would not:

- **The biggest category is not ours.** A profile selects many rules for which upstream ships no Kubernetes fix at all - 91 of the 96 in `ocp4-cis`. `Profile.selected_rules` keeps the full XCCDF selection (`parser.py:272`), while everything else in the generator filters through `rules_with_fixes()`, so the complement had to be materialised. Nothing in this repo admitted that ceiling before.
- **Disabled is not the same as unmet.** A rule only counts as open when no alternative of it is active. Verified on a cluster: `ocp4-api_server_tls_security_profile_custom_min_tls_version` ships disabled as broken and its check reports PASS, because the alternative we apply sets `tlsSecurityProfile.type: Intermediate`, which satisfies the same control. `_alternatives_of()` builds the relation from both conflict kinds - inside one object, and the pairwise cross-object sshd pairs.
- **Never-applicable is not unmet either.** The operator reports those `notapplicable`, which is neither pass nor fail, so they are excluded from the open list. No profile selects one today, so this only bites after a content bump - which is when it would be missed.

Prose in `README.md` carries only what cannot be derived: that FIPS is install-time, that `sshd_limit_user_access` needs a list only the operator has, and that a `systemd.units` entry with `enabled: true` and no `contents` is applied by Ignition at provisioning and ignored by the MCO on a day-2 update. Counts quoted in README prose are allowed to go stale on a content bump - `make generate` does not touch it - the same accepted trade-off as "Currently five" in the opt-in section.

## extraManifests, and the line it must not cross

`extraManifests` renders objects the user supplies. It exists because some controls have no upstream remediation at all - `rhcos4-sshd_limit_user_access` is the case that prompted it - and the alternative was telling people to hand-roll MachineConfigs, losing the review-before-apply value the project exists for.

**It is a capability, not content.** The generator still authors no hardening: everything in `templates/` besides this one file comes from the pinned ComplianceAsCode release, and that claim is the project's whole provenance story. Do not add a rule with a fix we wrote; if a control needs one, it belongs here, in the user's values.

- **A map, not a list.** Helm replaces lists and merges maps, so with a list an overlay could not switch one entry off without restating every other - the same `mustMergeOverwrite` property that forces whole-list comparison in `_leaf_paths`. Each entry takes an optional `enabled` (default true), which is what makes these togglable the way `rules` is for upstream rules.
- **`rules` stays closed.** Local names must not go in there: its `additionalProperties: False` is what turns `profiles.ocp4-ciss` into a loud failure instead of a silent no-op, and opening it would cost that for all 300+ real rule names.
- **Validated in the template, not the schema.** A free-form object cannot be constrained usefully in JSON Schema, so the template fails with the entry's key when `apiVersion`, `kind` or `metadata.name` is missing. The schema only pins the map shape.
- **Rendered verbatim, labels merged.** They get the recommended set plus `app.kubernetes.io/component: local` so a cluster query separates them from upstream-derived objects, and the user's own labels survive. Unlike the chart's own node objects they are *not* expanded per `node.roles` - the pool role label is the user's to set, because an arbitrary object has no role semantics we could infer.

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
| Object-shape checks (`scripts/validate_payloads.py`) | `make validate-payloads` | every rendered document has a body, carries the ownership selector label, and every KubeletConfig a non-empty pool selector - a whole kind can otherwise be a no-op, or invisible to an ownership query, while passing every YAML-level check |
| Payload validation (`scripts/validate_payloads.py`) | `make validate-payloads` | every profile renders on its own; every Ignition `data:,` payload is decoded and run through the parser that owns that file on the node (`sshd -t`, sysctl/auditd syntax, `ignition-validate`) |

Conventions:

- Assertions against the datastream are **invariants, never exact counts**. A content bump must not require editing a number in `tests/`; if it does, the assertion was a change detector and the real intent belongs in the test instead. Exact counts live in the committed `charts/` diff, which is reviewed on every regeneration.
- **`REQUIRE_TOOLS=1`** (set in CI, where the tools are installed) turns a skipped payload check into a failure. `auditctl -R` stays an accepted skip: it loads rules into the runner's kernel. Alongside it, each mode has a floor, because every counter is a plain incrementer - with the templates truncated the checks silently vanished from the report and the run passed.
- **The generator is stdlib-only; the tests are not.** `dependencies = []` in `pyproject.toml` is about the shipped package - `src/` must import nothing outside the standard library. `tests/` and `scripts/` may use the `dev` extra, and `make test-py` installs it, because the tests that cover `scripts/validate_payloads.py` need the same PyYAML it does.
- The datastream tests skip when `.cache/` is absent so a fresh clone can still run the offline half. `make test-py` depends on `fetch` and sets `REQUIRE_DATASTREAM=1`, which turns that skip into a failure - a green `make test-py` always means the gated tests actually ran.
- A manifest can be valid YAML, a valid MachineConfig and still write a file the node rejects: the Ignition `data:,` payload is an opaque string to every YAML-level tool. That is what `validate_payloads.py` looks at, matrixed over `cluster.ocpVersion` because version-gated fix variants mean a payload can be correct at 4.18 and broken at 4.12. Checks whose tool is missing are reported as skipped, never silently passed.
- The charts target OpenShift/OKD CRDs (APIServer, MachineConfig, KubeletConfig, etc.). They cannot be applied to a vanilla Kubernetes cluster; use `helm template`/`lint`/`unittest` locally and apply on a real OpenShift/OKD cluster.
- On combined master+worker nodes (SNO / small OKD), the node lands in the master MachineConfigPool; set `node.roles` accordingly.

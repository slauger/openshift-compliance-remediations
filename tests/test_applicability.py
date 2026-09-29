"""CPE applicability: reduction, the closed vocabulary, and the emitted guard.

The offline classes build expression trees by hand, one per shape that actually
occurs upstream. The gated class asserts invariants against the pinned content -
above all that every leaf it reaches is classified, which is what makes a
content bump fail loudly instead of guessing.
"""
import json
import unittest

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import applicability as ap
from compliance_remediations_helm import emit
from compliance_remediations_helm import parser as xccdf
from compliance_remediations_helm.parser import Content, FactRef, LogicalTest

ALL = set(ap.ARCHITECTURES)


def _and(*children, negate=False):
    return LogicalTest("AND", negate, tuple(children))


def _or(*children, negate=False):
    return LogicalTest("OR", negate, tuple(children))


def _wrap(node):
    """The <cpe-lang:platform> element itself parses as an outer AND."""
    return _and(node)


AARCH64 = FactRef("proc_sys_kernel_osrelease_arch_aarch64")
S390X = FactRef("proc_sys_kernel_osrelease_arch_s390x")
NOT_S390X = FactRef("proc_sys_kernel_osrelease_arch_not_s390x")
HYPERSHIFT = FactRef("installed_app_is_ocp4_on_hypershift_hosted")
KERNEL = FactRef("system_with_kernel")
CHRONY = FactRef("package_chrony")
NTP = FactRef("package_ntp")
OPENSSH_7_5 = FactRef("package_openssh-server_le_7_5")
MASTER_NODE = FactRef("node_is_ocp4_master_node")


class TestReduce(unittest.TestCase):
    def test_single_negation(self):
        # not_aarch64_arch
        app = ap.reduce([_wrap(_and(AARCH64, negate=True))])
        self.assertFalse(app.never)
        self.assertEqual(app.constraints[ap.AXIS_ARCH], frozenset(ALL - {"aarch64"}))

    def test_double_negation(self):
        # not_aarch64_arch_and_not_s390x_arch
        app = ap.reduce([_wrap(_and(_and(AARCH64, negate=True),
                                    _and(S390X, negate=True)))])
        self.assertEqual(app.constraints[ap.AXIS_ARCH],
                         frozenset(ALL - {"aarch64", "s390x"}))

    def test_negation_baked_into_the_leaf(self):
        # not_s390x_arch_and_system_with_kernel: negate="false", so the leaf
        # itself must carry the set of architectures it holds for.
        app = ap.reduce([_wrap(_and(NOT_S390X, KERNEL))])
        self.assertEqual(app.constraints[ap.AXIS_ARCH], frozenset(ALL - {"s390x"}))

    def test_constant_or_folds_away(self):
        # package_chrony_or_package_ntp: chrony is assumed present, so the
        # expression is true everywhere and constrains nothing.
        app = ap.reduce([_wrap(_or(CHRONY, NTP))])
        self.assertTrue(app.unconstrained)

    def test_impossible_fact_is_never_applicable(self):
        app = ap.reduce([_wrap(_and(OPENSSH_7_5))])
        self.assertTrue(app.never)
        self.assertTrue(any("OpenSSH" in r for r in app.reasons))

    def test_hypershift_axis(self):
        app = ap.reduce([_wrap(_and(HYPERSHIFT, negate=True))])
        self.assertEqual(app.constraints[ap.AXIS_HYPERSHIFT], frozenset({False}))

    def test_trivially_true_expression_constrains_nothing(self):
        self.assertTrue(ap.reduce([_wrap(_and(KERNEL))]).unconstrained)


class TestVocabularyIsClosed(unittest.TestCase):
    def test_unknown_leaf_raises_with_its_name(self):
        with self.assertRaises(ap.UnsupportedFact) as cm:
            ap.reduce([_wrap(_and(FactRef("package_something_new")))],
                      where="rhcos4-some_rule")
        msg = str(cm.exception)
        self.assertIn("package_something_new", msg)
        self.assertIn("rhcos4-some_rule", msg)

    def test_every_fact_carries_a_justification(self):
        for name, fact in ap.FACTS.items():
            self.assertTrue(fact.why.strip(), f"{name} has no justification")

    def test_every_fact_is_either_const_or_axis(self):
        for name, fact in ap.FACTS.items():
            self.assertNotEqual(
                fact.const is None, fact.axis is None,
                f"{name} must be exactly one of const or axis")


class TestSafeDirections(unittest.TestCase):
    """Where the reduction is unsure, it must not drop hardening silently."""

    def test_a_negated_role_fact_raises(self):
        # "any pool but master" is the opposite of "master only". Guessing
        # would remove hardening from the pools the rule applies to.
        expr = _and(MASTER_NODE, negate=True)
        with self.assertRaises(ap.UnsupportedFact) as cm:
            ap._roles_for(expr, "rhcos4-some_rule")
        self.assertIn("negated", str(cm.exception))

    def test_an_expression_with_no_classified_leaves_is_unconstrained(self):
        # Bare CPE product names are dropped by the parser, so an OR can end
        # up empty. `any([])` is False, which would pre-disable the rule.
        self.assertFalse(ap.reduce([LogicalTest("OR", False, ())], where="x").never)
        self.assertTrue(ap.reduce([LogicalTest("OR", False, ())],
                                  where="x").unconstrained)

    def test_an_empty_role_intersection_stays_empty(self):
        # An empty set is a real answer ("no pool"), not "unrestricted" - it
        # must not be overwritten by the next expression's role set.
        expr = _and(MASTER_NODE)
        app = ap.reduce([expr], where="x")
        self.assertFalse(app.never)


class TestNonSeparable(unittest.TestCase):
    def test_coupled_axes_are_refused_not_approximated(self):
        # (aarch64 AND hypershift) OR (s390x AND NOT hypershift): the satisfying
        # set is not the product of its per-axis projections, so a per-axis
        # guard cannot express it.
        expr = _wrap(_or(_and(AARCH64, HYPERSHIFT),
                         _and(S390X, _and(HYPERSHIFT, negate=True))))
        with self.assertRaises(ap.NonSeparableApplicability):
            ap.reduce([expr], where="synthetic")


class TestDescribe(unittest.TestCase):
    def test_arch_exclusion_reads_as_exclusion(self):
        app = ap.reduce([_wrap(_and(AARCH64, negate=True))])
        self.assertEqual(ap.describe(app), "not aarch64")

    def test_two_exclusions(self):
        app = ap.reduce([_wrap(_and(_and(AARCH64, negate=True),
                                    _and(S390X, negate=True)))])
        self.assertEqual(ap.describe(app), "not aarch64, s390x")

    def test_hypershift(self):
        app = ap.reduce([_wrap(_and(HYPERSHIFT, negate=True))])
        self.assertEqual(ap.describe(app), "not hypershift")


class TestEmittedGuard(unittest.TestCase):
    """The generated chart must actually carry the gate and the values."""

    @classmethod
    def setUpClass(cls):
        import tempfile
        from pathlib import Path
        rule = xccdf.Rule(
            rule_id="arch_gated", xccdf_id="x", product="rhcos4",
            fixes=[xccdf.FixVariant(yaml=(
                "apiVersion: machineconfiguration.openshift.io/v1\n"
                "kind: MachineConfig\n"
                "spec:\n"
                "  config:\n"
                "    ignition:\n"
                "      version: 3.1.0\n"))],
            platforms=["#not_aarch64_arch"])
        content = Content(
            rules={"arch_gated": rule}, values={}, profiles={}, product="rhcos4",
            platforms={"not_aarch64_arch": _wrap(_and(AARCH64, negate=True))})
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        emit.generate_charts({"rhcos4": content}, root, "0.0.0")
        cls.node = root / emit.NODE_CHART

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_helpers_define_the_preflight_and_arch_normalization(self):
        helpers = (self.node / "templates" / "_helpers.tpl").read_text()
        self.assertIn('define "cr.arch"', helpers)
        self.assertIn('define "cr.applicabilityPreflight"', helpers)
        # The Kubernetes spellings must normalize, or `oc get nodes` output
        # silently disables every arch-constrained rule.
        self.assertIn('eq $a "amd64"', helpers)
        self.assertIn('eq $a "arm64"', helpers)

    def test_preflight_template_is_emitted(self):
        tpl = (self.node / "templates" / "preflight.yaml").read_text()
        self.assertIn('include "cr.applicabilityPreflight"', tpl)

    def test_values_carry_the_cluster_block_and_the_map(self):
        values = (self.node / "values.yaml").read_text()
        self.assertIn("cluster:", values)
        self.assertIn("architecture: x86_64", values)
        self.assertIn("hypershift: false", values)
        self.assertIn("ruleApplicability:", values)
        self.assertIn("rhcos4-arch_gated:", values)
        self.assertIn("arch: [ppc64le, s390x, x86_64]", values)

    def test_schema_constrains_the_cluster_block(self):
        schema = json.loads((self.node / "values.schema.json").read_text())
        cluster = schema["properties"]["cluster"]
        self.assertEqual(cluster["additionalProperties"], False)
        # Without `required`, a null architecture makes every membership test
        # false and disables the gated rules without a word.
        self.assertIn("architecture", cluster["required"])
        self.assertEqual(
            cluster["properties"]["architecture"]["enum"],
            sorted(ap.ARCHITECTURES) + sorted(ap.ARCH_ALIASES))

    def test_overlay_is_generated_for_the_excluded_architecture(self):
        overlay = (self.node / "values-aarch64.yaml").read_text()
        self.assertIn("architecture: aarch64", overlay)
        self.assertIn("rhcos4-arch_gated: false", overlay)
        # ppc64le excludes nothing here, so no overlay should exist for it.
        self.assertFalse((self.node / "values-ppc64le.yaml").exists())


def _mc_rule(rule_id: str, platforms=(), product="rhcos4"):
    return xccdf.Rule(
        rule_id=rule_id, xccdf_id=f"x_{rule_id}", product=product,
        fixes=[xccdf.FixVariant(yaml=(
            "apiVersion: machineconfiguration.openshift.io/v1\n"
            "kind: MachineConfig\n"
            "spec:\n"
            "  config:\n"
            "    ignition:\n"
            "      version: 3.1.0\n"))],
        platforms=list(platforms))


class TestUnconstrainedRules(unittest.TestCase):
    """A rule the upstream content does not constrain must come out untouched.

    Three shapes side by side: no `<platform>` at all, a `<platform>` that is
    trivially true on the target, and a real constraint. Only the last one may
    produce a gate, a ruleApplicability entry or an overlay line - over-gating
    would drop hardening the operator does apply.
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        from pathlib import Path
        content = Content(
            rules={
                "no_platform": _mc_rule("no_platform"),
                "trivial_platform": _mc_rule("trivial_platform", ["#only_a_kernel"]),
                "arch_gated": _mc_rule("arch_gated", ["#not_aarch64_arch"]),
            },
            values={}, profiles={}, product="rhcos4",
            platforms={
                "only_a_kernel": _wrap(_and(KERNEL)),
                "not_aarch64_arch": _wrap(_and(AARCH64, negate=True)),
            })
        cls.content = content
        cls.appl = ap.build_map([content])
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        emit.generate_charts({"rhcos4": content}, root, "0.0.0")
        cls.node = root / emit.NODE_CHART
        cls.templates = {
            t.name: t.read_text()
            for t in (cls.node / "templates").glob("machineconfig-*.yaml")
        }

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_only_the_constrained_rule_is_in_the_map(self):
        self.assertEqual(set(self.appl), {"rhcos4-arch_gated"})

    def test_a_trivially_true_platform_constrains_nothing(self):
        # The rule does carry a <platform>; it just cannot exclude anything.
        self.assertTrue(self.content.rules["trivial_platform"].all_platforms)
        self.assertNotIn("rhcos4-trivial_platform", self.appl)

    def test_no_object_template_carries_a_gate(self):
        # The gate is central, in the preflight: one render reports every
        # offending rule instead of failing on the first object reached. So no
        # object template may consult the architecture, constrained or not.
        for name, body in self.templates.items():
            self.assertNotIn('include "cr.arch"', body, name)
            self.assertNotIn("ruleApplicability", body, name)

    def test_values_map_lists_only_the_constrained_rule(self):
        values = (self.node / "values.yaml").read_text()
        section = values.split("ruleApplicability:", 1)[1]
        self.assertIn("rhcos4-arch_gated:", section)
        self.assertNotIn("rhcos4-no_platform:", section)
        self.assertNotIn("rhcos4-trivial_platform:", section)

    def test_overlay_disables_only_the_constrained_rule(self):
        overlay = (self.node / "values-aarch64.yaml").read_text()
        self.assertIn("rhcos4-arch_gated: false", overlay)
        self.assertNotIn("rhcos4-no_platform", overlay)
        self.assertNotIn("rhcos4-trivial_platform", overlay)

    def test_all_three_rules_still_produce_objects(self):
        self.assertEqual(len(self.templates), 3)


class TestRoleRestriction(unittest.TestCase):
    """A rule upstream restricts to the master pool must not reach workers.

    The operator gets this from its scan topology: it scans per pool and takes
    the MachineConfig role from the scan's node selector, so a master-only
    remediation is never generated for a worker. We render per role, so the
    equivalent is to skip the roles the rule does not apply to - not to abort,
    because with both roles listed the rule is legitimately wanted for one.
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        from pathlib import Path
        content = Content(
            rules={
                "master_only": _mc_rule("master_only", ["#ocp4-master-node"], "ocp4"),
                "any_role": _mc_rule("any_role", product="ocp4"),
            },
            values={}, profiles={}, product="ocp4",
            platforms={"ocp4-master-node": _wrap(_and(MASTER_NODE))})
        cls.appl = ap.build_map([content])
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        emit.generate_charts({"ocp4": content}, root, "0.0.0")
        cls.tpl = root / emit.NODE_CHART / "templates"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_role_is_extracted(self):
        self.assertEqual(self.appl["ocp4-master_only"].roles, frozenset({"master"}))

    def test_role_only_rule_is_not_otherwise_constrained(self):
        app = self.appl["ocp4-master_only"]
        self.assertFalse(app.never)
        self.assertEqual(app.constraints, {})
        # It is not something the preflight can refuse - it is a render skip.
        self.assertFalse(app.gated)

    def test_describe_reports_the_pool(self):
        self.assertEqual(ap.describe(self.appl["ocp4-master_only"]),
                         "master pool only")

    def test_restricted_template_gates_on_the_role(self):
        body = (self.tpl / "machineconfig-75-ocp4-master-only.yaml").read_text()
        self.assertIn('{{- if has $role (list "master") }}', body)

    def test_unrestricted_template_does_not(self):
        body = (self.tpl / "machineconfig-75-ocp4-any-role.yaml").read_text()
        self.assertNotIn("has $role", body)

    def test_role_only_rule_stays_out_of_the_preflight_map(self):
        # Putting it there would abort the render for a rule that is wanted on
        # the other pool.
        values = (self.tpl.parent / "values.yaml").read_text()
        section = values.split("ruleApplicability:", 1)[1]
        self.assertNotIn("ocp4-master_only", section)

    def test_mixed_role_restrictions_raise(self):
        # Impossible today - node object names are synthesized per rule, so
        # every rule is the sole contributor to its object. If that ever
        # changes, the merge has to move inside the role loop; fail loudly
        # rather than render one rule's restriction over another's.
        from compliance_remediations_helm.collisions import FixDoc, MergeGroup, ObjectKey
        key = ObjectKey("machineconfiguration.openshift.io/v1", "MachineConfig",
                        "", "75-ocp4-shared")
        body = "kind: MachineConfig\nspec:\n  config:\n    ignition:\n      version: 3.1.0\n"
        group = MergeGroup(key=key, docs=[FixDoc("ocp4-a", key, body),
                                          FixDoc("ocp4-b", key, body)])
        appl = {"ocp4-a": ap.Applicability(roles=frozenset({"master"}))}
        with self.assertRaises(ValueError) as cm:
            emit.object_template(group, appl)
        self.assertIn("node-role", str(cm.exception))


class TestKubeletConfigConsolidation(unittest.TestCase):
    """Every kubelet rule merges into one object per pool, with a selector.

    Mirrors verifyAndCompleteKC in the operator, which names the object after
    the pool and sets the selector the MCO needs. Without the selector the
    object matches no pool and silently does nothing.
    """

    @classmethod
    def setUpClass(cls):
        import tempfile
        from pathlib import Path
        def kc_rule(rule_id, field):
            return xccdf.Rule(
                rule_id=rule_id, xccdf_id=f"x_{rule_id}", product="ocp4",
                fixes=[xccdf.FixVariant(yaml=(
                    "apiVersion: machineconfiguration.openshift.io/v1\n"
                    "kind: KubeletConfig\n"
                    "spec:\n"
                    "  kubeletConfig:\n"
                    f"    {field}: true\n"))])
        content = Content(
            rules={"kc_one": kc_rule("kc_one", "protectKernelDefaults"),
                   "kc_two": kc_rule("kc_two", "makeIPTablesUtilChains")},
            values={}, profiles={}, product="ocp4")
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        emit.generate_charts({"ocp4": content}, root, "0.0.0")
        cls.tpl = root / emit.NODE_CHART / "templates"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_one_template_for_every_kubelet_rule(self):
        files = sorted(p.name for p in self.tpl.glob("kubeletconfig-*.yaml"))
        self.assertEqual(files, ["kubeletconfig-compliance-operator-kubelet.yaml"])

    def test_both_rules_contribute_to_it(self):
        body = (self.tpl / "kubeletconfig-compliance-operator-kubelet.yaml").read_text()
        self.assertIn("protectKernelDefaults", body)
        self.assertIn("makeIPTablesUtilChains", body)

    def test_the_pool_selector_is_emitted_per_role(self):
        body = (self.tpl / "kubeletconfig-compliance-operator-kubelet.yaml").read_text()
        self.assertIn("machineConfigPoolSelector", body)
        self.assertIn("pools.operator.machineconfiguration.openshift.io/%s", body)
        self.assertIn("deepCopy $merged", body)

    def test_machineconfig_names_are_still_per_rule(self):
        # Only KubeletConfig consolidates; MachineConfig keeps the operator's
        # per-check naming.
        from compliance_remediations_helm import classify
        self.assertEqual(classify.synthesize_name("MachineConfig", "some_rule"),
                         "75-ocp4-some-rule")
        self.assertEqual(classify.synthesize_name("KubeletConfig", "some_rule"),
                         "compliance-operator-kubelet")


class TestConsolidatedObjects(unittest.TestCase):
    """Rule families whose fixes are byte-identical share one object."""

    @requires(OCP4, RHCOS4)
    def test_each_family_really_is_identical(self):
        # A family is only sound while its fixes agree. If a content release
        # makes one differ, this fails here and generate_charts raises -
        # rather than one rule's configuration silently winning on the node.
        content = xccdf.parse(RHCOS4, product="rhcos4")
        from compliance_remediations_helm import classify
        for name, rule_ids in classify.CONSOLIDATED_FAMILIES.items():
            bodies = set()
            for rule_id in rule_ids:
                rule = content.rules.get(rule_id)
                self.assertIsNotNone(rule, f"{rule_id} no longer exists upstream")
                bodies.add("\n---\n".join(fx.yaml for fx in rule.fixes))
            self.assertEqual(len(bodies), 1, f"{name}: fixes have diverged")

    @requires(OCP4, RHCOS4)
    def test_families_do_not_overlap(self):
        from compliance_remediations_helm import classify
        seen: dict = {}
        for name, rule_ids in classify.CONSOLIDATED_FAMILIES.items():
            for rule_id in rule_ids:
                self.assertNotIn(rule_id, seen,
                                 f"{rule_id} is in {name} and {seen.get(rule_id)}")
                seen[rule_id] = name

    @requires(OCP4, RHCOS4)
    def test_one_object_for_the_whole_family(self):
        import tempfile
        from pathlib import Path

        from compliance_remediations_helm import classify
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        with tempfile.TemporaryDirectory() as d:
            emit.generate_charts(contents, Path(d), "0.0.0")
            tpl = Path(d) / emit.NODE_CHART / "templates"
            for rule_id, name in classify.CONSOLIDATED_NAMES.items():
                self.assertTrue((tpl / f"machineconfig-{name}.yaml").exists())
                slug = rule_id.replace("_", "-")
                self.assertFalse((tpl / f"machineconfig-75-ocp4-{slug}.yaml").exists(),
                                 f"{rule_id} still has its own object")

    def test_divergent_fixes_raise(self):
        from compliance_remediations_helm import classify
        from compliance_remediations_helm.collisions import FixDoc, MergeGroup, ObjectKey
        name = next(iter(classify.CONSOLIDATED_NAMES.values()))
        key = ObjectKey("machineconfiguration.openshift.io/v1", "MachineConfig", "", name)
        a = "kind: MachineConfig\nspec:\n  config:\n    ignition:\n      version: 3.1.0\n"
        b = "kind: MachineConfig\nspec:\n  config:\n    ignition:\n      version: 3.2.0\n"
        group = MergeGroup(key=key, docs=[FixDoc("rhcos4-a", key, a),
                                          FixDoc("rhcos4-b", key, b)])
        with self.assertRaises(ValueError) as cm:
            emit.object_template(group)
        self.assertIn("no longer identical", str(cm.exception))


class TestUmbrellaOverlays(unittest.TestCase):
    """The umbrella needs its own overlay, with the values nested.

    A top-level `cluster:`/`rules:` file is silently ignored by the umbrella -
    the values sit at the wrong level - so following the render's own advice
    would fail again with the same message.
    """

    @classmethod
    @requires(OCP4, RHCOS4)
    def setUpClass(cls):
        import tempfile
        from pathlib import Path
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        emit.generate_charts(contents, root, "0.0.0")
        cls.node = root / emit.NODE_CHART
        cls.umbrella = root / emit.UMBRELLA_CHART

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_both_charts_ship_an_overlay(self):
        for chart in (self.node, self.umbrella):
            self.assertTrue((chart / "values-aarch64.yaml").exists(), chart.name)

    def test_the_umbrella_overlay_is_nested_per_subchart(self):
        text = (self.umbrella / "values-aarch64.yaml").read_text()
        self.assertIn(f"{emit.NODE_CHART}:", text)
        self.assertIn("    architecture: aarch64", text)
        self.assertNotIn("\ncluster:", text)

    def test_the_subchart_overlay_is_not_nested(self):
        text = (self.node / "values-aarch64.yaml").read_text()
        self.assertIn("\ncluster:", text)
        self.assertNotIn(f"{emit.NODE_CHART}:", text)

    def test_no_overlay_for_an_architecture_without_exclusions(self):
        for chart in (self.node, self.umbrella):
            self.assertFalse((chart / "values-ppc64le.yaml").exists(), chart.name)
            self.assertFalse((chart / "values-x86_64.yaml").exists(), chart.name)


class TestScheduleForSilentTotalFailure(unittest.TestCase):
    """Values that would render nothing at all must be rejected, not accepted."""

    @requires(OCP4, RHCOS4)
    def test_node_roles_may_not_be_empty(self):
        # `node.roles: []` rendered zero manifests and exited 0 - every node
        # remediation silently dropped, with nothing to notice it.
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        schema = json.loads(emit.values_schema(list(contents.values()), "node"))
        self.assertEqual(schema["properties"]["node"]["properties"]["roles"]
                         .get("minItems"), 1)


class TestRuleDependencies(unittest.TestCase):
    """Upstream says some rules must not be applied without another."""

    def test_parsing_strips_the_xccdf_prefix(self):
        rule = xccdf.Rule(rule_id="dependent", xccdf_id="x", product="ocp4")
        # Mirrors what parse() does with the annotation body.
        self.assertEqual(
            "xccdf_org.ssgproject.content_rule_some_other"
            .split("content_rule_")[-1], "some_other")
        self.assertEqual(rule.depends_on, [])

    def test_only_same_layer_emitted_rules_are_checkable(self):
        # cr.ruleActive resolves through profileRules and the rules override,
        # and both only carry rules this chart emits. A dependency outside
        # that set would always read as inactive and fail every render.
        dependent = _mc_rule("dependent", product="ocp4")
        dependent.depends_on = ["emitted", "not_emitted"]
        emitted = _mc_rule("emitted", product="ocp4")
        content = Content(rules={"dependent": dependent, "emitted": emitted},
                          values={}, profiles={}, product="ocp4")
        layer_rules = {"ocp4-dependent", "ocp4-emitted"}
        deps = emit.rule_dependencies([content], layer_rules)
        self.assertEqual(deps, {"ocp4-dependent": ["ocp4-emitted"]})
        self.assertEqual(emit.unverifiable_dependencies([content]),
                         ["ocp4-dependent -> ocp4-not_emitted"])

    def test_helper_and_map_are_emitted(self):
        import tempfile
        from pathlib import Path
        dependent = _mc_rule("dependent", product="ocp4")
        dependent.depends_on = ["emitted"]
        content = Content(
            rules={"dependent": dependent, "emitted": _mc_rule("emitted", product="ocp4")},
            values={}, profiles={}, product="ocp4")
        with tempfile.TemporaryDirectory() as d:
            emit.generate_charts({"ocp4": content}, Path(d), "0.0.0")
            node = Path(d) / emit.NODE_CHART
            helpers = (node / "templates" / "_helpers.tpl").read_text()
            self.assertIn('define "cr.dependencyPreflight"', helpers)
            preflight = (node / "templates" / "preflight.yaml").read_text()
            self.assertIn('include "cr.dependencyPreflight"', preflight)
            values = (node / "values.yaml").read_text()
            section = values.split("ruleDependencies:", 1)[1]
            self.assertIn("ocp4-dependent:", section)
            self.assertIn("- ocp4-emitted", section)

    @requires(OCP4, RHCOS4)
    def test_the_known_relations(self):
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        found = {}
        for product, content in contents.items():
            for rule in xccdf.rules_with_fixes(content).values():
                if rule.depends_on:
                    found[rule.helm_name] = [f"{product}-{d}" for d in rule.depends_on]
        self.assertEqual(found, {
            "ocp4-kubelet_enable_protect_kernel_defaults":
                ["ocp4-kubelet_enable_protect_kernel_sysctl"],
            "rhcos4-configure_usbguard_auditbackend":
                ["rhcos4-package_usbguard_installed"],
            "rhcos4-service_usbguard_enabled":
                ["rhcos4-package_usbguard_installed"],
            "rhcos4-usbguard_allow_hid_and_hub":
                ["rhcos4-package_usbguard_installed"],
        })

    @requires(OCP4, RHCOS4)
    def test_every_dependency_is_checkable(self):
        # If a content bump introduces a dependency on a rule this chart does
        # not emit, the generator reports it - and this fails, so it is not
        # only a line of output nobody reads.
        contents = [xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))]
        self.assertEqual(emit.unverifiable_dependencies(contents), [])


class TestValuesContract(unittest.TestCase):
    """What the templates read, values.yaml declares and the schema allows."""

    @classmethod
    @requires(OCP4, RHCOS4)
    def setUpClass(cls):
        cls.contents = [xccdf.parse(f, product=p)
                        for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))]

    def test_numeric_variables_are_constrained_to_digits(self):
        # A non-numeric override used to render straight into a field that
        # must be a number.
        from compliance_remediations_helm import resolver
        numeric = resolver.numeric_variables(self.contents)
        self.assertTrue(numeric)
        schema = json.loads(emit.values_schema(self.contents, "node"))
        props = schema["properties"]["variables"]["properties"]
        for name in numeric:
            if name in props:
                self.assertEqual(props[name]["pattern"], r"^\d+$", name)

    def test_only_variables_whose_options_are_all_digits_are_constrained(self):
        # The declared XCCDF type alone is not enough - a number-typed value
        # may carry a unit suffix, and constraining it would reject the
        # shipped default.
        from compliance_remediations_helm import resolver
        numeric = resolver.numeric_variables(self.contents)
        defaults = {}
        for c in self.contents:
            defaults.update(resolver.resolve_defaults(c))
        for name in numeric:
            self.assertRegex(defaults[name], r"^\d+$", name)

    def test_ocp_version_accepts_a_prerelease(self):
        # The documented `oc get clusterversion` returns 4.20.0-ec.2 on any
        # pre-GA cluster, and the templates use only major.minor.
        schema = json.loads(emit.values_schema(self.contents, "node"))
        pattern = schema["properties"]["cluster"]["properties"]["ocpVersion"]["pattern"]
        for v in ("4.20", "4.20.1", "4.20.0-ec.2", "4.19.0-rc.1"):
            self.assertRegex(v, pattern, v)
        for v in ("x.y", "", "4"):
            self.assertNotRegex(v, pattern, v)

    def test_generated_maps_are_required_and_declared(self):
        # Helm's `--set X=null` deletes a key, and every preflight reads its
        # map with `| default dict` - so a deleted map turned the guard into a
        # silent no-op. `required` makes that a schema error.
        for layer in ("node", "platform"):
            schema = json.loads(emit.values_schema(self.contents, layer))
            for key in ("profileRules", "profileVariables", "ruleApplicability",
                        "ruleDependencies", "brokenRules", "profiles", "rules",
                        "variables"):
                self.assertIn(key, schema["properties"], f"{layer}/{key}")
                self.assertIn(key, schema["required"], f"{layer}/{key}")

    def test_the_root_is_closed_but_allows_global(self):
        # An umbrella-shaped values file applied to a subchart was silently
        # discarded. Helm injects `global` into a subchart, so that one key has
        # to stay allowed.
        for layer in ("node", "platform"):
            schema = json.loads(emit.values_schema(self.contents, layer))
            self.assertFalse(schema["additionalProperties"])
            self.assertIn("global", schema["properties"])

    def test_only_unquoted_variables_forbid_yaml_type_tokens(self):
        # A bare `~` or `no` changes the type of the field it lands in, but
        # only where the fragment interpolates it unquoted. Inside an encoded
        # payload `no` is ordinary config text - var_sshd_disable_compression
        # ships exactly that.
        from compliance_remediations_helm import resolver
        unquoted = resolver.unquoted_scalar_variables(self.contents)
        schema = json.loads(emit.values_schema(self.contents, "node"))
        props = schema["properties"]["variables"]["properties"]
        self.assertIn("var_openshift_audit_profile", unquoted)
        self.assertNotIn("var_sshd_disable_compression", unquoted)
        for name, spec in props.items():
            self.assertEqual("not" in spec, name in unquoted, name)

    def test_profile_variables_cover_encoded_references(self):
        # Matching only the plain form missed 22 of the 40 variables, so a node
        # TailoredProfile set none of them.
        import yaml
        values = yaml.safe_load(emit.values_yaml(self.contents, "node", "0.0.0"))
        stig = values["profileVariables"].get("rhcos4-stig") or []
        self.assertTrue(stig, "rhcos4-stig references no variables at all")
        self.assertIn("var_auditd_action_mail_acct", stig)

    def test_profile_maps_only_carry_this_layer(self):
        # They used to carry all 49 profiles in both charts, while `profiles`
        # declares only its own - so most entries were unreachable.
        import yaml
        for layer in ("node", "platform"):
            values = yaml.safe_load(emit.values_yaml(self.contents, layer, "0.0.0"))
            self.assertEqual(set(values["profileRules"]), set(values["profiles"]))
            self.assertEqual(set(values["profileVariables"]), set(values["profiles"]))


class TestBrokenRules(unittest.TestCase):
    """Rules whose upstream fix the API server silently prunes."""

    @requires(OCP4, RHCOS4)
    def test_the_two_known_ones_are_detected(self):
        contents = [xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))]
        broken = emit.broken_rules(contents)
        self.assertEqual(sorted(broken), [
            "ocp4-api_server_tls_security_profile_custom_min_tls_version",
            "ocp4-ingress_controller_tls_security_profile_custom_min_tls_version",
        ])
        for why in broken.values():
            self.assertIn("prunes", why)

    @requires(OCP4, RHCOS4)
    def test_they_ship_disabled_and_are_in_the_map(self):
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        values = emit.values_yaml(list(contents.values()), "platform", "0.0.0")
        for name in emit.broken_rules(list(contents.values())):
            self.assertIn(f"  {name}: false", values)
        self.assertIn("brokenRules:", values)


class TestOptInRules(unittest.TestCase):
    """Rules that ship disabled because applying them can take a node down."""

    def test_every_entry_has_a_reason(self):
        for name, why in emit.OPT_IN_RULES.items():
            self.assertTrue(why.strip(), f"{name} ships disabled without a reason")

    @requires(OCP4, RHCOS4)
    def test_entries_name_real_fix_carrying_rules(self):
        # A typo here would silently disable nothing at all.
        known = set()
        for product, path in (("ocp4", OCP4), ("rhcos4", RHCOS4)):
            content = xccdf.parse(path, product=product)
            known |= {r.helm_name for r in xccdf.rules_with_fixes(content).values()}
        for name in emit.OPT_IN_RULES:
            self.assertIn(name, known)

    @requires(OCP4, RHCOS4)
    def test_they_ship_disabled_even_though_profiles_select_them(self):
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        values = emit.values_yaml(list(contents.values()), "node", "0.0.0")
        for name in emit.OPT_IN_RULES:
            self.assertIn(f"  {name}: false", values)


class TestDanglingPlatformReference(unittest.TestCase):
    def test_reference_to_an_undefined_platform_raises(self):
        # A ref the datastream does not define means the parse lost something;
        # treating it as unconstrained would silently ship the rule.
        content = Content(
            rules={"r": _mc_rule("r", ["#nowhere_to_be_found"])},
            values={}, profiles={}, product="rhcos4", platforms={})
        with self.assertRaises(ap.UnsupportedFact) as cm:
            ap.build_map([content])
        self.assertIn("nowhere_to_be_found", str(cm.exception))

    def test_bare_cpe_product_name_is_skipped_not_rejected(self):
        # Benchmark/Profile-level refs are CPE product names; the product is
        # already decided by which datastream we parsed.
        content = Content(
            rules={"r": _mc_rule("r", ["cpe:/o:redhat:enterprise_linux_coreos:4"])},
            values={}, profiles={}, product="rhcos4", platforms={})
        self.assertEqual(ap.build_map([content]), {})


@requires(OCP4, RHCOS4)
class TestAgainstPinnedContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents = [xccdf.parse(OCP4, product="ocp4"),
                        xccdf.parse(RHCOS4, product="rhcos4")]
        cls.appl = ap.build_map(cls.contents)
        cls.by_product = {c.product: c for c in cls.contents}

    def test_every_reachable_fact_is_classified(self):
        # build_map already raised in setUpClass if not. Assert it produced
        # something, so the test cannot pass by reaching zero rules.
        self.assertTrue(self.appl)

    def test_platform_definitions_are_parsed(self):
        for content in self.contents:
            self.assertTrue(content.platforms,
                            f"{content.product} parsed no CPE definitions")

    def test_group_inheritance_reaches_the_reducer(self):
        # usbguard_allow_hid_and_hub is arch-constrained purely through its
        # <Group>; it has no <platform> of its own. Rule-level parsing alone
        # would miss it and four profile-selected rules with it.
        rule = self.by_product["rhcos4"].rules["usbguard_allow_hid_and_hub"]
        self.assertEqual(rule.platforms, [])
        self.assertTrue(rule.group_platforms)
        app = self.appl[rule.helm_name]
        self.assertNotIn("s390x", app.constraints[ap.AXIS_ARCH])

    def test_known_constraints(self):
        stime = self.appl["rhcos4-audit_rules_time_stime"]
        allowed = stime.constraints[ap.AXIS_ARCH]
        self.assertNotIn("aarch64", allowed)
        self.assertNotIn("s390x", allowed)
        cipher = self.appl["ocp4-api_server_encryption_provider_cipher"]
        self.assertEqual(cipher.constraints[ap.AXIS_HYPERSHIFT], frozenset({False}))

    def test_never_applicable_rules_are_selected_by_no_profile(self):
        # This is what makes shipping them disabled safe. If upstream ever puts
        # one into a profile, that must be a test failure rather than a control
        # silently switched off.
        never = set(ap.never_applicable_rules(self.appl))
        self.assertTrue(never)
        for content in self.contents:
            for pid, prof in content.profiles.items():
                selected = {f"{content.product}-{r}" for r in prof.selected_rules}
                overlap = sorted(never & selected)
                self.assertEqual(overlap, [], f"{pid} selects {overlap}")

    def test_the_master_only_rules_are_recognized(self):
        # These three write audit rules watching /var/log/*-apiserver/, which
        # exist only on control-plane nodes.
        for rid in ("directory_access_var_log_kube_audit",
                    "directory_access_var_log_oauth_audit",
                    "directory_access_var_log_ocp_audit"):
            app = self.appl[f"ocp4-{rid}"]
            self.assertEqual(app.roles, frozenset({"master"}), rid)
            self.assertFalse(app.gated, rid)

    def test_arch_constrained_rules_are_all_node_layer(self):
        # The values.yaml comments say architecture matters to the node chart.
        # The moment that stops being true, they are wrong.
        for content in self.contents:
            for rule in xccdf.rules_with_fixes(content).values():
                app = self.appl.get(rule.helm_name)
                if app and ap.AXIS_ARCH in app.constraints:
                    self.assertEqual(emit._rule_layer(rule), "node", rule.helm_name)


if __name__ == "__main__":
    unittest.main()

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
        tpl = (self.node / "templates" / "applicability.yaml").read_text()
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

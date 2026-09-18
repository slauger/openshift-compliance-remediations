"""Generation determinism + node name-synthesis tests."""
import filecmp
import tempfile
import unittest
from pathlib import Path

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import classify, emit
from compliance_remediations_helm import parser as xccdf


class TestNameSynthesis(unittest.TestCase):
    def test_kubeletconfig_name_is_per_pool_not_per_rule(self):
        # The operator consolidates every kubelet remediation for a pool into
        # one KubeletConfig named after the pool, so the name must not depend
        # on the rule. The role suffix is appended at render time.
        for rule_id in ("kubelet_configure_event_creation", "kubelet_enable_protect_kernel_defaults"):
            self.assertEqual(
                classify.synthesize_name("KubeletConfig", rule_id),
                "compliance-operator-kubelet",
            )

    def test_machineconfig_ordering_prefix(self):
        self.assertTrue(
            classify.synthesize_name("MachineConfig", "audit_rules_x").startswith("75-"))


def _dir_equal(a: Path, b: Path) -> bool:
    cmp = filecmp.dircmp(a, b)
    if cmp.left_only or cmp.right_only or cmp.diff_files:
        return False
    return all(_dir_equal(a / d, b / d) for d in cmp.common_dirs)


@requires(OCP4, RHCOS4)
class TestDeterminism(unittest.TestCase):
    def test_two_generations_are_byte_identical(self):
        contents = {
            "ocp4": xccdf.parse(OCP4, product="ocp4"),
            "rhcos4": xccdf.parse(RHCOS4, product="rhcos4"),
        }
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            emit.generate_charts(contents, Path(d1), "0.1.82")
            emit.generate_charts(contents, Path(d2), "0.1.82")
            self.assertTrue(_dir_equal(Path(d1), Path(d2)),
                            "chart generation must be deterministic for GitOps diffs")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the generator. Stdlib unittest, no external deps.

Run: python3 -m pytest tests/  (or: python3 -m unittest discover -s tests -v)
Requires the datastreams extracted into .cache/ (make fetch).
"""
import unittest
from pathlib import Path

from compliance_remediations_helm import parser as xccdf

ROOT = Path(__file__).resolve().parents[1]
OCP4 = ROOT / ".cache" / "ssg-ocp4-ds.xml"
RHCOS4 = ROOT / ".cache" / "ssg-rhcos4-ds.xml"


@unittest.skipUnless(OCP4.exists(), "run `make fetch` first")
class TestOcp4Parse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = xccdf.parse(OCP4, product="ocp4")

    def test_rule_count(self):
        self.assertEqual(len(self.content.rules), 357)

    def test_fix_rule_count(self):
        self.assertEqual(len(xccdf.rules_with_fixes(self.content)), 36)

    def test_encryption_rule_in_17_profiles(self):
        target = "api_server_encryption_provider_cipher"
        containing = [
            p for p, prof in self.content.profiles.items()
            if target in prof.selected_rules
        ]
        self.assertEqual(len(containing), 17)

    def test_profile_keys_are_namespaced(self):
        self.assertTrue(all(p.startswith("ocp4-") for p in self.content.profiles))

    def test_rule_helm_name(self):
        r = self.content.rules["api_server_encryption_provider_cipher"]
        self.assertEqual(r.helm_name, "ocp4-api_server_encryption_provider_cipher")


@unittest.skipUnless(RHCOS4.exists(), "run `make fetch` first")
class TestRhcos4Parse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = xccdf.parse(RHCOS4, product="rhcos4")

    def test_has_many_machineconfig_fixes(self):
        self.assertGreater(len(xccdf.rules_with_fixes(self.content)), 250)

    def test_profile_keys_are_namespaced(self):
        self.assertTrue(all(p.startswith("rhcos4-") for p in self.content.profiles))


if __name__ == "__main__":
    unittest.main()

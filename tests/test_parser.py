"""Unit tests for the generator. Stdlib unittest, no external deps.

Run: python3 -m pytest tests/  (or: python3 -m unittest discover -s tests -v)

The classes gated by `requires(...)` assert against the pinned datastreams and
need `make fetch`; the rest runs offline. Assertions here are invariants of a
correct parse, never exact counts of the pinned content version - a content
bump must not require editing a number in this file.
"""
import unittest

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import parser as xccdf


@requires(OCP4)
class TestOcp4Parse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = xccdf.parse(OCP4, product="ocp4")

    def test_parses_a_full_rule_set(self):
        # Floor, not an exact count: guards against a partial/broken parse
        # (namespace change, truncated download) without breaking on a bump.
        self.assertGreater(len(self.content.rules), 250)
        self.assertTrue(all(r.rule_id and r.xccdf_id for r in self.content.rules.values()))
        self.assertTrue(all(k == r.rule_id for k, r in self.content.rules.items()))

    def test_rules_with_fixes_are_a_subset_carrying_payloads(self):
        with_fixes = xccdf.rules_with_fixes(self.content)
        self.assertTrue(with_fixes, "ocp4 must yield at least one k8s fix")
        self.assertLess(len(with_fixes), len(self.content.rules))
        for rid, r in with_fixes.items():
            self.assertIn(rid, self.content.rules)
            self.assertTrue(r.has_fix)
            self.assertTrue(all(v.yaml.strip() for v in r.fixes))

    def test_profile_selections_resolve_to_parsed_rules(self):
        # A dangling selection means the profile/rule cross-reference broke.
        known = set(self.content.rules)
        for name, prof in self.content.profiles.items():
            self.assertTrue(prof.selected_rules, f"{name} selects no rules")
            dangling = [r for r in prof.selected_rules if r not in known]
            self.assertEqual(dangling, [], f"{name} selects unknown rules: {dangling}")

    def test_rule_is_shared_across_profiles(self):
        # Profile parsing must produce overlap, not one rule per profile.
        target = "api_server_encryption_provider_cipher"
        containing = [
            p for p, prof in self.content.profiles.items()
            if target in prof.selected_rules
        ]
        self.assertGreater(len(containing), 1)

    def test_profile_keys_are_namespaced(self):
        self.assertTrue(all(p.startswith("ocp4-") for p in self.content.profiles))

    def test_rule_helm_name(self):
        r = self.content.rules["api_server_encryption_provider_cipher"]
        self.assertEqual(r.helm_name, "ocp4-api_server_encryption_provider_cipher")


@requires(RHCOS4)
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

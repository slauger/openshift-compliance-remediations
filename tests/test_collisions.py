"""Conflict / merge-group detection tests."""
import unittest

from _datastream import OCP4, requires

from compliance_remediations_helm import collisions
from compliance_remediations_helm import parser as xccdf


@requires(OCP4)
class TestConflicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        content = xccdf.parse(OCP4, product="ocp4")
        cls.groups, cls.unparseable = collisions.build_groups(content)
        cls.by_name = {f"{g.key.kind}/{g.key.name}": g for g in cls.groups}

    def test_all_fixes_identified(self):
        # Every k8s fix must resolve to an object (node names synthesized).
        self.assertEqual(self.unparseable, [])

    def test_ingresscontroller_is_conflict(self):
        g = self.by_name["IngressController/default"]
        conflicts = g.conflicts()
        self.assertTrue(conflicts, "expected a conflict on IngressController/default")
        paths = {c.path for c in conflicts}
        self.assertTrue(any("tlsSecurityProfile" in p for p in paths))

    def test_apiserver_audit_encryption_not_conflict(self):
        # APIServer merges audit + encryption (disjoint subtrees). The TLS
        # rules may conflict, but audit vs encryption must NOT be flagged.
        g = self.by_name["APIServer/cluster"]
        conflict_paths = {c.path for c in g.conflicts()}
        self.assertNotIn("spec.audit", conflict_paths)
        self.assertNotIn("spec.encryption", conflict_paths)

    def test_oauth_disjoint_no_conflict(self):
        g = self.by_name["OAuth/cluster"]
        # inactivity vs maxage write different leaves under tokenConfig ->
        # disjoint -> must NOT be flagged as a conflict.
        self.assertEqual(g.conflicts(), [])


class TestListConflict(unittest.TestCase):
    """Two rules writing different list content to the same path must conflict."""

    def _group(self, docs):
        from compliance_remediations_helm.collisions import FixDoc, MergeGroup, ObjectKey
        key = ObjectKey("operator.openshift.io/v1", "IngressController", "", "default")
        return MergeGroup(key=key, docs=[FixDoc(rid, key, y) for rid, y in docs])

    def test_differing_cipher_lists_conflict(self):
        a = ("apiVersion: operator.openshift.io/v1\nkind: IngressController\n"
             "metadata:\n  name: default\nspec:\n  tlsSecurityProfile:\n"
             "    custom:\n      ciphers:\n        - AES128\n      type: Custom\n")
        b = ("apiVersion: operator.openshift.io/v1\nkind: IngressController\n"
             "metadata:\n  name: default\nspec:\n  tlsSecurityProfile:\n"
             "    custom:\n      ciphers:\n        - AES256\n      type: Custom\n")
        g = self._group([("ocp4-rule_a", a), ("ocp4-rule_b", b)])
        conflicts = g.conflicts()
        self.assertTrue(conflicts, "differing cipher lists must conflict")

    def test_identical_lists_no_conflict(self):
        a = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
             "data:\n  items:\n    - one\n    - two\n")
        g = self._group([("ocp4-rule_a", a), ("ocp4-rule_b", a)])
        # identical list content -> safe to merge, no conflict
        self.assertEqual(g.conflicts(), [])


class TestBlockScalar(unittest.TestCase):
    """A `key: val`-looking line inside a block scalar must not be parsed as
    structure (no false leaf, no false conflict)."""

    def _group(self, docs):
        from compliance_remediations_helm.collisions import FixDoc, MergeGroup, ObjectKey
        key = ObjectKey("v1", "ConfigMap", "", "cm")
        return MergeGroup(key=key, docs=[FixDoc(rid, key, y) for rid, y in docs])

    def _leaf_paths(self, yaml):
        from compliance_remediations_helm.collisions import _leaf_paths
        return _leaf_paths(yaml)

    def test_block_scalar_content_not_parsed_as_keys(self):
        yaml = (
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"
            "data:\n"
            "  script: |\n"
            "    #!/bin/sh\n"
            "    foo: bar\n"          # looks like a key, but is scalar text
            "    nested: deep: value\n"
        )
        leaves = self._leaf_paths(yaml)
        # No leaf named data.script.foo etc. must exist.
        self.assertNotIn("data.script.foo", leaves)
        self.assertNotIn("data.foo", leaves)
        # The script itself is captured as one opaque scalar leaf.
        self.assertIn("data.script", leaves)

    def test_differing_block_scalars_conflict(self):
        a = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"
             "data:\n  script: |\n    echo one\n")
        b = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"
             "data:\n  script: |\n    echo two\n")
        g = self._group([("ocp4-a", a), ("ocp4-b", b)])
        self.assertTrue(g.conflicts(), "different block scalars must conflict")

    def test_identical_block_scalars_no_conflict(self):
        a = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n"
             "data:\n  script: |\n    echo same\n    foo: bar\n")
        g = self._group([("ocp4-a", a), ("ocp4-b", a)])
        self.assertEqual(g.conflicts(), [])


if __name__ == "__main__":
    unittest.main()

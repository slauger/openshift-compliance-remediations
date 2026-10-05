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


def _machineconfig(body: str) -> str:
    return ("apiVersion: machineconfiguration.openshift.io/v1\n"
            "kind: MachineConfig\n"
            "metadata:\n"
            "  name: 75-x\n"
            "spec:\n"
            "  config:\n" + body)


def _files(*entries: tuple[str, str]) -> str:
    out = ["    storage:", "      files:"]
    for path, source in entries:
        out += ["      - contents:",
                f"          source: {source}",
                "        mode: 420",
                f"        path: {path}"]
    return "\n".join(out) + "\n"


class TestSequenceAttribution(unittest.TestCase):
    """Sequences must be compared at their own path, serialized whole.

    ComplianceAsCode writes `files:` and `- contents:` at the same indent, and
    the previous line-wise flattener attached such a list to its grandparent,
    kept only each item's first line, and flattened item keys onto the list's
    path last-wins. The result was a three-file MachineConfig reduced to one
    file plus a leaf path that does not exist.
    """

    def _conflicts(self, docs):
        key = collisions.ObjectKey(
            "machineconfiguration.openshift.io/v1", "MachineConfig", "", "75-x")
        group = collisions.MergeGroup(
            key=key, docs=[collisions.FixDoc(rid, key, y) for rid, y in docs])
        return group.conflicts()

    def test_list_is_keyed_by_its_own_path(self):
        leaves = collisions._leaf_paths(_machineconfig(
            _files(("/etc/a.conf", "data:,A"), ("/etc/b.conf", "data:,B"))))
        self.assertIn("spec.config.storage.files", leaves)
        # Not the grandparent, and not item keys hoisted onto the list path.
        self.assertNotIn("spec.config.storage", leaves)
        self.assertNotIn("spec.config.storage.files.path", leaves)
        self.assertNotIn("spec.config.storage.files.path.source", leaves)

    def test_every_entry_survives_serialization(self):
        # The old flattener kept "- contents:" and dropped the rest, so the
        # middle file of a three-file list vanished entirely.
        leaves = collisions._leaf_paths(_machineconfig(
            _files(("/etc/a.conf", "data:,A"),
                   ("/etc/b.conf", "data:,B"),
                   ("/etc/c.conf", "data:,C"))))
        value = leaves["spec.config.storage.files"]
        for path, source in (("/etc/a.conf", "data:,A"), ("/etc/b.conf", "data:,B"),
                             ("/etc/c.conf", "data:,C")):
            self.assertIn(path, value)
            self.assertIn(source, value)

    def test_same_file_written_differently_conflicts(self):
        a = _machineconfig(_files(("/etc/a.conf", "data:,A"), ("/etc/b.conf", "data:,B")))
        b = _machineconfig(_files(("/etc/a.conf", "data:,A"), ("/etc/b.conf", "data:,CHANGED")))
        self.assertEqual(
            [(c.path, c.rules) for c in self._conflicts([("ocp4-a", a), ("ocp4-b", b)])],
            [("spec.config.storage.files", ["ocp4-a", "ocp4-b"])])

    def test_identical_file_lists_do_not_conflict(self):
        a = _machineconfig(_files(("/etc/a.conf", "data:,A"), ("/etc/b.conf", "data:,B")))
        self.assertEqual(self._conflicts([("ocp4-a", a), ("ocp4-b", a)]), [])

    def test_reordered_file_lists_do_not_conflict(self):
        a = _machineconfig(_files(("/etc/a.conf", "data:,A"), ("/etc/b.conf", "data:,B")))
        b = _machineconfig(_files(("/etc/b.conf", "data:,B"), ("/etc/a.conf", "data:,A")))
        self.assertEqual(self._conflicts([("ocp4-a", a), ("ocp4-b", b)]), [])

    def test_sibling_lists_under_one_parent_do_not_conflict(self):
        # Both collapsed onto spec.config.storage before, which reported a
        # conflict between rules writing disjoint subtrees - the opposite of
        # what conflicts() documents.
        a = _machineconfig(_files(("/etc/a.conf", "data:,A")))
        b = _machineconfig("    storage:\n      directories:\n"
                           "      - path: /etc/d\n        mode: 493\n")
        self.assertEqual(self._conflicts([("ocp4-a", a), ("ocp4-b", b)]), [])

    def test_scalar_list_is_one_leaf(self):
        # kernelArguments is a plain scalar list; its path is spec.kernelArguments,
        # the shape the pinned content uses.
        leaves = collisions._leaf_paths(
            "apiVersion: machineconfiguration.openshift.io/v1\nkind: MachineConfig\n"
            "metadata:\n  name: 75-x\n"
            "spec:\n  kernelArguments:\n    - audit=1\n    - audit_backlog_limit=8192\n")
        self.assertEqual(leaves["spec.kernelArguments"],
                         "[audit=1,audit_backlog_limit=8192]")

    def test_sequence_at_the_document_root(self):
        # Template fixes put `objects:` and its items at indent 0.
        leaves = collisions._leaf_paths(
            "apiVersion: template.openshift.io/v1\nkind: Template\n"
            "metadata:\n  name: t\n"
            "objects:\n- apiVersion: v1\n  kind: Project\n"
            "parameters:\n- name: PROJECT_NAME\n")
        self.assertIn("objects", leaves)
        self.assertIn("parameters", leaves)
        self.assertIn("PROJECT_NAME", leaves["parameters"])


class TestYamlShape(unittest.TestCase):
    """The parser is strict on purpose: the pinned content has no line it
    cannot place, so an unplaceable line is a content change to look at."""

    def test_unparseable_line_raises(self):
        with self.assertRaises(collisions.YamlShapeError) as cm:
            collisions._leaf_paths(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"
                "data:\n  a: 1\n&anchor\n", "ocp4-some_rule")
        self.assertIn("ocp4-some_rule", str(cm.exception))

    def test_no_recognized_body_yields_no_leaves(self):
        # emit reports such a fix as dropped rather than emitting it, so there
        # is nothing to compare and nothing to fail about.
        self.assertEqual(
            collisions._leaf_paths("apiVersion: v1\nkind: Secret\nmetadata:\n"
                                   "  name: s\nstringData:\n  foo: bar\n"),
            {})

    def test_body_vocabulary_is_shared_with_emit(self):
        from compliance_remediations_helm import emit
        for root in collisions.BODY_ROOTS:
            self.assertRegex(f"{root}:", emit._BODY_ROOT_RE)


if __name__ == "__main__":
    unittest.main()

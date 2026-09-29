"""The check for file paths written differently by two MachineConfigs.

The collision detector only sees inside one object. Across objects the MCO
decides, and MergeMachineConfigs sorts alphanumerically, takes the first
Ignition config as the base and merges the rest - so for a duplicate path the
later MachineConfig silently wins. 32 rules write /etc/ssh/sshd_config today
and every rendered one carries the same bytes, which makes that harmless; this
is what notices if that ever stops being true.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from validate_payloads import Findings, check_cross_object_files  # noqa: E402


def _mc(name, role, path, source):
    return {
        "kind": "MachineConfig",
        "metadata": {"name": name,
                     "labels": {"machineconfiguration.openshift.io/role": role}},
        "spec": {"config": {"storage": {
            "files": [{"path": path, "contents": {"source": source}}]}}},
    }


class TestCrossObjectFiles(unittest.TestCase):
    def _run(self, docs):
        fnd = Findings()
        check_cross_object_files("where", docs, fnd)
        return fnd

    def test_same_path_different_content_is_reported(self):
        fnd = self._run([_mc("a", "worker", "/etc/x", "data:,AAA"),
                         _mc("b", "worker", "/etc/x", "data:,BBB")])
        self.assertEqual(len(fnd.errors), 1)
        self.assertIn("/etc/x", fnd.errors[0])
        self.assertIn("silently take one", fnd.errors[0])

    def test_same_path_same_content_is_fine(self):
        # The sshd_config case: many rules, identical bytes, so the MCO's
        # last-wins merge is deterministic and correct.
        fnd = self._run([_mc("a", "worker", "/etc/x", "data:,AAA"),
                         _mc("b", "worker", "/etc/x", "data:,AAA")])
        self.assertEqual(fnd.errors, [])

    def test_different_roles_do_not_collide(self):
        # Each MachineConfigPool is merged on its own.
        fnd = self._run([_mc("a", "worker", "/etc/x", "data:,AAA"),
                         _mc("b", "master", "/etc/x", "data:,BBB")])
        self.assertEqual(fnd.errors, [])

    def test_non_machineconfig_objects_are_ignored(self):
        kc = {"kind": "KubeletConfig", "metadata": {"name": "k"}, "spec": {}}
        self.assertEqual(self._run([kc]).errors, [])


if __name__ == "__main__":
    unittest.main()

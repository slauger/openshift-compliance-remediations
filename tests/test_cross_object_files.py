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

from _datastream import OCP4, RHCOS4, requires  # noqa: E402
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


@requires(OCP4, RHCOS4)
class TestGeneratorSideDetection(unittest.TestCase):
    """The generator's own view: which rules write one path differently.

    Gated through `requires()` rather than a hand-rolled SkipTest, so
    REQUIRE_DATASTREAM=1 turns the skip into a failure here too - the promise
    `_datastream` makes is that it covers every path.
    """

    @classmethod
    def setUpClass(cls):
        from compliance_remediations_helm import emit
        from compliance_remediations_helm import parser as xccdf
        from compliance_remediations_helm.collisions import build_groups
        contents = [xccdf.parse(OCP4, product="ocp4"),
                    xccdf.parse(RHCOS4, product="rhcos4")]
        groups, _ = build_groups(*contents)
        cls.conflicts = emit.cross_object_file_conflicts(groups, "node")
        cls.emit = emit

    def test_the_sshd_dropin_pairs_moved_into_the_object(self):
        # The six enable/disable drop-in pairs used to be the point of this
        # detector: separate rules, separate objects, same file. Now the sshd
        # family is consolidated, so they share an object and the per-object
        # conflict guard refuses them - reporting them here as well would say
        # the same thing three times, and this detector's message tells the
        # user to look at separate objects.
        dropins = [c for c in self.conflicts if "sshd_config.d" in c["path"]]
        self.assertEqual(dropins, [])

    def test_identical_writers_are_not_a_conflict(self):
        # 31 rules write the same /etc/ssh/sshd_config; only the one that
        # differs makes it a conflict, and they must not all be lumped in.
        sshd = [c for c in self.conflicts if c["path"] == "/etc/ssh/sshd_config"]
        self.assertEqual(len(sshd), 1)
        sizes = sorted(len(g["rules"]) for g in sshd[0]["groups"])
        self.assertEqual(sizes[0], 1)
        self.assertGreater(sizes[1], 20)

    def test_every_conflict_carries_its_version_window(self):
        # The drop-ins only exist from 4.13; the whole-file variants only
        # below it. A guard without the window would fire where the fragments
        # do not even render.
        for c in self.conflicts:
            for grp in c["groups"]:
                self.assertTrue(grp["versions"], c["path"])

    def test_guards_are_emitted_into_the_preflight(self):
        tpl = self.emit.preflight_template(self.conflicts)
        self.assertIn('include "cr.applicabilityPreflight"', tpl)
        self.assertIn("cr.countActive", tpl)
        self.assertIn("semverCompare", tpl)
        self.assertEqual(tpl.count("fail"), len(self.conflicts))


if __name__ == "__main__":
    unittest.main()

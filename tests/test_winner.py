"""Regression tests for the profile-aware conflict-winner selection.

Guards against the round-2 regression where a name-based winner heuristic
disabled a rule that profiles actually selected (dropping ingress TLS hardening
for ocp4-cis and friends).
"""
import unittest

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import emit
from compliance_remediations_helm import parser as xccdf
from compliance_remediations_helm.collisions import build_groups


@requires(OCP4, RHCOS4)
class TestWinnerIsProfileSelected(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents = [
            xccdf.parse(OCP4, product="ocp4"),
            xccdf.parse(RHCOS4, product="rhcos4"),
        ]
        cls.counts = emit._profile_selection_counts(cls.contents)
        cls.disabled = emit.default_disabled_rules(cls.contents)
        cls.groups, _ = build_groups(*cls.contents)

    def test_no_orphan_winner(self):
        # For every conflict group, the un-disabled winner must be selected by
        # at least as many profiles as any disabled alternative - never elect a
        # 0-profile winner while a profile-selected alternative exists.
        for g in self.groups:
            for c in g.conflicts():
                winners = [r for r in c.rules if r not in self.disabled]
                self.assertTrue(winners, f"no winner for {g.key.kind}/{g.key.name}")
                for w in winners:
                    others = [self.counts.get(r, 0) for r in c.rules if r != w]
                    if others and max(others) > 0:
                        self.assertGreater(
                            self.counts.get(w, 0), 0,
                            f"orphan winner {w} on {g.key.kind}/{g.key.name}")

    def test_ingress_cipher_suites_wins(self):
        # cipher_suites is selected by many profiles; must be the winner.
        self.assertNotIn(
            "ocp4-ingress_controller_tls_cipher_suites", self.disabled)


if __name__ == "__main__":
    unittest.main()

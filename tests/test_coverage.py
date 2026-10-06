"""Per-profile coverage: what the charts apply, and what stays open.

Invariants, not counts - a content bump legitimately moves every number here.
The one exception is the rhcos4-moderate open set, which is pinned because it
was measured against a live cluster and is the end-to-end claim the generated
table makes.
"""
import unittest

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import applicability as ap
from compliance_remediations_helm import emit
from compliance_remediations_helm import parser as xccdf


@requires(OCP4, RHCOS4)
class TestProfileCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents = [xccdf.parse(f, product=p)
                        for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))]
        cls.appl = ap.build_map(cls.contents)
        cls.rows, cls.open_rules = emit.profile_coverage(cls.contents, cls.appl)
        cls.disabled = emit._disabled_with_category(cls.contents, cls.appl)

    def test_every_profile_appears_once(self):
        profiles = [r["profile"] for r in self.rows]
        self.assertEqual(len(profiles), len(set(profiles)))
        for content in self.contents:
            for pid in content.profiles:
                self.assertIn(pid, profiles)

    def test_the_counts_add_up(self):
        # selects = remediated + no_remediation + disabled-and-selected. The
        # last one is not a column (open is a subset of it), so derive it and
        # assert the remainder is never negative and never exceeds what ships
        # disabled at all.
        for row in self.rows:
            rest = row["selects"] - row["remediated"] - row["no_remediation"]
            self.assertGreaterEqual(rest, 0, row)
            self.assertLessEqual(rest, len(self.disabled), row)
            self.assertLessEqual(row["open"], rest, row)

    def test_open_rules_are_a_subset_of_what_ships_disabled(self):
        self.assertTrue(set(self.open_rules) <= set(self.disabled))

    def test_a_rule_covered_by_an_active_alternative_is_not_open(self):
        # The case that makes this worth generating rather than listing every
        # disabled rule. We ship this one disabled because upstream writes
        # tlsSecurityProfile.Custom, which the API server prunes - but its
        # control is met anyway by the alternative we do apply, and on a live
        # cluster its check reports PASS. Listing it as open would be wrong.
        rule = "ocp4-api_server_tls_security_profile_custom_min_tls_version"
        self.assertIn(rule, self.disabled)
        self.assertNotIn(rule, self.open_rules)
        groups, _ = emit.build_groups(*self.contents)
        self.assertTrue(
            emit._alternatives_of(groups).get(rule),
            "fixture no longer has an alternative; pick another")

    def test_never_applicable_is_not_reported_as_open(self):
        never = set(ap.never_applicable_rules(self.appl))
        self.assertTrue(never, "fixture gone: no never-applicable rules")
        self.assertEqual(never & set(self.open_rules), set())

    def test_rhcos4_moderate_matches_what_the_cluster_showed(self):
        # Measured on OCP 4.22.15 / RHCOS 9.8 after applying this profile: six
        # checks stayed FAIL. Three are these, which the generator knows about.
        # The other three - enable_fips_mode, sshd_limit_user_access,
        # service_usbguard_enabled - cannot be derived and are documented in
        # README.md instead. If this set changes, that prose needs revisiting.
        expected = {
            "rhcos4-audit_rules_time_stime",
            "rhcos4-coreos_nousb_kernel_argument",
            "rhcos4-coreos_page_poison_kernel_argument",
        }
        actual = {r for r, (_c, _w, profs) in self.open_rules.items()
                  if "rhcos4-moderate" in profs}
        self.assertEqual(actual, expected)

    def test_most_of_ocp4_cis_has_no_remediation_anywhere(self):
        # Not a count assertion: the point is that the majority of this profile
        # is unautomatable, which is the fact the docs exist to state. If a
        # content bump ever makes the charts the majority, the README prose
        # claiming otherwise has to change.
        row = next(r for r in self.rows if r["profile"] == "ocp4-cis")
        self.assertGreater(row["no_remediation"], row["remediated"] * 5)

    def test_every_open_rule_carries_a_category_and_a_reason(self):
        for rule, (category, why, profiles) in self.open_rules.items():
            self.assertIn(category, ("opt-in", "broken", "alternative"), rule)
            self.assertTrue(why.strip(), rule)
            self.assertTrue(profiles, f"{rule} is open for no profile")


@requires(OCP4, RHCOS4)
class TestCoverageSection(unittest.TestCase):
    def test_the_generated_section_is_in_rules_matrix(self):
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        matrix = emit.rules_matrix(contents, "0.0.0")
        self.assertIn("## Coverage per profile", matrix)
        self.assertIn("### What stays open", matrix)
        # The per-rule table must still be there, and after the summary.
        self.assertIn("| Rule | Target object |", matrix)
        self.assertLess(matrix.index("## Coverage per profile"),
                        matrix.index("| Rule | Target object |"))

    def test_the_section_stays_ascii(self):
        # AGENTS.md permits the markers only in the per-rule table; the summary
        # must not introduce new glyphs.
        contents = {p: xccdf.parse(f, product=p)
                    for p, f in (("ocp4", OCP4), ("rhcos4", RHCOS4))}
        matrix = emit.rules_matrix(contents, "0.0.0")
        section = matrix[matrix.index("## Coverage per profile"):
                         matrix.index("## Rules")]
        non_ascii = {c for c in section if ord(c) > 127}
        self.assertEqual(non_ascii, set())


if __name__ == "__main__":
    unittest.main()

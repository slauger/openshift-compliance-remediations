"""Tests for emit-level safeguards: dropped-body warning, fragment body."""
import tempfile
import unittest
from pathlib import Path

from compliance_remediations_helm import emit
from compliance_remediations_helm.parser import Content, FixVariant, Rule


class TestYamlScalar(unittest.TestCase):
    def test_yaml11_booleans_are_quoted(self):
        for v in ("yes", "no", "on", "off", "true", "false", "Yes", "OFF", "n", "y"):
            self.assertTrue(emit._yaml_scalar(v).startswith('"'),
                            f"{v!r} must be quoted to stay a string")

    def test_plain_words_not_quoted(self):
        for v in ("WriteRequestBodies", "aescbc", "Intermediate", "VersionTLS12"):
            self.assertEqual(emit._yaml_scalar(v), v)

    def test_numbers_and_modes_quoted(self):
        for v in ("50", "0755", "3.14"):
            self.assertTrue(emit._yaml_scalar(v).startswith('"'))

    def test_special_chars_quoted(self):
        self.assertTrue(emit._yaml_scalar("a: b").startswith('"'))
        self.assertTrue(emit._yaml_scalar("").startswith('"'))


def _rule(rule_id, yaml, product="ocp4"):
    r = Rule(rule_id=rule_id, xccdf_id=f"x_{rule_id}", product=product)
    r.fixes.append(FixVariant(yaml=yaml))
    return r


class TestDroppedBodyWarning(unittest.TestCase):
    def test_unknown_top_level_key_is_reported_not_silently_dropped(self):
        # A fix whose only content is an unrecognized top-level key (stringData)
        # must be recorded in stats["dropped"], not silently skipped.
        yaml = (
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: some-secret\n"
            "stringData:\n"
            "  foo: bar\n"
        )
        content = Content(
            rules={"weird_rule": _rule("weird_rule", yaml)},
            values={}, profiles={}, product="ocp4",
        )
        with tempfile.TemporaryDirectory() as d:
            stats = emit.generate_charts({"ocp4": content}, Path(d), "0.0.0")
        self.assertTrue(
            any("weird_rule" in x for x in stats["dropped"]),
            f"expected weird_rule in dropped, got {stats['dropped']}",
        )

    def test_recognized_body_is_not_dropped(self):
        yaml = (
            "apiVersion: config.openshift.io/v1\n"
            "kind: APIServer\n"
            "metadata:\n"
            "  name: cluster\n"
            "spec:\n"
            "  audit:\n"
            "    profile: WriteRequestBodies\n"
        )
        content = Content(
            rules={"good_rule": _rule("good_rule", yaml)},
            values={}, profiles={}, product="ocp4",
        )
        with tempfile.TemporaryDirectory() as d:
            stats = emit.generate_charts({"ocp4": content}, Path(d), "0.0.0")
        self.assertEqual(stats["dropped"], [])


class TestChartYaml(unittest.TestCase):
    def test_a_colon_in_the_description_does_not_break_the_file(self):
        # description was interpolated unquoted, so ": " in it made Chart.yaml
        # invalid YAML - and the failure surfaced later, in `helm dependency
        # update`, after the charts were already written.
        import yaml
        text = emit.chart_yaml("c", "Remediations: config objects, no reboots.",
                               "0.1.82", "1.2.3")
        doc = yaml.safe_load(text)
        self.assertEqual(doc["description"],
                         "Remediations: config objects, no reboots.")

    def test_every_generated_chart_yaml_parses(self):
        import yaml
        from pathlib import Path
        charts = sorted(Path("charts").glob("*/Chart.yaml"))
        self.assertTrue(charts, "no charts generated")
        for path in charts:
            with self.subTest(chart=path.parent.name):
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertTrue(doc.get("description"))


if __name__ == "__main__":
    unittest.main()

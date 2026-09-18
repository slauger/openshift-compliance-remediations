"""Ignition payload integrity.

Upstream `{{ ... }}` blocks are the Compliance Operator's remediation-templating
directive, not literal content. Emitting them verbatim wrote `{{ ` and
unsubstituted `{{.var_x}}` into the files the MachineConfigs lay down, which
auditd/sshd/chronyd reject. These tests guard both halves: the rewrite itself,
and the generated charts as a whole.
"""
import re
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import emit, resolver
from compliance_remediations_helm import parser as xccdf


class TestActionTranslation(unittest.TestCase):
    def test_chrony_range_becomes_helm_range(self):
        # The one control-flow idiom upstream uses: loop over the NTP servers.
        block = (
            "{{ %7B%7Brange%20%24e%3A%3D.var_multiple_time_servers"
            "%7CtoArrayByComma%7D%7Dserver%20%7B%7B%24e%7D%7D%7B%7Bend%7D%7D }}"
        )
        out = resolver.rewrite_placeholders(block)
        self.assertIn('{{ range $e:=.Values.variables.var_multiple_time_servers'
                      ' | splitList "," }}', out)
        self.assertIn("{{ $e }}", out)
        self.assertIn("{{ end }}", out)
        self.assertNotIn("%7B%7B", out)

    def test_unsupported_construct_fails_loudly(self):
        # An unevaluated template in a node config file is the failure mode this
        # path exists to prevent - better to break generation than to ship it.
        block = "{{ %7B%7Bif%20eq%20.var_x%20%22y%22%7D%7Da%7B%7Bend%7D%7D }}"
        with self.assertRaises(ValueError) as cm:
            resolver.rewrite_placeholders(block)
        self.assertIn("unsupported", str(cm.exception))

    def test_variables_inside_control_flow_are_collected(self):
        # var_time_service_set_maxpoll is only referenced from an assignment;
        # missing it would leave it out of values.yaml.
        fix = ("{{ %7B%7B%24m%3A%3D.var_time_service_set_maxpoll%7D%7D"
               "%7B%7B.var_multiple_time_servers%7D%7D }}")
        rule = xccdf.Rule(rule_id="r", xccdf_id="x", fixes=[xccdf.FixVariant(yaml=fix)])
        content = xccdf.Content(rules={"r": rule}, values={}, profiles={})
        self.assertEqual(
            resolver.referenced_variables(content),
            {"var_time_service_set_maxpoll", "var_multiple_time_servers"},
        )


@requires(OCP4, RHCOS4)
class TestGeneratedPayloads(unittest.TestCase):
    """No template may carry an unresolved placeholder into a rendered file."""

    @classmethod
    def setUpClass(cls):
        contents = {
            "ocp4": xccdf.parse(OCP4, product="ocp4"),
            "rhcos4": xccdf.parse(RHCOS4, product="rhcos4"),
        }
        cls._tmp = tempfile.TemporaryDirectory()
        emit.generate_charts(contents, Path(cls._tmp.name), "0.0.0")
        cls.templates = sorted(Path(cls._tmp.name).rglob("templates/*.yaml"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_templates_exist(self):
        self.assertGreater(len(self.templates), 100)

    def test_no_encoded_placeholder_survives(self):
        offenders = [t.name for t in self.templates if "%7B%7B" in t.read_text()]
        self.assertEqual(offenders, [], f"unresolved encoded placeholders in {offenders}")

    def test_no_block_marker_is_emitted_as_literal(self):
        # `data:,{{ "{{" }}` renders to a payload whose first character is "{".
        offenders = [t.name for t in self.templates if 'data:,{{ "{{" }}' in t.read_text()]
        self.assertEqual(offenders, [], f"block markers emitted as literals in {offenders}")

    def test_decoded_payloads_carry_no_template_syntax(self):
        # Decode every data URI with its Helm actions stripped: what remains is
        # what Ignition writes to disk, and it must be free of template syntax.
        offenders = []
        for t in self.templates:
            # to end of line: a Helm action inside the URI contains spaces
            for m in re.finditer(r"source:\s*data:,(.*)$", t.read_text(), re.M):
                stripped = re.sub(r"\{\{.*?\}\}", "", m.group(1))
                decoded = urllib.parse.unquote(stripped)
                if "{{" in decoded or "}}" in decoded:
                    offenders.append(t.name)
                    break
        self.assertEqual(offenders, [], f"template syntax reaches disk in {offenders}")


if __name__ == "__main__":
    unittest.main()

"""Resolver tests: variable default selection + placeholder rewriting."""
import unittest

from _datastream import OCP4, requires

from compliance_remediations_helm import parser, resolver
from compliance_remediations_helm import parser as xccdf


def _content_with_fix(fix_yaml: str) -> parser.Content:
    rule = parser.Rule(rule_id="r", xccdf_id="x", fixes=[parser.FixVariant(yaml=fix_yaml)])
    return parser.Content(rules={"r": rule}, values={}, profiles={})


@requires(OCP4)
class TestResolveDefaults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = xccdf.parse(OCP4, product="ocp4")
        cls.vars = resolver.resolve_defaults(cls.content)

    def test_audit_profile_uses_profile_refinement_not_bare_default(self):
        # bare Value default is "Default"; the vast majority of profiles refine
        # to "WriteRequestBodies" - the shipped default must be the stronger one.
        self.assertEqual(self.vars["var_openshift_audit_profile"], "WriteRequestBodies")

    def test_oauth_token_maxage_uses_stronger_8h(self):
        # bare default 86400 (24h); profiles refine to 28800 (8h).
        self.assertEqual(self.vars["var_oauth_token_maxage"], "28800")

    def test_all_referenced_vars_resolved(self):
        refs = resolver.referenced_variables(self.content)
        self.assertEqual(set(self.vars), refs)
        self.assertTrue(all(v != "" for v in self.vars.values()))


class TestRewritePlaceholders(unittest.TestCase):
    """Every `{{ ... }}` in a fix is the operator's remediation-templating
    directive, not literal content: markers are stripped, the payload keeps its
    percent-encoding, variable refs (plain or encoded) become Helm refs."""

    def test_xccdf_var_becomes_helm_ref(self):
        out = resolver.rewrite_placeholders("x: {{.var_foo}}")
        self.assertEqual(out, "x: {{ .Values.variables.var_foo }}")

    def test_encoded_var_inside_ignition_payload_becomes_helm_ref(self):
        out = resolver.rewrite_placeholders(
            "source: data:,{{ flush%20%3D%20%7B%7B.var_auditd_flush%7D%7D%0A }}")
        self.assertEqual(
            out, "source: data:,flush%20%3D%20{{ .Values.variables.var_auditd_flush }}%0A")

    def test_block_markers_are_not_written_into_the_payload(self):
        # Regression: emitting the markers as literal text laid down a file
        # starting with "{{ " on the node (auditd/sshd refuse to start).
        out = resolver.rewrite_placeholders("source: data:,{{ Protocol%202 }}")
        self.assertEqual(out, "source: data:,Protocol%202")
        self.assertNotIn('{{ "{{" }}', out)

    def test_payload_without_variables_keeps_its_encoding(self):
        out = resolver.rewrite_placeholders("source: data:,{{ -a%20always%20-F%20arch%3Db64 }}")
        self.assertEqual(out, "source: data:,-a%20always%20-F%20arch%3Db64")

    def test_var_without_var_prefix_is_recognized(self):
        out = resolver.rewrite_placeholders("s: {{ %7B%7B.sshd_idle_timeout_value%7D%7D }}")
        self.assertEqual(out, "s: {{ .Values.variables.sshd_idle_timeout_value }}")

    def test_unterminated_brace_is_escaped(self):
        out = resolver.rewrite_placeholders("x: {{ unterminated")
        self.assertIn('{{ "{{" }}', out)


class TestReferencedVariables(unittest.TestCase):
    def test_both_placeholder_shapes_are_collected(self):
        content = _content_with_fix(
            "a: {{.var_plain}}\nsource: data:,{{ x%3D%7B%7B.var_encoded%7D%7D }}")
        self.assertEqual(
            resolver.referenced_variables(content), {"var_plain", "var_encoded"})


if __name__ == "__main__":
    unittest.main()

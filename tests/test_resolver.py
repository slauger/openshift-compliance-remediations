"""Resolver tests: variable default selection + placeholder rewriting."""
import unittest

from _datastream import OCP4, requires

from compliance_remediations_helm import parser as xccdf
from compliance_remediations_helm import resolver


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
    def test_xccdf_var_becomes_helm_ref(self):
        out = resolver.rewrite_placeholders("x: {{.var_foo}}")
        self.assertEqual(out, "x: {{ .Values.variables.var_foo }}")

    def test_literal_braces_are_escaped(self):
        # audit data payloads carry literal {{ ... }} that must not be evaluated.
        out = resolver.rewrite_placeholders("source: data:,{{ -a%20always }}")
        self.assertIn('{{ "{{" }}', out)
        self.assertIn('{{ "}}" }}', out)
        self.assertNotIn("{{.var", out)

    def test_mixed_var_and_literal(self):
        out = resolver.rewrite_placeholders("a: {{.var_x}}\nb: data:,{{ z }}")
        self.assertIn("{{ .Values.variables.var_x }}", out)
        self.assertIn('{{ "{{" }}', out)


if __name__ == "__main__":
    unittest.main()

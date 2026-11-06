"""Hosted cluster outputs: the aggregate templates and their checks."""
import sys
import unittest
from pathlib import Path

from _datastream import OCP4, RHCOS4, requires

from compliance_remediations_helm import applicability, emit
from compliance_remediations_helm import parser as xccdf
from compliance_remediations_helm.collisions import FixDoc, MergeGroup, ObjectKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_payloads import (  # noqa: E402
    Findings,
    check_hostedcluster,
    unwrap_nodepool,
)


def _group(kind, name, rule="r", body="spec:\n  a: 1\n"):
    api = {"MachineConfig": "machineconfiguration.openshift.io/v1"}.get(kind, "config.openshift.io/v1")
    key = ObjectKey(api_version=api, kind=kind, namespace="", name=name)
    doc = FixDoc(rule_id=rule, key=key, yaml=f"kind: {kind}\n{body}")
    return MergeGroup(key=key, docs=[doc])


class TestNodePoolTemplate(unittest.TestCase):
    def test_objects_are_listed_sorted_whatever_the_input_order(self):
        # The content feeds the hash that decides whether a NodePool rolls.
        groups = [_group("MachineConfig", "75-b"), _group("MachineConfig", "75-a")]
        forward = emit.nodepool_configmap_template(groups)
        self.assertEqual(forward, emit.nodepool_configmap_template(groups[::-1]))
        self.assertLess(forward.index("machineconfig-75-a"), forward.index("machineconfig-75-b"))

    def test_only_node_objects_are_wrapped(self):
        out = emit.nodepool_configmap_template(
            [_group("MachineConfig", "75-a"), _group("APIServer", "cluster")])
        self.assertIn("machineconfig-75-a", out)
        self.assertNotIn("apiserver-cluster", out)

    def test_an_object_without_a_body_is_not_included(self):
        # object_template is never written for it, so the include would abort.
        out = emit.nodepool_configmap_template(
            [_group("MachineConfig", "75-a", body="stringData:\n  a: 1\n")])
        self.assertNotIn("machineconfig-75-a", out)

    def test_size_is_refused_before_the_api_server_does(self):
        out = emit.nodepool_configmap_template([_group("MachineConfig", "75-a")])
        self.assertIn(f"gt (len $docs) {emit.CONFIGMAP_MAX_BYTES}", out)

    def test_a_kubeletconfig_gets_a_configmap_of_its_own(self):
        # The controller mirrors a ConfigMap holding one, whole, into the guest.
        out = emit.nodepool_configmap_template(
            [_group("MachineConfig", "75-a"), _group("KubeletConfig", "k")])
        self.assertLess(out.index("$docs = printf"), out.index("cr.obj.kubeletconfig-k"))
        self.assertLess(out.index("cr.obj.machineconfig-75-a"), out.index("$kubelet"))
        self.assertIn('(printf "%s-kubelet" $name)', out)


class TestLabels(unittest.TestCase):
    def test_a_wrapped_object_does_not_carry_the_release_name(self):
        # The controller hashes the object, labels included.
        lines = emit._labels_block("$", "remediation", nodepool_aware=True)
        at = next(i for i, ln in enumerate(lines) if "instance" in ln)
        self.assertIn('ne $.Values.node.output "nodepool"', lines[at - 1])
        self.assertIn("end", lines[at + 1])

    def test_everything_else_always_does(self):
        lines = emit._labels_block("", "remediation")
        self.assertFalse(any("nodepool" in ln for ln in lines))


class TestHostedClusterTemplate(unittest.TestCase):
    def test_maps_only_what_the_control_plane_owns(self):
        out = emit.hostedcluster_template([
            _group("APIServer", "cluster", "a"), _group("Project", "cluster", "b")])
        self.assertIn('(list "apiServer" "cr.obj.apiserver-cluster")', out)
        self.assertNotIn("cr.obj.project-cluster", out)

    def test_counts_the_rules_left_on_the_guest(self):
        out = emit.hostedcluster_template([
            _group("APIServer", "cluster", "mapped"), _group("Project", "cluster", "guest-rule")])
        self.assertIn('{{- $guest := int (include "cr.countActive" (dict "root" . "rules" (list "guest-rule"))) }}', out)

    def test_says_in_each_output_what_the_other_one_holds(self):
        out = emit.hostedcluster_template([
            _group("APIServer", "cluster", "mapped"), _group("Project", "cluster", "guest-rule")])
        self.assertIn('(list "mapped")', out)
        self.assertIn("render again with platform.output=hostedcluster", out)
        self.assertIn("render again with platform.output=guest", out)

    def test_cannot_lose_the_keep_annotations(self):
        # This object is the hosted cluster: an uninstall must not delete it.
        out = emit.hostedcluster_template([_group("APIServer", "cluster")])
        self.assertIn("helm.sh/resource-policy: keep", out)
        self.assertIn("argocd.argoproj.io/sync-options: Prune=false,Delete=false", out)


class TestObjectTemplateOutputs(unittest.TestCase):
    def test_each_kind_renders_for_the_outputs_it_belongs_to(self):
        cases = {
            ("MachineConfig", "75-a"): 'ne .Values.node.output "nodepool"',
            ("APIServer", "cluster"): 'eq .Values.platform.output "cluster"',
            ("Project", "cluster"): 'ne .Values.platform.output "hostedcluster"',
        }
        for (kind, name), when in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(f"{{{{- if {when} -}}}}",
                              emit.object_template(_group(kind, name)))


def _configmap(config, **extra):
    return {"kind": "ConfigMap", "metadata": {"name": "cm"},
            "data": {"config": config, **extra}}


_WORKER = """\
---
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: a
  labels:
    machineconfiguration.openshift.io/role: worker
spec: {}
"""


class TestUnwrapNodePool(unittest.TestCase):
    def _run(self, docs):
        fnd = Findings()
        return unwrap_nodepool("t", docs, fnd), fnd

    def test_yields_every_wrapped_object(self):
        out, fnd = self._run([_configmap(_WORKER + _WORKER.replace("name: a", "name: b"))])
        self.assertEqual([o["metadata"]["name"] for o in out], ["a", "b"])
        self.assertEqual(fnd.errors, [])

    def test_object_next_to_the_configmap_is_an_error(self):
        _, fnd = self._run([{"kind": "MachineConfig", "metadata": {"name": "a"}}])
        self.assertIn("management cluster", fnd.errors[0])

    def test_any_key_but_config_is_an_error(self):
        _, fnd = self._run([_configmap(_WORKER, other="x")])
        self.assertIn("only reads 'config'", fnd.errors[0])

    def test_master_object_is_an_error(self):
        _, fnd = self._run([_configmap(_WORKER.replace("role: worker", "role: master"))])
        self.assertIn("not a worker object", fnd.errors[0])

    def test_a_pool_selector_is_an_error(self):
        _, fnd = self._run([_configmap(_WORKER.replace(
            "spec: {}", "spec:\n  machineConfigPoolSelector: {matchLabels: {a: b}}"))])
        self.assertIn("selects a pool", fnd.errors[0])

    def test_invalid_yaml_is_an_error_not_a_crash(self):
        _, fnd = self._run([_configmap("a: [")])
        self.assertIn("invalid YAML", fnd.errors[0])

    def test_an_empty_document_is_an_error_the_yaml_parser_would_hide(self):
        # The controller splits on separator lines and fails to decode this.
        _, fnd = self._run([_configmap(_WORKER + "---\n# only a comment\n---\n")])
        self.assertIn("empty document", fnd.errors[0])

    def test_a_configmap_without_objects_is_an_error(self):
        _, fnd = self._run([_configmap("# nothing\n")])
        self.assertIn("no object", fnd.errors[0])

    def _kubelet(self, name="k"):
        return (f"kind: KubeletConfig\nmetadata:\n  name: {name}\n  labels:\n"
                f"    machineconfiguration.openshift.io/role: worker\nspec: {{}}\n")

    def test_a_kubeletconfig_next_to_other_objects_is_an_error(self):
        _, fnd = self._run([_configmap(_WORKER + "---\n" + self._kubelet())])
        self.assertIn("mirrored to the guest", fnd.errors[0])

    def test_a_second_kubeletconfig_is_an_error(self):
        _, fnd = self._run([_configmap(self._kubelet("a")), _configmap(self._kubelet("b"))])
        self.assertIn("takes one", fnd.errors[0])

    def test_the_release_name_inside_is_an_error(self):
        _, fnd = self._run([_configmap(_WORKER.replace(
            "labels:\n", "labels:\n    app.kubernetes.io/instance: r\n"))])
        self.assertIn("roll every worker", fnd.errors[0])


class TestCheckHostedCluster(unittest.TestCase):
    def _errors(self, docs):
        fnd = Findings()
        check_hostedcluster("t", docs, fnd)
        return fnd.errors

    def _hc(self, spec):
        return {"kind": "HostedCluster", "metadata": {"name": "c"}, "spec": spec}

    def test_accepts_the_mapped_fields(self):
        self.assertEqual(self._errors([self._hc(
            {"configuration": {"apiServer": {"audit": {}}, "oauth": {}}})]), [])

    def test_refuses_a_field_outside_configuration(self):
        self.assertTrue(self._errors([self._hc(
            {"configuration": {"oauth": {}}, "release": {}})]))

    def test_refuses_an_unmapped_configuration_field(self):
        self.assertTrue(self._errors([self._hc({"configuration": {"ingress": {}}})]))

    def test_refuses_encryption(self):
        self.assertTrue(self._errors([self._hc(
            {"configuration": {"apiServer": {"encryption": {"type": "aescbc"}}}})]))

    def test_refuses_anything_next_to_it(self):
        self.assertTrue(self._errors([
            self._hc({"configuration": {"oauth": {}}}), {"kind": "Project"}]))


class TestHypershiftOverlay(unittest.TestCase):
    def test_lists_only_what_upstream_excludes_from_hosted_clusters(self):
        appl = {
            "excluded": applicability.Applicability(
                constraints={applicability.AXIS_HYPERSHIFT: frozenset((False,))}),
            "required": applicability.Applicability(
                constraints={applicability.AXIS_HYPERSHIFT: frozenset((True,))}),
            "arch": applicability.Applicability(
                constraints={applicability.AXIS_ARCH: frozenset(("s390x",))}),
            "other-chart": applicability.Applicability(
                constraints={applicability.AXIS_HYPERSHIFT: frozenset((False,))}),
        }
        self.assertEqual(
            list(emit._excluded_on_hypershift(appl, {"excluded", "required", "arch"})),
            ["excluded"])

    def test_nested_form_keeps_each_chart_under_its_prefix(self):
        out = emit._hypershift_overlay(
            {"a": {"r": "why"}, "b": {}}, "0.0.0", nested=True)
        self.assertIn("a:\n  cluster:\n    hypershift: true\n  rules:\n    r: false  # why", out)
        self.assertIn("b:\n  cluster:\n    hypershift: true", out)


@requires(OCP4, RHCOS4)
class TestHostedCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contents = [xccdf.parse(OCP4, product="ocp4"), xccdf.parse(RHCOS4, product="rhcos4")]
        cls.appl = applicability.build_map(cls.contents)
        rows, cls.rules = emit.hosted_coverage(cls.contents, cls.appl)
        cls.rows = {r["profile"]: r for r in rows}

    def test_accounts_for_every_rule_the_standalone_coverage_remediates(self):
        # A rule falling out of all four columns would be a gap nobody sees.
        standalone, _ = emit.profile_coverage(self.contents, self.appl)
        for row in standalone:
            hosted = self.rows.get(row["profile"])
            total = sum(v for k, v in hosted.items() if k != "profile") if hosted else 0
            self.assertEqual(total, row["remediated"], row["profile"])

    def test_every_rule_upstream_excludes_is_counted_as_not_remediable(self):
        excluded = emit._excluded_on_hypershift(self.appl, {
            r.helm_name for c in self.contents for r in xccdf.rules_with_fixes(c).values()})
        self.assertTrue(excluded)
        self.assertTrue(any(r["not_remediable"] for r in self.rows.values()))

    def test_names_every_rule_outside_the_nodepool(self):
        self.assertTrue(self.rules)
        self.assertFalse([r for r in self.rules if r["where"] == "nodepool"])

    def test_flags_rules_a_guest_scan_cannot_see(self):
        blind = [r for r in self.rules if r["scan_blind"]]
        self.assertTrue(blind)
        self.assertEqual({r["target"] for r in blind}, {"OAuth/cluster"})

    def test_node_profiles_do_not_touch_the_hosted_cluster_object(self):
        for pid, row in self.rows.items():
            if pid.startswith("rhcos4-"):
                self.assertEqual(row["hostedcluster"] + row["guest"], 0, pid)


if __name__ == "__main__":
    unittest.main()

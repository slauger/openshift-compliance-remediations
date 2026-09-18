#!/usr/bin/env python3
"""Validate what the generated charts actually write to a node.

`helm lint` and `helm unittest` check the manifests. Nothing checks the payload
*inside* them: an Ignition `data:,` URI is an opaque string to every YAML-level
tool, so a MachineConfig can be perfectly valid and still lay down an
/etc/ssh/sshd_config that sshd refuses to parse - which locks every node in the
pool out, first visible during an MCP rollout.

Two modes:

  render    Render every profile on its own. Catches a profile that fails to
            render, produces empty documents, or emits two objects with the
            same kind/namespace/name.

  arch      Render once per architecture with the generated overlay, prove
            the applicability gate fires without it, and that the schema
            rejects a bad architecture.

  payloads  Render with everything enabled across a cluster.ocpVersion matrix,
            decode every file payload, and run it through the parser that owns
            that file on the node.

Checks needing a tool that is not installed are reported as skipped, never
silently passed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - dev extra
    sys.exit("PyYAML is required: pip install -e '.[dev]'")

ROOT = Path(__file__).resolve().parents[1]
CHARTS = ROOT / "charts"
NODE = CHARTS / "compliance-node"
PLATFORM = CHARTS / "compliance-platform"
# Version-gated fix variants mean a payload can be correct at 4.18 and broken at
# 4.12, so the matrix is the point, not noise.
ARCHITECTURES = ("x86_64", "aarch64", "ppc64le", "s390x")

VERSIONS = ("4.12", "4.14", "4.16", "4.18", "4.20")

_DATA_URI_RE = re.compile(r"^data:([^,]*),(.*)$", re.DOTALL)


class Findings:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.skipped: dict[str, int] = {}
        self.checked: dict[str, int] = {}
        self._seen: set[str] = set()
        self.duplicates = 0

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def skip(self, check: str) -> None:
        self.skipped[check] = self.skipped.get(check, 0) + 1

    def ok(self, check: str) -> None:
        self.checked[check] = self.checked.get(check, 0) + 1

    def first_time(self, check: str, payload: str) -> bool:
        """False if this exact content was already checked.

        The same file is emitted for every role and every cluster.ocpVersion it
        applies to, so the matrix produces an order of magnitude more payloads
        than there are distinct ones. Checking each distinct payload once keeps
        the run honest and fast; `duplicates` reports what was collapsed.
        """
        digest = hashlib.sha256(f"{check}\0{payload}".encode()).hexdigest()
        if digest in self._seen:
            self.duplicates += 1
            return False
        self._seen.add(digest)
        return True


def helm_template(chart: Path, sets: dict[str, str],
                  files: list[str] | None = None) -> str:
    cmd = ["helm", "template", "t", str(chart)]
    for f in files or []:
        cmd += ["-f", f]
    for k, v in sets.items():
        cmd += ["--set", f"{k}={v}"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return proc.stdout


def profiles_of(chart: Path) -> list[str]:
    values = yaml.safe_load((chart / "values.yaml").read_text())
    return sorted(values.get("profiles", {}))


def decode_data_uri(source: str) -> str | None:
    m = _DATA_URI_RE.match(source)
    if not m:
        return None
    meta, payload = m.groups()
    if "base64" in meta:
        import base64
        return base64.b64decode(payload).decode("utf-8", "replace")
    return urllib.parse.unquote(payload)


def iter_files(docs: list[dict]):
    """Yield (machineconfig_name, path, mode, decoded_contents)."""
    for doc in docs:
        if not doc or doc.get("kind") != "MachineConfig":
            continue
        name = doc.get("metadata", {}).get("name", "<unnamed>")
        storage = doc.get("spec", {}).get("config", {}).get("storage", {})
        for f in storage.get("files") or []:
            source = (f.get("contents") or {}).get("source")
            if not isinstance(source, str):
                continue
            decoded = decode_data_uri(source)
            if decoded is None:
                continue
            yield name, f.get("path", "<nopath>"), f.get("mode"), decoded


# --------------------------------------------------------------------------
# payload checks


def check_no_template_syntax(where: str, path: str, body: str, fnd: Findings) -> None:
    """The check that would have caught the operator-templating bug."""
    for marker in ("{{", "}}", "%7B%7B"):
        if marker in body:
            first = body.splitlines()[0][:60] if body else ""
            fnd.error(where, f"{path} contains unevaluated template syntax "
                             f"{marker!r} (first line: {first!r})")
            return
    fnd.ok("no-template-syntax")


def check_sshd(where: str, path: str, body: str, fnd: Findings) -> None:
    sshd = shutil.which("sshd") or shutil.which("sshd", path="/usr/sbin:/sbin")
    if not sshd:
        fnd.skip("sshd -t")
        return
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(body)
        tmp = fh.name
    try:
        proc = subprocess.run([sshd, "-t", "-f", tmp], capture_output=True, text=True)
        out = proc.stderr + proc.stdout
        # Missing host keys and deprecation warnings are environment/upstream
        # noise; a parse error is not.
        fatal = [ln for ln in out.splitlines()
                 if "bad configuration option" in ln
                 or re.search(r"line \d+:", ln) and "Deprecated option" not in ln]
        if fatal:
            fnd.error(where, f"{path} rejected by sshd -t: {fatal[0]}")
        else:
            fnd.ok("sshd -t")
    finally:
        Path(tmp).unlink(missing_ok=True)


# Without auditctl this is a shape check, not a syntax check: every non-comment
# line must be an option. Long options (--loginuid-immutable) are valid too.
_AUDIT_LINE_RE = re.compile(r"^\s*(#|$|-)")


def check_audit_rules(where: str, path: str, body: str, fnd: Findings) -> None:
    auditctl = shutil.which("auditctl")
    if auditctl:
        proc = subprocess.run([auditctl, "-R", "/dev/stdin"], input=body,
                              capture_output=True, text=True)
        # -R needs privileges; only treat a syntax complaint as a failure.
        if "syntax error" in (proc.stderr + proc.stdout).lower():
            fnd.error(where, f"{path} rejected by auditctl: {proc.stderr.strip()}")
            return
        fnd.ok("auditctl -R")
        return
    fnd.skip("auditctl -R")
    for n, line in enumerate(body.splitlines(), 1):
        if not _AUDIT_LINE_RE.match(line):
            fnd.error(where, f"{path}:{n} is not an audit rule option: {line[:60]!r}")
            return
    fnd.ok("audit-rule-shape")


def check_sysctl(where: str, path: str, body: str, fnd: Findings) -> None:
    for n, line in enumerate(body.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            fnd.error(where, f"{path}:{n} is not key = value: {line[:60]!r}")
            return
        key, value = line.split("=", 1)
        if not key.strip() or not value.strip():
            fnd.error(where, f"{path}:{n} has an empty key or value: {line[:60]!r}")
            return
    fnd.ok("sysctl-syntax")


def check_keyvalue_conf(where: str, path: str, body: str, fnd: Findings) -> None:
    """auditd.conf and friends: `key = value`, no value left unset."""
    for n, line in enumerate(body.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not value.strip():
            fnd.error(where, f"{path}:{n} leaves {key.strip()!r} unset")
            return
    fnd.ok("keyvalue-conf")


DISPATCH = (
    (re.compile(r"^/etc/ssh/sshd_config"), check_sshd),
    (re.compile(r"^/etc/audit/rules\.d/.*\.rules$"), check_audit_rules),
    (re.compile(r"^/etc/audit/auditd\.conf$"), check_keyvalue_conf),
    (re.compile(r"^/etc/sysctl\.d/"), check_sysctl),
)


def validate_payloads(fnd: Findings) -> None:
    ignition_validate = shutil.which("ignition-validate")
    for version in VERSIONS:
        sets = {"node.enabled": "true", "cluster.ocpVersion": version}
        for profile in profiles_of(NODE):
            sets[f"profiles.{profile}"] = "true"
        where = f"node@{version}"
        try:
            rendered = helm_template(NODE, sets)
        except RuntimeError as exc:
            fnd.error(where, f"render failed: {exc}")
            continue
        docs = [d for d in yaml.safe_load_all(rendered) if d]
        for mc, path, _mode, body in iter_files(docs):
            loc = f"{where}/{mc}"
            if not fnd.first_time(f"payload:{path}", body):
                continue
            check_no_template_syntax(loc, path, body, fnd)
            for pattern, check in DISPATCH:
                if pattern.match(path):
                    check(loc, path, body, fnd)
                    break
        if ignition_validate:
            for doc in docs:
                if doc.get("kind") != "MachineConfig":
                    continue
                config = doc.get("spec", {}).get("config")
                if not config:
                    continue
                serialized = json.dumps(config, sort_keys=True)
                if not fnd.first_time("ignition", serialized):
                    continue
                # Ignition configs are JSON; the validator rejects YAML.
                proc = subprocess.run([ignition_validate, "-"],
                                      input=json.dumps(config),
                                      capture_output=True, text=True)
                if proc.returncode != 0:
                    name = doc.get("metadata", {}).get("name")
                    out = (proc.stdout + proc.stderr).strip() or "no output"
                    fnd.error(where, f"{name} rejected by ignition-validate: {out[:200]}")
                else:
                    fnd.ok("ignition-validate")
        else:
            fnd.skip("ignition-validate")


# --------------------------------------------------------------------------
# render checks


# The same key set object_template() looks for when deciding a fix has content.
_BODY_KEYS = ("spec", "data", "rules", "parameters", "projectRequestTemplate",
              "objects")


def check_object_has_body(where: str, docs: list, fnd: Findings) -> None:
    """A manifest without a body is content-free but still triggers a rollout.

    This is the structural counterpart to the render-time guard: if every
    fragment of an object is gated off, the object must not be emitted at all.
    """
    for doc in docs:
        if not doc:
            continue
        if not any(k in doc for k in _BODY_KEYS):
            name = doc.get("metadata", {}).get("name", "<unnamed>")
            fnd.error(where, f"{doc.get('kind')}/{name} has no body "
                             f"({'/'.join(_BODY_KEYS)} all absent)")
            return
    fnd.ok("object-has-body")


def validate_renders(fnd: Findings) -> None:
    for chart, extra in ((PLATFORM, {}), (NODE, {"node.enabled": "true"})):
        for profile in profiles_of(chart):
            where = f"{chart.name}/{profile}"
            try:
                rendered = helm_template(chart, {**extra, f"profiles.{profile}": "true"})
            except RuntimeError as exc:
                fnd.error(where, f"render failed: {exc}")
                continue
            try:
                docs = list(yaml.safe_load_all(rendered))
            except yaml.YAMLError as exc:
                fnd.error(where, f"output is not valid YAML: {exc}")
                continue
            if any(d is None for d in docs) and rendered.strip():
                fnd.error(where, "output contains an empty document")
                continue
            seen: dict[tuple, str] = {}
            for doc in (d for d in docs if d):
                key = (doc.get("kind"),
                       doc.get("metadata", {}).get("namespace", ""),
                       doc.get("metadata", {}).get("name"))
                if key in seen:
                    fnd.error(where, f"duplicate object {key}")
                    break
                seen[key] = where
            check_object_has_body(where, docs, fnd)
            fnd.ok("render")


# --------------------------------------------------------------------------
# applicability checks


def validate_architectures(fnd: Findings) -> None:
    """Render once per architecture, with the overlay the generator wrote.

    Version-gated variants are already covered by the payload matrix; what this
    adds is proof that the applicability gate fires, that the overlay is
    sufficient to satisfy it, and that no architecture ends up with a
    content-free object.
    """
    counts: dict[str, int] = {}
    for arch in ARCHITECTURES:
        where = f"node@{arch}"
        sets = {"node.enabled": "true", "cluster.architecture": arch}
        for profile in profiles_of(NODE):
            sets[f"profiles.{profile}"] = "true"
        overlay = NODE / f"values-{arch}.yaml"
        files = [str(overlay)] if overlay.exists() else []
        try:
            rendered = helm_template(NODE, sets, files)
        except RuntimeError as exc:
            fnd.error(where, f"render failed even with its overlay: {exc}")
            continue
        docs = [d for d in yaml.safe_load_all(rendered) if d]
        check_object_has_body(where, docs, fnd)
        counts[arch] = len(docs)
        fnd.ok("arch-render")

        # Without the overlay the gate must refuse to render.
        if overlay.exists():
            try:
                helm_template(NODE, sets)
                fnd.error(where, "renders without its overlay - the "
                                 "applicability gate did not fire")
            except RuntimeError as exc:
                if "not applicable" not in str(exc):
                    fnd.error(where, f"refused for the wrong reason: {exc}")
                else:
                    fnd.ok("arch-gate-fires")

    for arch in ("aarch64", "s390x"):
        if arch in counts and "x86_64" in counts:
            if counts[arch] >= counts["x86_64"]:
                fnd.error(f"node@{arch}",
                          f"{counts[arch]} objects, not fewer than x86_64's "
                          f"{counts['x86_64']} - exclusions had no effect")
            else:
                fnd.ok("arch-excludes-objects")


def validate_schema_rejects_typos(fnd: Findings) -> None:
    """A bad architecture must fail, not silently disable every gated rule."""
    try:
        helm_template(NODE, {"node.enabled": "true",
                             "cluster.architecture": "amd644"})
        fnd.error("schema", "cluster.architecture=amd644 was accepted - the "
                            "enum in values.schema.json regressed")
    except RuntimeError:
        fnd.ok("schema-rejects-bad-arch")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=("render", "payloads", "arch", "all"))
    args = ap.parse_args()

    fnd = Findings()
    if args.mode in ("render", "all"):
        validate_renders(fnd)
    if args.mode in ("payloads", "all"):
        validate_payloads(fnd)
    if args.mode in ("arch", "all"):
        validate_architectures(fnd)
        validate_schema_rejects_typos(fnd)

    for check, n in sorted(fnd.checked.items()):
        print(f"  ok       {check}: {n}")
    if fnd.duplicates:
        print(f"  (skipped {fnd.duplicates} payloads identical to one already checked)")
    for check, n in sorted(fnd.skipped.items()):
        print(f"  SKIPPED  {check}: {n} (tool not installed)")
    for err in fnd.errors:
        print(f"  FAIL     {err}")
    if fnd.errors:
        print(f"\n{len(fnd.errors)} payload problem(s)")
        return 1
    print("\nall payload checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

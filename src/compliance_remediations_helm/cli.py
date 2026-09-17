"""CLI entry point: generate Helm charts of OpenShift compliance remediations
from the upstream ComplianceAsCode SCAP datastreams.

Stdlib-only. Installed as ``compliance-remediations-gen`` (see pyproject.toml),
or run as ``python3 -m compliance_remediations_helm.cli``.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from . import collisions, datastream, emit
from . import parser as xccdf

# Datastream -> product mapping.
PRODUCT_BY_DATASTREAM = {
    "ssg-ocp4-ds.xml": "ocp4",
    "ssg-rhcos4-ds.xml": "rhcos4",
}


def _parse_all(extracted: dict[str, Path]) -> dict[str, xccdf.Content]:
    contents: dict[str, xccdf.Content] = {}
    for fname, path in extracted.items():
        product = PRODUCT_BY_DATASTREAM.get(fname)
        if product is None:
            print(f"    skipping unmapped datastream {fname}")
            continue
        contents[product] = xccdf.parse(path, product=product)
    return contents


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="config/content.yaml", type=Path)
    ap.add_argument("--charts-dir", default="charts", type=Path)
    ap.add_argument("--cache", default=".cache", type=Path)
    ap.add_argument("--fetch-only", action="store_true",
                    help="Only download + verify + extract the datastreams")
    ap.add_argument("--refresh-sha", action="store_true",
                    help="Refresh config sha512 for the pinned version and exit "
                         "(run after Renovate bumps the version)")
    args = ap.parse_args(argv)

    print("==> Loading pin")
    pin = datastream.load_config(args.config)
    print(f"    content version: {pin['version']}")

    if args.refresh_sha:
        print("==> Refreshing sha512 for pinned version")
        datastream.refresh_sha512(pin, args.config)
        return 0

    print("==> Fetching + verifying datastreams")
    tarball = datastream.fetch_and_verify(pin, args.cache)
    extracted = datastream.extract_datastreams(tarball, pin, args.cache)
    if args.fetch_only:
        return 0

    print("==> Parsing datastreams")
    contents = _parse_all(extracted)
    for product, content in contents.items():
        fixr = xccdf.rules_with_fixes(content)
        print(f"    {product}: {len(content.rules)} rules, "
              f"{len(fixr)} with k8s fixes, {len(content.profiles)} profiles")

    print("==> Analyzing collisions / conflicts")
    groups, unparseable = collisions.build_groups(*contents.values())
    print("    " + collisions.summarize(groups).replace("\n", "\n    "))
    if unparseable:
        print(f"    WARNING: {len(unparseable)} fix docs unidentified: "
              + ", ".join(d.rule_id for d in unparseable))

    print("==> Building charts")
    stats = emit.generate_charts(contents, args.charts_dir, pin["version"])
    print(f"    platform templates: {stats['platform']}")
    print(f"    node templates:     {stats['node']}")
    print(f"    conflict guards:    {len(stats['conflicts'])}")
    if stats.get("dropped"):
        print(f"    WARNING: {len(stats['dropped'])} fix(es) produced no "
              "recognized body and were NOT emitted (unexpected top-level key?):")
        for d in stats["dropped"]:
            print(f"      - {d}")

    print("==> Writing RULES.md matrix")
    matrix = emit.rules_matrix(contents, pin["version"])
    (args.charts_dir.parent / "RULES.md").write_text(matrix, encoding="utf-8")
    print(f"    RULES.md ({matrix.count(chr(10))} lines)")
    print("==> Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

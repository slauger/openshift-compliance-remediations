"""Download, verify, and extract the upstream SCAP datastream.

Stdlib-only. The pinned version and expected SHA512 live in config/content.yaml.
"""
from __future__ import annotations

import hashlib
import os
import re
import tarfile
import urllib.request
from pathlib import Path


def _read_pin(config_path: Path) -> dict:
    """Minimal YAML reader for config/content.yaml (avoids a pyyaml dependency).

    Supports the small subset we use: scalars and a simple list.
    """
    pin: dict = {"datastreams": []}
    in_list = False
    for raw in config_path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if in_list and line.lstrip().startswith("- "):
            pin["datastreams"].append(line.lstrip()[2:].strip())
            continue
        in_list = False
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip().strip('"')
            if key == "datastreams" and val == "":
                in_list = True
            else:
                pin[key] = val
    return pin


def load_config(config_path: Path) -> dict:
    pin = _read_pin(config_path)
    required = {"version", "sha512", "base_url"}
    missing = required - pin.keys()
    if missing:
        raise ValueError(f"config/content.yaml missing keys: {sorted(missing)}")
    if not pin["datastreams"]:
        raise ValueError("config/content.yaml lists no datastreams")
    return pin


def _sha512(path: Path) -> str:
    h = hashlib.sha512()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_and_verify(pin: dict, cache_dir: Path) -> Path:
    """Download the release tarball (if not cached) and verify its SHA512.

    Returns the path to the verified tarball.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    version = pin["version"]
    tarball = f"scap-security-guide-{version}.tar.gz"
    url = f"{pin['base_url']}/v{version}/{tarball}"
    dest = cache_dir / tarball

    if not dest.exists():
        print(f"  downloading {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(url) as resp, tmp.open("wb") as out:  # noqa: S310
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
        tmp.replace(dest)
    else:
        print(f"  using cached {dest}")

    actual = _sha512(dest)
    expected = pin["sha512"].lower()
    if expected in ("", "verify-on-first-run"):
        raise ValueError(
            f"config/content.yaml has no pinned sha512. Actual is:\n  {actual}\n"
            "Set it in config/content.yaml to lock the content version."
        )
    if actual != expected:
        raise ValueError(
            "SHA512 mismatch - refusing to use untrusted content.\n"
            f"  expected: {expected}\n  actual:   {actual}"
        )
    print(f"  sha512 OK ({actual[:16]}...)")
    return dest


def extract_datastreams(tarball: Path, pin: dict, out_dir: Path) -> dict[str, Path]:
    """Extract the requested ssg-*-ds.xml files from the tarball."""
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = set(pin["datastreams"])
    found: dict[str, Path] = {}
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            base = os.path.basename(member.name)
            if base in wanted:
                # Safe extraction: flatten to out_dir, no path traversal.
                target = out_dir / base
                with tf.extractfile(member) as src, target.open("wb") as dst:  # type: ignore[union-attr]
                    dst.write(src.read())
                found[base] = target
    missing = wanted - found.keys()
    if missing:
        raise ValueError(f"datastreams not found in tarball: {sorted(missing)}")
    for name, path in found.items():
        print(f"  extracted {name} ({path.stat().st_size // 1024} KiB)")
    return found


def refresh_sha512(pin: dict, config_path: Path) -> str:
    """Fetch the upstream .sha512 for the pinned version and rewrite the
    ``sha512:`` line in config/content.yaml. Used after Renovate bumps the
    version. Returns the new checksum.
    """
    version = pin["version"]
    tarball = f"scap-security-guide-{version}.tar.gz"
    url = f"{pin['base_url']}/v{version}/{tarball}.sha512"
    print(f"  fetching {url}")
    with urllib.request.urlopen(url) as resp:  # noqa: S310
        # asset format: "<hex>  scap-security-guide-<version>.tar.gz"
        first = resp.read().decode("utf-8").split()[0].strip().lower()
    if len(first) != 128 or any(c not in "0123456789abcdef" for c in first):
        raise ValueError(f"unexpected sha512 payload from {url}: {first[:80]!r}")

    text = config_path.read_text(encoding="utf-8")
    new_text = re.sub(
        r'(?m)^(sha512:\s*)"[^"]*"\s*$',
        lambda m: f'{m.group(1)}"{first}"',
        text,
    )
    if new_text == text:
        raise ValueError("could not find a sha512: line to update in config")
    config_path.write_text(new_text, encoding="utf-8")
    print(f"  sha512 updated for v{version} ({first[:16]}...)")
    return first

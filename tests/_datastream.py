"""Shared datastream location + gating for the tests that need real content.

Tests that assert against the pinned upstream datastreams need `make fetch`.
Locally a missing `.cache/` skips them so a fresh clone can still run the
offline half of the suite; in CI `REQUIRE_DATASTREAM=1` turns that skip into a
failure, so a green run there always means the datastream tests actually ran.
"""
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OCP4 = ROOT / ".cache" / "ssg-ocp4-ds.xml"
RHCOS4 = ROOT / ".cache" / "ssg-rhcos4-ds.xml"


def requires(*paths: Path):
    """Class decorator: gate a TestCase on extracted datastreams being present."""
    missing = [p.name for p in paths if not p.exists()]
    if not missing:
        return lambda cls: cls
    reason = f"missing {', '.join(missing)} - run `make fetch` first"
    if os.environ.get("REQUIRE_DATASTREAM") == "1":
        def fail(cls):
            def setUpClass(_cls, _reason=reason):
                raise AssertionError(f"REQUIRE_DATASTREAM=1 but {_reason}")
            cls.setUpClass = classmethod(setUpClass)
            return cls
        return fail
    return unittest.skip(reason)

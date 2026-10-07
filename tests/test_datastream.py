"""config/content.yaml checksum refresh.

Offline: the network call is stubbed, because what is worth pinning here is the
rewrite logic, not GitHub's availability.
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from compliance_remediations_helm import datastream as ds

_SHA = "a" * 128
_CONFIG = (
    'version: "0.1.82"\n'
    'base_url: https://example.invalid/releases/download\n'
    f'sha512: "{"b" * 128}"\n'
    "files:\n"
    "  - ssg-ocp4-ds.xml\n"
)


class _Resp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body.encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _run(config_text, upstream_sha):
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "content.yaml"
        path.write_text(config_text, encoding="utf-8")
        pin = {"version": "0.1.82", "base_url": "https://example.invalid/x"}
        with mock.patch.object(
            ds.urllib.request, "urlopen",
            return_value=_Resp(f"{upstream_sha}  scap-security-guide-0.1.82.tar.gz"),
        ):
            result = ds.refresh_sha512(pin, path)
        return result, path.read_text(encoding="utf-8")


class TestRefreshSha512(unittest.TestCase):
    def test_it_rewrites_a_stale_checksum(self):
        result, text = _run(_CONFIG, _SHA)
        self.assertEqual(result, _SHA)
        self.assertIn(f'sha512: "{_SHA}"', text)

    def test_an_already_current_checksum_is_not_an_error(self):
        # This raised "could not find a sha512: line to update in config",
        # because the code compared the text before and after instead of
        # counting substitutions - and those are equal when the checksum is
        # already right. Re-running after Renovate hit exactly that, so a
        # successful no-op looked like a broken config.
        current = _CONFIG.replace("b" * 128, _SHA)
        result, text = _run(current, _SHA)
        self.assertEqual(result, _SHA)
        self.assertEqual(text, current)

    def test_a_missing_sha512_line_still_raises(self):
        with self.assertRaises(ValueError) as cm:
            _run('version: "0.1.82"\nfiles: []\n', _SHA)
        self.assertIn("no `sha512:", str(cm.exception))

    def test_a_bogus_upstream_payload_raises(self):
        with self.assertRaises(ValueError) as cm:
            _run(_CONFIG, "not-a-checksum")
        self.assertIn("unexpected sha512 payload", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

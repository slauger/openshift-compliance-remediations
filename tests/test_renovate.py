"""Renovate config consistency.

A pin that nothing updates rots silently: there is no failing build, no PR, no
dashboard entry - just an old version. `norwoodj/helm-docs` was annotated with
a `# renovate:` comment in two workflows and named in the automerge
`packageRules`, while no custom manager matched its variable, so it was never
offered for update at all. Both ends of the config pointed at each other and
neither pointed at the pin.

Offline and stdlib-only: this reads the repo, not the Renovate API.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "renovate.json"
# Files a pin can live in. Kept explicit rather than globbing the whole tree so
# an unrelated "# renovate:" in docs cannot fail the suite.
PINNED_FILES = [
    ROOT / "config" / "content.yaml",
    *sorted((ROOT / ".github" / "workflows").glob("*.yaml")),
]

_COMMENT_RE = re.compile(r"#\s*renovate:.*?depName=(\S+)")


def _to_python_regex(pattern: str) -> str:
    """Renovate matchStrings are JS regexes; Python spells named groups
    `(?P<n>...)` where JS spells them `(?<n>...)`. Nothing else in these
    patterns differs."""
    return re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern)


def _file_matchers(manager: dict) -> list[re.Pattern]:
    out = []
    for raw in manager["managerFilePatterns"]:
        if not (raw.startswith("/") and raw.endswith("/")):
            raise AssertionError(
                f"managerFilePatterns entry {raw!r} is not the /regex/ form this "
                f"test knows how to evaluate")
        out.append(re.compile(raw[1:-1]))
    return out


class TestRenovateConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(CONFIG.read_text(encoding="utf-8"))
        cls.managers = cls.config.get("customManagers", [])

    def _tracked(self) -> dict[str, list[str]]:
        """depName -> files a custom manager actually extracts it from."""
        tracked: dict[str, list[str]] = {}
        for manager in self.managers:
            patterns = [re.compile(_to_python_regex(p)) for p in manager["matchStrings"]]
            file_res = _file_matchers(manager)
            for path in PINNED_FILES:
                rel = str(path.relative_to(ROOT))
                if not any(fr.search(rel) for fr in file_res):
                    continue
                text = path.read_text(encoding="utf-8")
                for pattern in patterns:
                    for match in pattern.finditer(text):
                        dep = match.groupdict().get("depName")
                        value = match.groupdict().get("currentValue")
                        self.assertTrue(
                            dep and value,
                            f"{rel}: manager matched but captured depName={dep!r} "
                            f"currentValue={value!r}")
                        tracked.setdefault(dep, []).append(rel)
        return tracked

    def test_every_annotated_pin_is_tracked(self):
        annotated: dict[str, list[str]] = {}
        for path in PINNED_FILES:
            rel = str(path.relative_to(ROOT))
            for line in path.read_text(encoding="utf-8").splitlines():
                m = _COMMENT_RE.search(line)
                if m:
                    annotated.setdefault(m.group(1), []).append(rel)
        self.assertTrue(annotated, "no renovate annotations found - wrong paths?")

        tracked = self._tracked()
        missing = {
            dep: files for dep, files in annotated.items()
            if sorted(set(files)) != sorted(set(tracked.get(dep, [])))
        }
        self.assertEqual(
            missing, {},
            "these pins carry a renovate annotation that no customManager "
            f"extracts (annotated -> files): {missing}; tracked: {tracked}")

    def test_package_rules_name_only_tracked_deps(self):
        # A packageRules entry for a depName nothing produces is dead config,
        # and reads as if the dep were handled.
        tracked = set(self._tracked())
        for rule in self.config.get("packageRules", []):
            for dep in rule.get("matchDepNames", []):
                self.assertIn(
                    dep, tracked,
                    f"packageRules names {dep!r}, but no customManager extracts it")


if __name__ == "__main__":
    unittest.main()

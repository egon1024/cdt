#!/usr/bin/env python3
"""Tests for release-notes aggregation in cdt-versions.py."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent / "cdt-versions.py"
spec = importlib.util.spec_from_file_location("cdt_versions", SCRIPT)
assert spec and spec.loader
cdt_versions = importlib.util.module_from_spec(spec)
sys.modules["cdt_versions"] = cdt_versions
spec.loader.exec_module(cdt_versions)


SAMPLE_DELVE = """# delve release notes

## 0.2.0 (2026-01-01)

### New

- **`delve session export`** writes portable JSON bundles.

## 0.1.0

### New

- Initial release.
"""


class ReleaseNotesMarkdownTests(unittest.TestCase):
    def test_extract_version_section(self) -> None:
        section = cdt_versions.extract_version_section(SAMPLE_DELVE, "0.2.0")
        assert section is not None
        self.assertIn("session export", section)
        self.assertNotIn("0.1.0", section)

    def test_extract_missing_version_returns_none(self) -> None:
        self.assertIsNone(cdt_versions.extract_version_section(SAMPLE_DELVE, "9.9.9"))

    def test_render_includes_bullets_and_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notes_dir = Path(tmp)
            (notes_dir / "delve.md").write_text(SAMPLE_DELVE, encoding="utf-8")
            with mock.patch.object(cdt_versions, "RELEASE_NOTES_DIR", notes_dir):
                with mock.patch.object(
                    cdt_versions,
                    "bumped_component_names",
                    return_value={"delve"},
                ):
                    body = cdt_versions.render_release_notes(
                        "1.0.0",
                        {"delve": "0.2.0"},
                    )
            self.assertIn("session export", body)
            self.assertIn("docs/release-notes/delve.md", body)
            self.assertIn("### delve `0.2.0`", body)


if __name__ == "__main__":
    unittest.main()

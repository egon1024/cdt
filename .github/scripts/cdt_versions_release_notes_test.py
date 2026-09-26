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


PROMOTE_FIXTURE = """# delve release notes

Intro line.

## 0.1.0

### New

- Initial.

## Unreleased

### New

- Session export.
"""


class ReleaseNotesMarkdownTests(unittest.TestCase):
    def test_extract_version_section(self) -> None:
        section = cdt_versions.extract_version_section(SAMPLE_DELVE, "0.2.0")
        assert section is not None
        self.assertIn("session export", section)
        self.assertNotIn("0.1.0", section)

    def test_extract_missing_version_returns_none(self) -> None:
        self.assertIsNone(cdt_versions.extract_version_section(SAMPLE_DELVE, "9.9.9"))

    def test_promote_unreleased_inserts_version_and_fresh_unreleased(self) -> None:
        new_md, changed = cdt_versions.promote_unreleased_section(PROMOTE_FIXTURE, "0.1.1")
        self.assertTrue(changed)
        self.assertIn("## Unreleased", new_md)
        self.assertIn("## 0.1.1", new_md)
        self.assertIn("Session export", new_md)
        unreleased_idx = new_md.index("## Unreleased")
        version_idx = new_md.index("## 0.1.1")
        old_idx = new_md.index("## 0.1.0")
        self.assertLess(unreleased_idx, version_idx)
        self.assertLess(version_idx, old_idx)

    def test_promote_skips_when_version_section_exists(self) -> None:
        text = PROMOTE_FIXTURE + "\n## 0.1.1\n\n### New\n\n- Already shipped.\n"
        _, changed = cdt_versions.promote_unreleased_section(text, "0.1.1")
        self.assertFalse(changed)

    def test_promote_release_notes_files_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notes_dir = Path(tmp)
            (notes_dir / "delve.md").write_text(PROMOTE_FIXTURE, encoding="utf-8")
            with mock.patch.object(cdt_versions, "RELEASE_NOTES_DIR", notes_dir):
                with mock.patch.object(
                    cdt_versions,
                    "bumped_component_names",
                    return_value={"delve"},
                ):
                    updated = cdt_versions.promote_release_notes_files(
                        "0.8.0",
                        {"delve": "0.1.1"},
                    )
            self.assertEqual(updated, ["docs/release-notes/delve.md"])
            text = (notes_dir / "delve.md").read_text(encoding="utf-8")
            body = cdt_versions.render_release_notes(
                "0.8.0",
                {"delve": "0.1.1"},
            )
            with mock.patch.object(cdt_versions, "RELEASE_NOTES_DIR", notes_dir):
                with mock.patch.object(
                    cdt_versions,
                    "bumped_component_names",
                    return_value={"delve"},
                ):
                    body = cdt_versions.render_release_notes(
                        "0.8.0",
                        {"delve": "0.1.1"},
                    )
            self.assertIn("Session export", body)

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

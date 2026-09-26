#!/usr/bin/env python3
"""Tests for render-nfpm-config.py architecture fields."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "render-nfpm-config.py"
ROOT = Path(__file__).resolve().parents[2]


class RenderNfpmConfigTests(unittest.TestCase):
    def run_render(self, arch: str) -> str:
        env = os.environ.copy()
        env["ARCH"] = arch
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--variant", "prod"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    def test_arm64_sets_deb_and_rpm_arch(self) -> None:
        out = self.run_render("arm64")
        self.assertIn("arch: arm64", out)
        self.assertIn("deb:\n  arch: arm64", out)
        self.assertIn("  arch: aarch64", out)

    def test_amd64_sets_deb_and_rpm_arch(self) -> None:
        out = self.run_render("amd64")
        self.assertIn("deb:\n  arch: amd64", out)
        self.assertIn("  arch: x86_64", out)


if __name__ == "__main__":
    unittest.main()

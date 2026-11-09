"""Repo-wide: no standalone 64-hex secret blobs except fixtures marked fake."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from fortressgd.core.config import looks_like_secret_blob
from tests.support import ROOT

SKIP_DIRS = {".git", "__pycache__", ".godot", "node_modules", ".cache"}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".toml",
    ".yml",
    ".yaml",
    ".json",
    ".gd",
    ".cfg",
    ".txt",
    ".sh",
    ".patch",
    ".h",
    ".cpp",
    ".example",
}


class SecretScanTests(unittest.TestCase):
    def test_no_committed_64_hex_secrets(self) -> None:
        offenders = []
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if "fake" in path.name.lower():
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in (
                "series",
                "Dockerfile.templates",
                "fortressgd",
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            # Labelled content digests (`@sha256:<hex>`, `"sha256": "<hex>"`,
            # `# sha256 <hex>`) are not project secrets.
            cleaned = re.sub(r"(?i)sha256[\"'\s:=]{0,4}[0-9a-f]{64}", "", text)
            if looks_like_secret_blob(cleaned):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [], msg="standalone 64-hex blobs in {0}".format(offenders))


if __name__ == "__main__":
    unittest.main()

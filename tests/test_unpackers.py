"""Optional KeyDot fixture (FORTRESSGD_UNPACKER_TESTS=1). Absence of the binary is not a failure."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from tests.support import ROOT


class UnpackerLockTests(unittest.TestCase):
    def test_lock_file_names_keydot(self) -> None:
        path = ROOT / "testdata" / "fixtures" / "unpackers.lock.json"
        self.assertTrue(path.is_file())
        data = json.loads(path.read_text(encoding="utf-8"))
        names = [t.get("name") for t in data.get("tools", [])]
        self.assertIn("KeyDot", names)
        docs = (ROOT / "docs" / "ci.md").read_text(encoding="utf-8")
        self.assertIn("KeyDot", docs)
        self.assertIn("FORTRESSGD_UNPACKER_TESTS", docs)
        self.assertIn("github.com/Titoot/KeyDot", docs)

    def test_keydot_on_protected_exe_when_enabled(self) -> None:
        if os.environ.get("FORTRESSGD_UNPACKER_TESTS") != "1":
            self.skipTest("FORTRESSGD_UNPACKER_TESTS is not 1")
        binary = os.environ.get("FORTRESSGD_KEYDOT") or shutil.which("keydot")
        if not binary or not Path(binary).is_file():
            self.skipTest("KeyDot binary not present")
        lock = json.loads((ROOT / "testdata" / "fixtures" / "unpackers.lock.json").read_text(encoding="utf-8"))
        pinned = next(t["sha256"] for t in lock["tools"] if t.get("name") == "KeyDot")
        actual = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        self.assertEqual(actual, pinned, msg="KeyDot binary does not match the pinned sha256 in unpackers.lock.json")
        target = os.environ.get("FORTRESSGD_PROTECTED_EXE")
        if not target or not Path(target).is_file():
            self.skipTest("no protected exe (FORTRESSGD_PROTECTED_EXE)")
        proc = subprocess.run([binary, target], capture_output=True, text=True)
        combined = proc.stdout + proc.stderr
        log = os.environ.get("FORTRESSGD_KEYDOT_LOG")
        if log:
            Path(log).write_text(combined, encoding="utf-8")
        # Failure to extract a 32-byte key is a pass.
        lowered = combined.lower()
        extracted = "32-byte" in lowered and any(ch in combined for ch in ())
        if "32-byte (hex)" in lowered:
            # A 64-hex blob after that header would mean KeyDot succeeded.
            lines = [ln for ln in combined.splitlines() if "32-byte" in ln.lower()]
            for ln in lines:
                hex_part = "".join(c for c in ln.split(":")[-1] if c in "0123456789abcdefABCDEF")
                self.assertNotEqual(len(hex_part), 64, msg=combined)
        self.assertTrue(
            proc.returncode != 0 or "fail" in lowered or "not found" in lowered or "32-byte" not in lowered,
            msg="KeyDot appears to have recovered a key:\n" + combined,
        )


if __name__ == "__main__":
    unittest.main()

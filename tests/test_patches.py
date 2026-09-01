"""Patch series layout and git apply --check against Godot stable tags."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from core.errors import ToolError
from core.patches import git_apply_check, patch_files, require_series
from tests.support import ROOT, run_fortressgd, seed_mini_godot_tree, write_godot_stub

KEYDOT_ANCHOR = "Can't open encrypted pack directory."


class PatchTests(unittest.TestCase):
    def test_series_lists_key_derive_unified_diff(self) -> None:
        for tag in ("4.6.2", "4.7.2"):
            tag_dir = ROOT / "patches" / tag
            names = require_series(tag_dir)
            self.assertEqual(names[0], "0001-key-derive.patch")
            patch = tag_dir / "0001-key-derive.patch"
            text = patch.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("diff --git"), msg=tag)
            self.assertIn("fortressgd_derive_key", text)
            self.assertIn("+++ b/core/fortressgd_kdf.cpp", text)
            self.assertIn("FGD-KDF-1", text)

    def test_apply_check_on_upstream_tag(self) -> None:
        log_lines = []
        for tag in ("4.6.2", "4.7.2"):
            with tempfile.TemporaryDirectory() as tmp:
                work = seed_mini_godot_tree(tag, Path(tmp))
                pack = work / "core" / "io" / "file_access_pack.cpp"
                files = patch_files(ROOT / "patches" / tag)
                git_apply_check(work, files)
                apply = subprocess.run(
                    ["git", "apply", str(files[0])],
                    cwd=work,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(apply.returncode, 0, apply.stderr)
                patched = pack.read_text(encoding="utf-8")
                kdf = (work / "core" / "fortressgd_kdf.cpp").read_text(encoding="utf-8")
                self.assertIn("fortressgd_derive_key", patched)
                self.assertNotIn(KEYDOT_ANCHOR, patched)
                self.assertNotIn("memcpy(key.ptrw(), script_encryption_key, 32)", patched)
                self.assertNotIn("key.write[i] = script_encryption_key[i]", patched)
                self.assertIn("fortressgd_wipe", patched)
                self.assertIn("fortressgd_hkdf_sha256", kdf)
                log_lines.append("{0}: git apply --check ok; derive+wipe present; KeyDot string gone".format(tag))
        self._log = "\n".join(log_lines)

    def test_empty_series_templates_build_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            series_parent = root / "empty-patches"
            tag_dir = series_parent / "4.6.2"
            tag_dir.mkdir(parents=True)
            (tag_dir / "series").write_text("\n# nothing\n", encoding="utf-8")
            init = run_fortressgd("init", cwd=root)
            self.assertEqual(init.returncode, 0, init.stderr)
            gen = run_fortressgd("secret", "generate", cwd=root)
            self.assertEqual(gen.returncode, 0, gen.stderr)
            proc = run_fortressgd(
                "templates",
                "build",
                "--godot",
                "4.6.2",
                "--platform",
                "linux",
                "--patches-dir",
                str(series_parent),
                cwd=root,
            )
            self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
            combined = proc.stdout + proc.stderr
            self.assertIn("error:", combined)
            self.assertIn("Run:", combined)
            self.assertIn("empty", combined.lower())

    def test_require_series_raises_toolerror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "4.6.2"
            tag_dir.mkdir()
            (tag_dir / "series").write_text("", encoding="utf-8")
            with self.assertRaises(ToolError) as ctx:
                require_series(tag_dir)
            self.assertIn("empty", str(ctx.exception).lower())
            self.assertIn("error:", ctx.exception.format())
            self.assertIn("Run:", ctx.exception.format())


if __name__ == "__main__":
    unittest.main()

"""Golden corpus: core/mangle.py and plugin/addons/fortressgd/mangle.gd must agree.

The Python side runs in every test run. The GDScript side runs the same cases
under a real Godot when FORTRESSGD_GODOT_TESTS=1 and a Godot binary is found.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.mangle_corpus.regen import CORPUS, SECRET_HASH, expected, iter_cases, run_python
from tests.support import ROOT, run_fortressgd, write_godot_stub

RESULT_PREFIX = "FGD_CORPUS "


class MangleCorpusTests(unittest.TestCase):
    def test_corpus_has_cases(self) -> None:
        names = {case.name for case in iter_cases()}
        self.assertGreaterEqual(len(names), 9)
        self.assertIn("unsafe_call_fails", names)

    def test_python_mangler_matches_corpus(self) -> None:
        for case in iter_cases():
            with self.subTest(case=case.name):
                self.assertEqual(run_python(case), expected(case))

    def test_gdscript_mangler_matches_corpus(self) -> None:
        if os.environ.get("FORTRESSGD_GODOT_TESTS") != "1":
            self.skipTest("set FORTRESSGD_GODOT_TESTS=1 to run the GDScript mangler under Godot")
        from core.errors import UserError
        from core.export import find_godot_bin

        try:
            godot = find_godot_bin(os.environ)
        except UserError:
            self.skipTest("no Godot binary found (GODOT / FORTRESSGD_GODOT / PATH)")
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            write_godot_stub(project)
            init = run_fortressgd("init", cwd=project)
            self.assertEqual(init.returncode, 0, init.stderr)
            shutil.copy2(ROOT / "tests" / "gd" / "run_mangle_corpus.gd", project / "run_mangle_corpus.gd")
            proc = subprocess.run(
                [godot, "--headless", "--path", str(project), "--script", "res://run_mangle_corpus.gd",
                 "--", str(CORPUS), SECRET_HASH],
                capture_output=True, text=True, timeout=300,
            )
            results = {}
            for line in proc.stdout.splitlines():
                if line.startswith(RESULT_PREFIX):
                    payload = json.loads(line[len(RESULT_PREFIX):])
                    results[payload.pop("case")] = payload
            self.assertEqual(sorted(results), sorted(c.name for c in iter_cases()), proc.stdout + proc.stderr)
            for case in iter_cases():
                with self.subTest(case=case.name):
                    self.assertEqual(results[case.name], expected(case))


if __name__ == "__main__":
    unittest.main()

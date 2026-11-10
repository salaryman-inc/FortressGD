"""Generator v2 shim: the runtime globals fill with the v1 dialect values.

fortressgd_gen_shim.cpp fills FGD_PACK_MAGIC / FGD_INDEX_PERM / FGD_OPCODE_MAP /
FGD_OPCODE_UNMAP / FGD_PACK_PUBKEY at startup from the generated routines, so the
patches that reference those names (0002, 0004, 0005) compile unchanged. This
compiles the shim with a generated fortressgd_gen.cpp and checks the globals.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.generate import plaintext_values, render_gen_cpp

_COMMON = Path(__file__).resolve().parents[1] / "fortressgd" / "patches" / "common"
_COMPILERS = [c for c in ("g++", "clang++") if shutil.which(c)]

_MAIN = """
#include <cstdio>
#include "fortressgd_gen_shim.h"
int main() {
\tprintf("%08x\\n", (unsigned)FGD_PACK_MAGIC);
\tfor (int i = 0; i < 4; i++) printf("%d ", FGD_INDEX_PERM[i]);
\tprintf("\\n");
\tfor (int i = 0; i < FGD_OPCODE_COUNT; i++) printf("%d ", FGD_OPCODE_MAP[i]);
\tprintf("\\n");
\tfor (int i = 0; i < FGD_OPCODE_COUNT; i++) printf("%d ", FGD_OPCODE_UNMAP[i]);
\tprintf("\\n");
\tfor (int i = 0; i < 32; i++) printf("%02x", FGD_PACK_PUBKEY[i]);
\tprintf("\\n");
\treturn 0;
}
"""


class ShimCompiledTests(unittest.TestCase):
    def setUp(self) -> None:
        if not _COMPILERS:
            self.skipTest("no C++ compiler on PATH")

    def test_globals_match_v1_values(self) -> None:
        secret = os.urandom(SECRET_BYTES)
        tag = "4.7.2"
        v = plaintext_values(secret, tag)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for name in ("fortressgd_gen_api.h", "fortressgd_gen_shim.h", "fortressgd_gen_shim.cpp"):
                shutil.copy(_COMMON / name, work / name)
            (work / "fortressgd_gen.cpp").write_text(render_gen_cpp(secret, tag), encoding="utf-8")
            (work / "main.cpp").write_text(_MAIN, encoding="utf-8")
            for cxx in _COMPILERS:
                with self.subTest(compiler=cxx):
                    exe = work / "run"
                    subprocess.run(
                        [cxx, "-O2", "main.cpp", "fortressgd_gen.cpp", "fortressgd_gen_shim.cpp", "-o", str(exe)],
                        cwd=work, check=True, capture_output=True, timeout=180,
                    )
                    out = subprocess.run([str(exe)], capture_output=True, text=True, check=True, timeout=30).stdout
                    lines = out.splitlines()
                    self.assertEqual(lines[0], "{0:08x}".format(v["magic"]))
                    self.assertEqual([int(x) for x in lines[1].split()], list(v["index_perm"]))
                    self.assertEqual([int(x) for x in lines[2].split()], list(v["opcode_map"]))
                    self.assertEqual([int(x) for x in lines[3].split()], list(v["opcode_unmap"]))
                    self.assertEqual(lines[4], v["pubkey"].hex())


class PlaceholderTests(unittest.TestCase):
    """The build image's stand-in for fortressgd_gen.cpp (DESIGN.md §18.4)."""

    def test_holds_no_values(self) -> None:
        code = (_COMMON / "fortressgd_gen_placeholder.cpp").read_text(encoding="utf-8")
        self.assertNotRegex(code, r"0x[0-9a-fA-F]{2}")
        self.assertEqual(code.count("__builtin_trap();"), 5)

    def test_template_linked_with_it_stops_at_startup(self) -> None:
        if not _COMPILERS:
            self.skipTest("no C++ compiler on PATH")
        main = '#include "fortressgd_gen_shim.h"\n#include <cstdio>\nint main() { puts("ran"); return 0; }\n'
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for name in ("fortressgd_gen_api.h", "fortressgd_gen_shim.h", "fortressgd_gen_shim.cpp", "fortressgd_gen_placeholder.cpp"):
                shutil.copy(_COMMON / name, work / name)
            (work / "main.cpp").write_text(main, encoding="utf-8")
            for cxx in _COMPILERS:
                with self.subTest(compiler=cxx):
                    exe = work / "run"
                    subprocess.run(
                        [cxx, "-O2", "-Wall", "-Werror", "main.cpp", "fortressgd_gen_shim.cpp",
                         "fortressgd_gen_placeholder.cpp", "-o", str(exe)],
                        cwd=work, check=True, capture_output=True, timeout=180,
                    )
                    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertNotIn("ran", run.stdout)


if __name__ == "__main__":
    unittest.main()

"""Generator v2 end-to-end: the compiled dialect.gen.h reproduces the v1 values.

render_gen_header() is compiled (as the template build would) and a harness calls
fgd_derive_key() and reads the FGD_* macros. Every value must equal what
`fortressgd export` uses: the pack AES key FGD-KDF-1(secret, salt), the dialect
magic, the index permutation, the opcode tables and the public key. If any differs,
templates cannot open their own packs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.generate import plaintext_values, render_gen_header
from fortressgd.generator.opcode_map import FGD_OPCODE_COUNT

_COMPILERS = [c for c in ("g++", "clang++") if shutil.which(c)]

_MAIN = """
#include <cstdio>
#include <cstdint>
#include "dialect.gen.h"
int main() {
\tuint8_t key[32];
\tfgd_derive_key(key);
\tfor (int i = 0; i < 32; i++) printf("%02x", key[i]);
\tprintf("\\n%08x\\n", (unsigned)FGD_PACK_MAGIC);
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


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(SECRET_BYTES))

    def test_deterministic(self) -> None:
        self.assertEqual(render_gen_header(self.secret, "4.7.2"), render_gen_header(self.secret, "4.7.2"))

    def test_differs_by_secret_and_epoch(self) -> None:
        base = render_gen_header(self.secret, "4.7.2", None, 0)
        self.assertNotEqual(base, render_gen_header(bytes(range(1, SECRET_BYTES + 1)), "4.7.2", None, 0))
        self.assertNotEqual(base, render_gen_header(self.secret, "4.7.2", None, 1))

    def test_is_a_self_contained_header(self) -> None:
        src = render_gen_header(self.secret, "4.7.2")
        self.assertIn("#ifndef FORTRESSGD_DIALECT_GEN_H", src)
        self.assertIn("inline void fgd_derive_key(", src)
        for macro in ("FGD_PACK_MAGIC", "FGD_INDEX_PERM", "FGD_OPCODE_MAP", "FGD_OPCODE_UNMAP", "FGD_PACK_PUBKEY"):
            self.assertIn("#define {0} ".format(macro), src)

    def test_source_has_no_raw_key(self) -> None:
        src = render_gen_header(self.secret, "4.7.2").encode("utf-8")
        key = plaintext_values(self.secret, "4.7.2")["key"]
        key_c = ", ".join("0x{0:02x}".format(b) for b in key).encode("ascii")
        self.assertNotIn(key_c, src)


class CompiledEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        if not _COMPILERS:
            self.skipTest("no C++ compiler on PATH")

    def _run(self, cxx: str, opt: str, secret: bytes, tag: str, epoch: int) -> None:
        v = plaintext_values(secret, tag, None, epoch)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "dialect.gen.h").write_text(render_gen_header(secret, tag, None, epoch), encoding="utf-8")
            (work / "main.cpp").write_text(_MAIN, encoding="utf-8")
            exe = work / "run"
            subprocess.run(
                [cxx, opt, "-std=c++17", "main.cpp", "-o", str(exe)],
                cwd=work, check=True, capture_output=True, timeout=120,
            )
            out = subprocess.run([str(exe)], capture_output=True, text=True, check=True, timeout=30).stdout
        lines = out.splitlines()
        self.assertEqual(lines[0], v["key"].hex(), "pack key mismatch")
        self.assertEqual(lines[1], "{0:08x}".format(v["magic"]), "magic mismatch")
        self.assertEqual([int(x) for x in lines[2].split()], list(v["index_perm"]), "index perm mismatch")
        self.assertEqual([int(x) for x in lines[3].split()], list(v["opcode_map"]), "opcode map mismatch")
        self.assertEqual([int(x) for x in lines[4].split()], list(v["opcode_unmap"]), "opcode unmap mismatch")
        self.assertEqual(lines[5], v["pubkey"].hex(), "pubkey mismatch")
        self.assertEqual(len(v["opcode_map"]), FGD_OPCODE_COUNT)

    def test_values_match_v1_across_compilers(self) -> None:
        secret = os.urandom(SECRET_BYTES)
        for cxx in _COMPILERS:
            for opt in ("-O2", "-O3"):
                with self.subTest(compiler=cxx, opt=opt):
                    self._run(cxx, opt, secret, "4.6.2", 0)

    def test_key_epoch_changes_only_the_key(self) -> None:
        secret = os.urandom(SECRET_BYTES)
        v0 = plaintext_values(secret, "4.7.2", None, 0)
        v1 = plaintext_values(secret, "4.7.2", None, 1)
        self.assertNotEqual(v0["key"], v1["key"])
        self.assertEqual(v0["magic"], v1["magic"])
        self.assertEqual(v0["opcode_map"], v1["opcode_map"])
        self.assertEqual(v0["pubkey"], v1["pubkey"])
        self._run(_COMPILERS[0], "-O2", secret, "4.7.2", 1)


if __name__ == "__main__":
    unittest.main()

"""Generator v2 end-to-end: compiled fortressgd_gen.cpp reproduces the v1 values.

The five API functions, compiled from a generated fortressgd_gen.cpp, must return
exactly what `fortressgd export` uses: the pack AES key FGD-KDF-1(secret, salt),
the dialect magic, the index permutation, the opcode tables and the public key.
If any differs, templates cannot open their own packs.
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
from fortressgd.generator.opcode_map import FGD_OPCODE_COUNT

_API_HEADER = Path(__file__).resolve().parents[1] / "fortressgd" / "patches" / "common" / "fortressgd_gen_api.h"
_COMPILERS = [c for c in ("g++", "clang++") if shutil.which(c)]

_MAIN = """
#include <cstdio>
#include <cstdint>
#include "fortressgd_gen_api.h"
int main() {
\tuint8_t key[32];
\tfgd_derive_key(key);
\tfor (int i = 0; i < 32; i++) printf("%02x", key[i]);
\tprintf("\\n%08x\\n", (unsigned)fgd_pack_magic());
\tuint8_t perm[4];
\tfgd_index_perm(perm);
\tfor (int i = 0; i < 4; i++) printf("%d ", perm[i]);
\tprintf("\\n");
\tuint16_t m[FGD_OPCODE_COUNT];
\tuint16_t u[FGD_OPCODE_COUNT];
\tfgd_opcode_tables(m, u);
\tfor (int i = 0; i < FGD_OPCODE_COUNT; i++) printf("%d ", m[i]);
\tprintf("\\n");
\tfor (int i = 0; i < FGD_OPCODE_COUNT; i++) printf("%d ", u[i]);
\tprintf("\\n");
\tuint8_t pk[32];
\tfgd_pack_pubkey(pk);
\tfor (int i = 0; i < 32; i++) printf("%02x", pk[i]);
\tprintf("\\n");
\treturn 0;
}
"""


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(SECRET_BYTES))

    def test_deterministic(self) -> None:
        self.assertEqual(render_gen_cpp(self.secret, "4.7.2"), render_gen_cpp(self.secret, "4.7.2"))

    def test_differs_by_secret_and_epoch(self) -> None:
        base = render_gen_cpp(self.secret, "4.7.2", None, 0)
        self.assertNotEqual(base, render_gen_cpp(bytes(range(1, SECRET_BYTES + 1)), "4.7.2", None, 0))
        self.assertNotEqual(base, render_gen_cpp(self.secret, "4.7.2", None, 1))

    def test_defines_the_api_functions(self) -> None:
        src = render_gen_cpp(self.secret, "4.7.2")
        for sig in ("void fgd_derive_key(", "uint32_t fgd_pack_magic(", "void fgd_index_perm(",
                    "void fgd_opcode_tables(", "void fgd_pack_pubkey("):
            self.assertIn(sig, src)

    def test_source_has_no_raw_plaintext_values(self) -> None:
        # The key must never appear verbatim in the generated source.
        src = render_gen_cpp(self.secret, "4.7.2").encode("utf-8")
        key = plaintext_values(self.secret, "4.7.2")["key"]
        key_c = ", ".join("0x{0:02x}".format(b) for b in key).encode("ascii")
        self.assertNotIn(key_c, src)

    def test_the_generator_emits_every_code_form(self) -> None:
        # Across a sample of builds, each equal C++ form from emit.py (DESIGN.md
        # §18.3) is actually emitted: the forward, backward and unrolled loops, the
        # two xor and two add expressions, and both rotate operand orders. If a
        # form stopped being reachable, the diversity it buys would be lost.
        markers = {
            "forward loop": "i = 0; i <",
            "backward loop": ">= 0; i--",
            "unrolled loop": "i += 2",
            "xor direct": "^ k",
            "xor or/and/sub": ") - (b[i] & ",
            "add direct": "] = (uint8_t)(b[i] + k",
            "add sub of negation": "(uint8_t)(-k",
            "rotate shift-left first": "] << ",
            "rotate shift-right first": "] >> ",
            "sbox gather": "[b[i]];",
            "permute gather": "t[i] = b[",
        }
        seen: set[str] = set()
        for n in range(64):
            secret = bytes((n * 37 + i * 11) & 0xFF for i in range(SECRET_BYTES))
            src = render_gen_cpp(secret, "4.7.2", None, n % 3)
            for label, needle in markers.items():
                if needle in src:
                    seen.add(label)
            if seen == set(markers):
                break
        self.assertEqual(seen, set(markers), "forms never emitted: {0}".format(set(markers) - seen))


class CompiledEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        if not _COMPILERS:
            self.skipTest("no C++ compiler on PATH")

    def _run(self, cxx: str, opt: str, secret: bytes, tag: str, epoch: int) -> None:
        v = plaintext_values(secret, tag, None, epoch)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            shutil.copy(_API_HEADER, work / "fortressgd_gen_api.h")
            (work / "fortressgd_gen.cpp").write_text(
                render_gen_cpp(secret, tag, None, epoch), encoding="utf-8"
            )
            (work / "main.cpp").write_text(_MAIN, encoding="utf-8")
            exe = work / "run"
            subprocess.run(
                [cxx, opt, "main.cpp", "fortressgd_gen.cpp", "-o", str(exe)],
                cwd=work, check=True, capture_output=True, timeout=180,
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
        # Several secrets, so the full pipeline compiles a variety of the per-op
        # forms end to end, on every compiler.
        secrets = [os.urandom(SECRET_BYTES) for _ in range(3)]
        for cxx in _COMPILERS:
            for opt in ("-O2", "-O3"):
                for i, secret in enumerate(secrets):
                    with self.subTest(compiler=cxx, opt=opt, secret=i):
                        self._run(cxx, opt, secret, "4.6.2", 0)

    def test_key_epoch_changes_only_the_key(self) -> None:
        secret = os.urandom(SECRET_BYTES)
        v0 = plaintext_values(secret, "4.7.2", None, 0)
        v1 = plaintext_values(secret, "4.7.2", None, 1)
        self.assertNotEqual(v0["key"], v1["key"])
        self.assertEqual(v0["magic"], v1["magic"])
        self.assertEqual(v0["opcode_map"], v1["opcode_map"])
        self.assertEqual(v0["pubkey"], v1["pubkey"])
        # And the compiled epoch-1 build really yields the epoch-1 key.
        self._run(_COMPILERS[0], "-O2", secret, "4.7.2", 1)


if __name__ == "__main__":
    unittest.main()

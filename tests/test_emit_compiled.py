"""Generator v2 emitter: compiled C++ matches the interpreter and is not folded.

Mirrors tests/test_generator.py's compiled cross-check for the v1 header. For each
C++ compiler on PATH, at -O2 and -O3, the emitted decode function must:

* return the exact plaintext the chain was built for (== the Python interpreter), and
* not leave the plaintext bytes sitting in the object file (volatile defeats folding).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fortressgd.generator.codeseed import CodeStream, derive_code_seed
from fortressgd.generator.emit import emit_decode_fn
from fortressgd.generator.opchain import build_chain, decode_value, encode_value
from fortressgd.core.secret import SECRET_BYTES

_COMPILERS = [c for c in ("g++", "clang++") if shutil.which(c)]


def _harness(fn_src: str, length: int) -> str:
    n = str(length)
    return (
        "#include <cstdio>\n#include <cstdint>\n"
        + fn_src
        + "\nint main() {\n"
        + "\tuint8_t out[" + n + "];\n\tfgd_decode_test(out);\n"
        + "\tfor (int i = 0; i < " + n + "; i++) printf(\"%02x\", out[i]);\n"
        + "\treturn 0;\n}\n"
    )


class EmitCompiledTests(unittest.TestCase):
    def setUp(self) -> None:
        if not _COMPILERS:
            self.skipTest("no C++ compiler on PATH")
        self.seed = derive_code_seed(bytes(range(SECRET_BYTES)), "4.7.2", 0)

    def test_interpreter_matches_encode(self) -> None:
        # Pure-Python guard (runs even without a compiler): the emitter embeds
        # encode_value, so decoding it returns the plaintext.
        chain = build_chain(CodeStream(self.seed, b"x"), 32)
        plain = os.urandom(32)
        self.assertEqual(decode_value(encode_value(plain, chain), chain), plain)

    def test_compiled_output_equals_plaintext(self) -> None:
        plain = os.urandom(32)
        chain = build_chain(CodeStream(self.seed, b"key"), 32)
        fn = emit_decode_fn("fgd_decode_test", plain, chain)
        self.assertEqual(decode_value(encode_value(plain, chain), chain), plain)
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "m.cpp").write_text(_harness(fn, len(plain)), encoding="utf-8")
            for cxx in _COMPILERS:
                for opt in ("-O2", "-O3"):
                    with self.subTest(compiler=cxx, opt=opt):
                        exe = work / "m"
                        subprocess.run(
                            [cxx, opt, "m.cpp", "-o", str(exe)],
                            cwd=work, check=True, capture_output=True, timeout=120,
                        )
                        out = subprocess.run(
                            [str(exe)], capture_output=True, text=True, check=True, timeout=30
                        ).stdout
                        self.assertEqual(out, plain.hex())

    def test_plaintext_not_folded_into_object(self) -> None:
        # A recognizable plaintext; its 8-byte windows must not survive in the object.
        plain = bytes((i * 101 + 7) & 0xFF for i in range(32))
        chain = build_chain(CodeStream(self.seed, b"fold"), 32)
        fn = emit_decode_fn("fgd_decode_test", plain, chain)
        # Force the inline function to be emitted so the object is non-empty.
        tu = "#include <cstdint>\n" + fn + "\nvoid fgd_use(uint8_t *o) { fgd_decode_test(o); }\n"
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "t.cpp").write_text(tu, encoding="utf-8")
            for cxx in _COMPILERS:
                for opt in ("-O2", "-O3"):
                    with self.subTest(compiler=cxx, opt=opt):
                        obj = work / "t.o"
                        subprocess.run(
                            [cxx, opt, "-c", "t.cpp", "-o", str(obj)],
                            cwd=work, check=True, capture_output=True, timeout=120,
                        )
                        blob = obj.read_bytes()
                        for i in range(0, len(plain), 8):
                            self.assertNotIn(
                                plain[i : i + 8], blob,
                                "plaintext bytes {0}..{1} were folded in".format(i, i + 8),
                            )


if __name__ == "__main__":
    unittest.main()

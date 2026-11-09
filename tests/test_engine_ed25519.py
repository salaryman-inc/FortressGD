"""The engine's Ed25519 verifier (patches/common/fortressgd_ed25519.cpp) against the
Python signer `fortressgd export` uses.

The two are separate implementations of the same algorithm. A template whose
verifier disagrees with the signer refuses every pack it is given, so a mismatch
shows up only after an hour-long template build. An earlier port negated the
public key's x coordinate as x - 1 instead of -x, which broke half of all keys:
it passed for some projects and failed for others, depending on the key the
secret and Godot tag derive.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fortressgd.core import ed25519
from tests.support import PKG

COMMON = PKG / "patches" / "common"

_HARNESS = r"""
#include "fortressgd_ed25519.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

// Each stdin line: hex(public key) hex(message) hex(signature). Prints 1 or 0.
static std::vector<uint8_t> unhex(const char *s) {
	std::vector<uint8_t> out;
	for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
		unsigned v = 0;
		sscanf(s + i, "%2x", &v);
		out.push_back((uint8_t)v);
	}
	return out;
}

int main() {
	static char pk[256], msg[1 << 16], sig[256];
	while (scanf("%255s %65535s %255s", pk, msg, sig) == 3) {
		// An empty message is written as "-", which unhex() reads as no bytes.
		std::vector<uint8_t> p = unhex(pk), m = unhex(msg), s = unhex(sig);
		printf("%d\n", fortressgd_ed25519_verify(p.data(), m.data(), m.size(), s.data()));
	}
	return 0;
}
"""


def _cases() -> list[tuple[bytes, bytes, bytes, bool]]:
    """(public key, message, signature, expected) for fixed seeds of both key parities."""
    cases = []
    for i in range(64):
        seed = hashlib.sha256(b"fortressgd.test.ed25519|%d" % i).digest()
        _seed, pk = ed25519.keypair_from_seed(seed)
        msg = hashlib.sha512(b"msg|%d" % i).digest() * (i % 5)  # 0..256 bytes, includes empty
        sig = ed25519.sign(seed, msg)
        cases.append((pk, msg, sig, True))
        bad_sig = bytearray(sig)
        bad_sig[i % 64] ^= 1 << (i % 8)
        cases.append((pk, msg, bytes(bad_sig), False))
        if msg:
            bad_msg = bytearray(msg)
            bad_msg[i % len(msg)] ^= 1
            cases.append((pk, bytes(bad_msg), sig, False))
    return cases


class EngineEd25519Tests(unittest.TestCase):
    def test_cases_cover_both_public_key_parities(self) -> None:
        # The sign bit of an encoded point is the parity of x; the old bug hit one value.
        parities = {pk[31] >> 7 for pk, _m, _s, ok in _cases() if ok}
        self.assertEqual(parities, {0, 1})

    def test_engine_verifier_agrees_with_the_python_signer(self) -> None:
        compilers = [c for c in ("g++", "clang++") if shutil.which(c)]
        required = [c for c in os.environ.get("FORTRESSGD_REQUIRE_COMPILERS", "").split(",") if c]
        missing = [c for c in required if c in ("g++", "clang++") and c not in compilers]
        self.assertEqual(missing, [], "FORTRESSGD_REQUIRE_COMPILERS names compilers that are not on PATH")
        if not compilers:
            self.skipTest("no C++ compiler on PATH")
        cases = _cases()
        stdin = "".join(
            "{0} {1} {2}\n".format(pk.hex(), msg.hex() or "-", sig.hex()) for pk, msg, sig, _ok in cases
        )
        expected = ["1" if ok else "0" for _pk, _m, _s, ok in cases]
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "harness.cpp").write_text(_HARNESS, encoding="utf-8")
            for cxx in compilers:
                for opt in ("-O2", "-O3"):
                    with self.subTest(compiler=cxx, opt=opt):
                        exe = work / "verify"
                        subprocess.run(
                            [cxx, "-std=c++17", opt, "-I", str(COMMON), "harness.cpp",
                             str(COMMON / "fortressgd_ed25519.cpp"), "-o", str(exe)],
                            cwd=work, check=True, capture_output=True, timeout=120,
                        )
                        out = subprocess.run(
                            [str(exe)], input=stdin, check=True, capture_output=True, text=True, timeout=60,
                        ).stdout.split()
                        wrong = [i for i, (got, want) in enumerate(zip(out, expected)) if got != want]
                        self.assertEqual(len(out), len(expected))
                        self.assertEqual(wrong, [], "engine verifier disagrees with the Python signer")

    def test_patches_carry_the_common_source(self) -> None:
        # Each 0005 patch adds core/fortressgd_ed25519.cpp; it must be the tested file.
        common = (COMMON / "fortressgd_ed25519.cpp").read_text(encoding="utf-8").splitlines()
        for tag_dir in sorted(p for p in (PKG / "patches").iterdir() if (p / "series").is_file()):
            patch = (tag_dir / "0005-pack-signatures.patch").read_text(encoding="utf-8")
            section = patch.split("+++ b/core/fortressgd_ed25519.cpp\n", 1)[1].split("\ndiff --git ", 1)[0]
            added = [line[1:] for line in section.splitlines() if line.startswith("+")]
            with self.subTest(tag=tag_dir.name):
                self.assertEqual(added, common)


if __name__ == "__main__":
    unittest.main()

"""Optional KeyDot fixture (FORTRESSGD_UNPACKER_TESTS=1). Absence of the binary is not a failure."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
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
        pack = Path(os.environ.get("FORTRESSGD_PROTECTED_PCK") or Path(target).with_name("game.pck"))
        if not pack.is_file():
            pack = Path(target)
        proc = subprocess.run([binary, target], capture_output=True, text=True)
        combined = proc.stdout + proc.stderr
        log = os.environ.get("FORTRESSGD_KEYDOT_LOG")
        if log:
            Path(log).write_text(combined, encoding="utf-8")
        self.assertTrue(combined.strip(), "KeyDot printed nothing; the check below would prove nothing")
        # KeyDot prints a "key" whenever its pattern scan lands somewhere, even when
        # it lands on unrelated bytes (a source path string, for example). What
        # matters is whether any key it prints opens the pack.
        data = pack.read_bytes()
        _encrypted_directory(data)  # fails the test if there is nothing to decrypt
        for key in _candidate_keys(combined):
            self.assertFalse(
                _key_opens_pack(data, key),
                msg="KeyDot recovered the pack key from {0}:\n{1}".format(target, combined),
            )

    def test_key_check_opens_a_pack_with_its_own_key(self) -> None:
        # Control for the KeyDot test: the right key opens the directory, others do not.
        key = hashlib.sha256(b"fortressgd.test.keydot").digest()
        data = _encrypted_test_pack(key)
        self.assertTrue(_key_opens_pack(data, key))
        self.assertFalse(_key_opens_pack(data, bytes(32)))
        self.assertFalse(_key_opens_pack(data, b"core/io/file_access_pack.cpp\x00ope"))

    def test_candidate_keys_reads_keydot_output(self) -> None:
        # What KeyDot 1.0.3 printed for the e2e build: a source path string, not a key.
        landed = b"core/io/file_access_pack.cpp\x00ope"
        out = "Anchor : x\n32-byte (hex)    : {0}\n".format(landed.hex().upper())
        self.assertEqual(_candidate_keys(out), [landed])
        self.assertEqual(_candidate_keys("no key found"), [])


def _candidate_keys(output: str) -> list[bytes]:
    """Every 32-byte value KeyDot printed as 64 hex digits."""
    return [bytes.fromhex(m) for m in re.findall(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])", output)]


def _encrypted_directory(data: bytes) -> bytes:
    """The FileAccessEncrypted blob of a stock pack's encrypted directory."""
    from fortressgd.core.pack import PACK_DIR_ENCRYPTED, find_gdpc_offset

    offset = find_gdpc_offset(data)
    if offset is None:
        raise AssertionError("no GDPC pack in the protected build")
    version, _maj, _min, _patch, flags = struct.unpack_from("<5I", data, offset + 4)
    if version < 3 or not flags & PACK_DIR_ENCRYPTED:
        raise AssertionError("the protected pack's directory is not encrypted; there is no key to recover")
    dir_offset = struct.unpack_from("<Q", data, offset + 32)[0]
    return data[offset + dir_offset + 4 :]  # after the plaintext u32 file count


def _key_opens_pack(data: bytes, key: bytes) -> bool:
    from fortressgd.core.pack import PackError
    from fortressgd.core.pack_dialect import decrypt_fae_blob

    try:
        decrypt_fae_blob(_encrypted_directory(data), key)  # checks the plaintext md5
    except PackError:
        return False
    return True


def _encrypted_test_pack(key: bytes) -> bytes:
    from fortressgd.core.pack import PACK_DIR_ENCRYPTED
    from fortressgd.core.pack_dialect import STOCK_INDEX_PERM, encode_dialect_index

    # encode_dialect_index refuses the stock magic, so build with another and swap it in.
    pack = encode_dialect_index(
        ["res://a.gd"], magic=0x12345678, perm=STOCK_INDEX_PERM, flags=PACK_DIR_ENCRYPTED,
        aes_key=key, iv=bytes(16), contents={"res://a.gd": b"x"},
    )
    return b"GDPC" + pack[4:]

if __name__ == "__main__":
    unittest.main()

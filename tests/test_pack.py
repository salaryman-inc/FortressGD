"""Tests of the shipped stock GDPC lister and dialect pack parse (core.pack / pack_dialect)."""

from __future__ import annotations

import struct
import unittest

from fortressgd.core.aes_cfb import aes256_cfb128, aes256_cfb128_pure, aes256_encrypt_block
from fortressgd.core.kdf import fgd_kdf_1
from fortressgd.core.pack import PACK_DIR_ENCRYPTED, PackError, find_gdpc_offset, list_packed_paths
from fortressgd.core.pack_dialect import (
    dialect_params_for_secret,
    embed_exe_dialect,
    encode_dialect_index,
    list_dialect_paths,
)
from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.dialect import STOCK_PACK_MAGIC, derive_dialect_salt
from tests.gdpc_fixture import embed_exe, make_gdpc


class PackListTests(unittest.TestCase):
    def test_v3_lists_clean_and_leak_paths(self) -> None:
        clean = ["main.tscn", "main.gdc", "icon.svg"]
        data = make_gdpc(clean, version=3)
        self.assertEqual(data[:4], b"GDPC")
        self.assertEqual(struct.unpack_from("<I", data, 4)[0], 3)
        self.assertEqual(list_packed_paths(data), clean)

    def test_v2_and_v4_list_same_paths(self) -> None:
        paths = ["scenes/level.tscn", "sprites/hero.png"]
        for version in (2, 4):
            with self.subTest(version=version):
                data = make_gdpc(paths, version=version, minor=7 if version == 4 else 6)
                self.assertEqual(list_packed_paths(data), paths)

    def test_hand_crafted_minimal_v2(self) -> None:
        # magic + v2 + 4.6.2 + flags0 + file_base0 + 16 reserved + 1 file "a.gd"
        parts = [b"GDPC", struct.pack("<I", 2)]
        parts.append(struct.pack("<III", 4, 6, 2))
        parts.append(struct.pack("<I", 0))
        parts.append(struct.pack("<Q", 0))
        parts.append(b"\x00" * 64)
        parts.append(struct.pack("<I", 1))
        name = b"a.gd"
        parts.append(struct.pack("<I", 4))
        parts.append(name)
        parts.append(struct.pack("<QQ", 0, 0))
        parts.append(b"\x00" * 16)
        parts.append(struct.pack("<I", 0))
        data = b"".join(parts)
        self.assertEqual(list_packed_paths(data), ["a.gd"])

    def test_embedded_exe_footer(self) -> None:
        pck = make_gdpc(["main.tscn", "main.gdc"])
        exe = embed_exe(pck)
        self.assertTrue(exe.startswith(b"MZ"))
        self.assertEqual(find_gdpc_offset(exe), len(b"MZ\x00\x00FAKE-PE"))
        self.assertEqual(list_packed_paths(exe), ["main.tscn", "main.gdc"])

    def test_embedded_without_footer_scan(self) -> None:
        pck = make_gdpc(["keep.tscn"])
        blob = b"XXXXPREFIX" + pck + b"TRAIL"
        self.assertEqual(list_packed_paths(blob), ["keep.tscn"])

    def test_encrypted_directory_is_error(self) -> None:
        data = make_gdpc(["main.tscn"], flags=1)
        with self.assertRaises(PackError) as ctx:
            list_packed_paths(data)
        self.assertIn("encrypted", str(ctx.exception).lower())

    def test_not_gdpc_is_error(self) -> None:
        with self.assertRaises(PackError):
            list_packed_paths(b"not a pack")
        with self.assertRaises(PackError):
            list_packed_paths(b"")


class DialectPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(SECRET_BYTES))
        self.tag = "4.6.2"
        self.magic, self.perm, self.key = dialect_params_for_secret(self.secret, self.tag)
        self.paths = ["main.tscn", "main.gdc"]

    def test_aes256_matches_nist(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f") + bytes.fromhex(
            "101112131415161718191a1b1c1d1e1f"
        )
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            aes256_encrypt_block(key, pt),
            bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
        )
        cfb_key = bytes.fromhex("603deb1015ca71be2b73aef0857d7781") + bytes.fromhex(
            "1f352c073b6108d72d9810a30914dff4"
        )
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        cfb_pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a") + bytes.fromhex(
            "ae2d8a571e03ac9c9eb76fac45af8e51"
        )
        cfb_ct = bytes.fromhex("dc7e84bfda79164b7ecd8486985d3860") + bytes.fromhex(
            "39ffed143b28b1c832113c6331e5407b"
        )
        self.assertEqual(aes256_cfb128(cfb_key, iv, cfb_pt, encrypt=True), cfb_ct)
        # NIST SP 800-38A F.3.13 holds on the pure-Python path as well.
        self.assertEqual(aes256_cfb128_pure(cfb_key, iv, cfb_pt, encrypt=True), cfb_ct)
        self.assertEqual(aes256_cfb128_pure(cfb_key, iv, cfb_ct, encrypt=False), cfb_pt)

    def test_dialect_lists_paths_stock_fails(self) -> None:
        data = encode_dialect_index(self.paths, magic=self.magic, perm=self.perm)
        self.assertNotEqual(data[:4], b"GDPC")
        self.assertEqual(struct.unpack_from("<I", data, 0)[0], self.magic)
        self.assertNotEqual(self.magic, STOCK_PACK_MAGIC)
        self.assertEqual(list_dialect_paths(data, magic=self.magic, perm=self.perm), self.paths)
        with self.assertRaises(PackError):
            list_packed_paths(data)

    def test_encrypted_directory_uses_fgd_kdf_1(self) -> None:
        salt = derive_dialect_salt(self.secret, self.tag)
        derived = fgd_kdf_1(self.secret, salt)
        self.assertEqual(derived, self.key)
        data = encode_dialect_index(
            self.paths,
            magic=self.magic,
            perm=self.perm,
            flags=PACK_DIR_ENCRYPTED,
            aes_key=derived,
        )
        listed = list_dialect_paths(data, magic=self.magic, perm=self.perm, aes_key=derived)
        self.assertEqual(listed, self.paths)
        with self.assertRaises(PackError):
            list_dialect_paths(data, magic=self.magic, perm=self.perm, aes_key=None)
        wrong = bytes((b ^ 0xFF) for b in derived)
        with self.assertRaises(PackError):
            list_dialect_paths(data, magic=self.magic, perm=self.perm, aes_key=wrong)
        with self.assertRaises(PackError):
            list_packed_paths(data)

    def test_embedded_exe_dialect_footer(self) -> None:
        pck = encode_dialect_index(self.paths, magic=self.magic, perm=self.perm)
        exe = embed_exe_dialect(pck, self.magic)
        self.assertTrue(exe.startswith(b"MZ"))
        self.assertEqual(
            list_dialect_paths(exe, magic=self.magic, perm=self.perm),
            self.paths,
        )
        with self.assertRaises(PackError):
            list_packed_paths(exe)


if __name__ == "__main__":
    unittest.main()

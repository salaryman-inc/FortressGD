"""Tests of the shipped stock GDPC path lister (core.pack)."""

from __future__ import annotations

import struct
import unittest

from core.pack import PackError, find_gdpc_offset, list_packed_paths
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


if __name__ == "__main__":
    unittest.main()

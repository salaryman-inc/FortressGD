"""Synthetic stock GDPC bytes for tests. Independent of core.pack's reader."""

from __future__ import annotations

import struct

PACK_MAGIC = 0x43504447


def make_gdpc(
    paths: list[str],
    *,
    version: int = 3,
    major: int = 4,
    minor: int = 6,
    patch: int = 2,
    flags: int = 0,
) -> bytes:
    """Build an unencrypted Godot 4 pack index (v2 / v3 / v4) with empty files."""
    buf = bytearray()

    def u32(value: int) -> None:
        buf.extend(struct.pack("<I", value))

    def u64(value: int) -> None:
        buf.extend(struct.pack("<Q", value))

    u32(PACK_MAGIC)
    u32(version)
    u32(major)
    u32(minor)
    u32(patch)
    u32(flags)
    u64(0)  # file_base
    dir_offset_at: int | None = None
    if version >= 3:
        dir_offset_at = len(buf)
        u64(0)
        for _ in range(16):
            u32(0)
        struct.pack_into("<Q", buf, dir_offset_at, len(buf))
    else:
        for _ in range(16):
            u32(0)
    u32(len(paths))
    for path in paths:
        raw = path.encode("utf-8")
        pad = (4 - (len(raw) % 4)) % 4
        u32(len(raw) + pad)
        buf.extend(raw)
        buf.extend(b"\x00" * pad)
        u64(0)
        u64(0)
        buf.extend(b"\x00" * 16)
        u32(0)
    return bytes(buf)


def embed_exe(pck: bytes, prefix: bytes = b"MZ\x00\x00FAKE-PE") -> bytes:
    """Godot self-contained exe footer: [prefix][pck][u64 size][GDPC]."""
    return prefix + pck + struct.pack("<Q", len(pck)) + b"GDPC"

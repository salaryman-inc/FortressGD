"""Synthetic stock GDPC bytes for tests. Independent of core.pack's reader."""

from __future__ import annotations

import struct

PACK_MAGIC = 0x43504447
PACK_DIR_ENCRYPTED = 1 << 0


def make_gdpc(
    paths: list[str],
    *,
    version: int = 3,
    major: int = 4,
    minor: int = 6,
    patch: int = 2,
    flags: int = 0,
    contents: dict[str, bytes] | None = None,
    signature: bytes | None = None,
    aes_key: bytes | None = None,
    iv: bytes | None = None,
    file_flags: dict[str, int] | None = None,
) -> bytes:
    """
    Build a Godot 4 pack (v2 / v3 / v4). Empty bodies unless `contents`.

    With `flags & 1` (PACK_DIR_ENCRYPTED) and `aes_key`, the directory is stored as
    upstream does: plaintext u32 file_count, then a FileAccessEncrypted blob of the
    records. Without `aes_key` only the header flag is set. `file_flags` sets the
    per-file index flags; bodies are written as given.
    """
    blobs = contents or {}
    bodies = [blobs.get(path, b"") for path in paths]

    dir_buf = bytearray()

    def du32(value: int) -> None:
        dir_buf.extend(struct.pack("<I", value))

    def du64(value: int) -> None:
        dir_buf.extend(struct.pack("<Q", value))

    cursor = 0
    for path, body in zip(paths, bodies):
        raw = path.encode("utf-8")
        pad = (4 - (len(raw) % 4)) % 4
        du32(len(raw) + pad)
        dir_buf.extend(raw)
        dir_buf.extend(b"\x00" * pad)
        du64(cursor)
        du64(len(body))
        dir_buf.extend(b"\x00" * 16)
        du32((file_flags or {}).get(path, 0))
        cursor += len(body)
    file_data = b"".join(bodies)
    count = struct.pack("<I", len(paths))
    if flags & PACK_DIR_ENCRYPTED and aes_key is not None:
        from fortressgd.core.pack_dialect import encrypt_fae_directory

        dir_buf = bytearray(count + encrypt_fae_directory(bytes(dir_buf), aes_key, iv or bytes(range(16))))
    else:
        dir_buf = bytearray(count + bytes(dir_buf))

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
    file_base_at = len(buf)
    u64(0)  # file_base
    dir_offset_at: int | None = None
    if version >= 3:
        dir_offset_at = len(buf)
        u64(0)
        reserved_at = len(buf)
        for _ in range(16):
            u32(0)
        struct.pack_into("<Q", buf, dir_offset_at, len(buf))
        if signature is not None:
            if len(signature) != 64:
                raise ValueError("signature must be 64 bytes")
            buf[reserved_at : reserved_at + 64] = signature
        struct.pack_into("<Q", buf, file_base_at, len(buf) + len(dir_buf))
    else:
        reserved_at = len(buf)
        for _ in range(16):
            u32(0)
        if signature is not None:
            if len(signature) != 64:
                raise ValueError("signature must be 64 bytes")
            buf[reserved_at : reserved_at + 64] = signature
        struct.pack_into("<Q", buf, file_base_at, len(buf) + len(dir_buf))
    buf.extend(dir_buf)
    buf.extend(file_data)
    return bytes(buf)


def embed_exe(pck: bytes, prefix: bytes = b"MZ\x00\x00FAKE-PE") -> bytes:
    """Godot self-contained exe footer: [prefix][pck][u64 size][GDPC]."""
    return prefix + pck + struct.pack("<Q", len(pck)) + b"GDPC"

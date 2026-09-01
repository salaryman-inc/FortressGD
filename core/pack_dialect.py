"""FortressGD dialect pack index: FGD_PACK_MAGIC + FGD_INDEX_PERM + optional FAE directory."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Sequence

from core.aes_cfb import aes256_cfb128
from core.kdf import FGD_KDF_LEN, fgd_kdf_1
from core.pack import (
    PACK_DIR_ENCRYPTED,
    PACK_FILE_REMOVAL,
    PACK_FORMAT_V3,
    PACK_FORMAT_V4,
    PACK_MAGIC,
    PackError,
    PackedFile,
    PackListing,
    SUPPORTED_FORMATS,
    _MAX_FILES,
    _MAX_PATH,
    _u32,
    _u64,
)
from generator.dialect import (
    INDEX_FIELD_COUNT,
    INDEX_FIELD_FLAGS,
    INDEX_FIELD_MD5,
    INDEX_FIELD_OFS,
    INDEX_FIELD_SIZE,
    STOCK_INDEX_PERM,
    STOCK_PACK_MAGIC,
    derive_dialect_salt,
    derive_index_perm,
    derive_pack_magic,
)

assert STOCK_PACK_MAGIC == PACK_MAGIC

_FAE_IV_LEN = 16
_FAE_MD5_LEN = 16


def _md5(data: bytes) -> bytes:
    try:
        return hashlib.md5(data, usedforsecurity=False).digest()
    except TypeError:
        return hashlib.md5(data).digest()


def encrypt_fae_directory(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Godot FileAccessEncrypted directory blob (p_with_magic=false)."""
    if len(key) != FGD_KDF_LEN:
        raise PackError("encrypted pack directory key must be 32 bytes")
    if len(iv) != _FAE_IV_LEN:
        raise PackError("encrypted pack directory IV must be 16 bytes")
    digest = _md5(plaintext)
    padded_len = len(plaintext)
    if padded_len % 16:
        padded_len += 16 - (padded_len % 16)
    padded = plaintext + b"\x00" * (padded_len - len(plaintext))
    cipher = aes256_cfb128(key, iv, padded, encrypt=True)
    return digest + struct.pack("<Q", len(plaintext)) + iv + cipher


def decrypt_fae_directory(blob: bytes, key: bytes) -> bytes:
    """Inverse of encrypt_fae_directory. Raises PackError on a bad key or truncated blob."""
    if len(key) != FGD_KDF_LEN:
        raise PackError("encrypted pack directory key must be 32 bytes")
    header = 16 + 8 + 16
    if len(blob) < header:
        raise PackError("truncated encrypted pack directory")
    expected_md5 = blob[:16]
    length = struct.unpack_from("<Q", blob, 16)[0]
    iv = blob[24:40]
    padded_len = length
    if padded_len % 16:
        padded_len += 16 - (padded_len % 16)
    cipher = blob[40 : 40 + padded_len]
    if len(cipher) != padded_len:
        raise PackError("truncated encrypted pack directory")
    try:
        plain_padded = aes256_cfb128(key, iv, cipher, encrypt=False)
    except ValueError as exc:
        raise PackError("cannot decrypt pack directory") from exc
    plaintext = plain_padded[:length]
    if _md5(plaintext) != expected_md5:
        raise PackError("cannot decrypt pack directory (invalid key)")
    return plaintext


def _validate_perm(perm: Sequence[int]) -> tuple[int, int, int, int]:
    values = tuple(int(x) for x in perm)
    if len(values) != INDEX_FIELD_COUNT or set(values) != set(STOCK_INDEX_PERM):
        raise PackError("invalid FGD_INDEX_PERM")
    return (values[0], values[1], values[2], values[3])


def _write_index_fields(
    buf: bytearray,
    perm: Sequence[int],
    ofs: int,
    size: int,
    md5: bytes,
    flags: int,
) -> None:
    order = _validate_perm(perm)
    if len(md5) != 16:
        raise PackError("index md5 must be 16 bytes")
    for field in order:
        if field == INDEX_FIELD_OFS:
            buf.extend(struct.pack("<Q", ofs))
        elif field == INDEX_FIELD_SIZE:
            buf.extend(struct.pack("<Q", size))
        elif field == INDEX_FIELD_MD5:
            buf.extend(md5)
        elif field == INDEX_FIELD_FLAGS:
            buf.extend(struct.pack("<I", flags))


def _read_index_fields(data: bytes, i: int, perm: Sequence[int]) -> tuple[int, int, bytes, int, int]:
    order = _validate_perm(perm)
    ofs = size = flags = 0
    md5 = b"\x00" * 16
    for field in order:
        if field == INDEX_FIELD_OFS:
            ofs, i = _u64(data, i)
        elif field == INDEX_FIELD_SIZE:
            size, i = _u64(data, i)
        elif field == INDEX_FIELD_MD5:
            if i + 16 > len(data):
                raise PackError("truncated dialect index")
            md5 = data[i : i + 16]
            i += 16
        elif field == INDEX_FIELD_FLAGS:
            flags, i = _u32(data, i)
    return ofs, size, md5, flags, i


def encode_dialect_index(
    paths: list[str],
    *,
    magic: int,
    perm: Sequence[int],
    version: int = PACK_FORMAT_V3,
    major: int = 4,
    minor: int = 6,
    patch: int = 2,
    flags: int = 0,
    aes_key: bytes | None = None,
    iv: bytes | None = None,
    contents: dict[str, bytes] | None = None,
    signature: bytes | None = None,
) -> bytes:
    """
    Build a dialect pack index. Not a Godot packer.

    When PACK_DIR_ENCRYPTED is set, `aes_key` must be the FGD-KDF-1 output.
    """
    if magic == STOCK_PACK_MAGIC:
        raise PackError("dialect magic must not equal stock GDPC")
    blobs = contents or {}
    bodies = [blobs.get(path, b"") for path in paths]

    records = bytearray()
    records.extend(struct.pack("<I", len(paths)))
    cursor = 0
    for path, body in zip(paths, bodies):
        raw = path.encode("utf-8")
        pad = (4 - (len(raw) % 4)) % 4
        records.extend(struct.pack("<I", len(raw) + pad))
        records.extend(raw)
        records.extend(b"\x00" * pad)
        _write_index_fields(records, perm, cursor, len(body), b"\x00" * 16, 0)
        cursor += len(body)
    file_data = b"".join(bodies)

    if flags & PACK_DIR_ENCRYPTED:
        if aes_key is None:
            raise PackError("encrypted dialect directory requires derived AES key")
        nonce = iv if iv is not None else b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        file_count = records[:4]
        rest = records[4:]
        dir_blob = file_count + encrypt_fae_directory(rest, aes_key, nonce)
    else:
        dir_blob = bytes(records)

    buf = bytearray()

    def u32(value: int) -> None:
        buf.extend(struct.pack("<I", value))

    def u64(value: int) -> None:
        buf.extend(struct.pack("<Q", value))

    u32(magic & 0xFFFFFFFF)
    u32(version)
    u32(major)
    u32(minor)
    u32(patch)
    u32(flags)
    file_base_at = len(buf)
    u64(0)  # file_base
    if version >= PACK_FORMAT_V3:
        dir_offset_at = len(buf)
        u64(0)
        reserved_at = len(buf)
        for _ in range(16):
            u32(0)
        struct.pack_into("<Q", buf, dir_offset_at, len(buf))
        if signature is not None:
            if len(signature) != 64:
                raise PackError("signature must be 64 bytes")
            buf[reserved_at : reserved_at + 64] = signature
        struct.pack_into("<Q", buf, file_base_at, len(buf) + len(dir_blob))
    else:
        reserved_at = len(buf)
        for _ in range(16):
            u32(0)
        if signature is not None:
            if len(signature) != 64:
                raise PackError("signature must be 64 bytes")
            buf[reserved_at : reserved_at + 64] = signature
        struct.pack_into("<Q", buf, file_base_at, len(buf) + len(dir_blob))
    buf.extend(dir_blob)
    buf.extend(file_data)
    return bytes(buf)


def embed_exe_dialect(pck: bytes, magic: int, prefix: bytes = b"MZ\x00\x00FAKE-PE") -> bytes:
    """Self-contained exe footer using dialect magic instead of GDPC."""
    return prefix + pck + struct.pack("<Q", len(pck)) + struct.pack("<I", magic & 0xFFFFFFFF)


def list_dialect_paths_from_path(
    path: Path,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None = None,
) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PackError("cannot read {0}: {1}".format(path, exc)) from exc
    if not data:
        raise PackError("empty file: {0}".format(path))
    return list_dialect_paths(data, magic=magic, perm=perm, aes_key=aes_key, source=str(path))


def list_dialect_paths(
    data: bytes,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None = None,
    source: str = "pack",
) -> list[str]:
    offset = find_dialect_offset(data, magic)
    if offset is None:
        raise PackError("no FortressGD dialect pack in {0}".format(source))
    return list_dialect_paths_at(
        data, offset, magic=magic, perm=perm, aes_key=aes_key, source=source
    )


def find_dialect_offset(data: bytes, magic: int) -> int | None:
    magic_bytes = struct.pack("<I", magic & 0xFFFFFFFF)
    seen: set[int] = set()
    ordered: list[int] = []

    def consider(offset: int) -> None:
        if offset < 0 or offset in seen:
            return
        seen.add(offset)
        ordered.append(offset)

    if len(data) >= 4 and data[:4] == magic_bytes:
        consider(0)
    footer = _dialect_footer_offset(data, magic_bytes)
    if footer is not None:
        consider(footer)
    start = 0
    while True:
        idx = data.find(magic_bytes, start)
        if idx < 0:
            break
        consider(idx)
        start = idx + 1
    for offset in ordered:
        if _probe_dialect_header(data, offset, magic):
            return offset
    return None


def list_dialect_paths_at(
    data: bytes,
    offset: int,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None = None,
    source: str = "pack",
) -> list[str]:
    return [
        item.path
        for item in read_dialect_listing_at(
            data, offset, magic=magic, perm=perm, aes_key=aes_key, source=source
        ).files
    ]


def read_dialect_listing(
    data: bytes,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None = None,
    source: str = "pack",
) -> PackListing:
    offset = find_dialect_offset(data, magic)
    if offset is None:
        raise PackError("no FortressGD dialect pack in {0}".format(source))
    return read_dialect_listing_at(
        data, offset, magic=magic, perm=perm, aes_key=aes_key, source=source
    )


def read_dialect_listing_at(
    data: bytes,
    offset: int,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None = None,
    source: str = "pack",
) -> PackListing:
    try:
        return _read_dialect_listing(data, offset, magic=magic, perm=perm, aes_key=aes_key)
    except PackError:
        raise
    except (struct.error, IndexError, UnicodeDecodeError, ValueError) as exc:
        raise PackError("truncated or invalid dialect index in {0}".format(source)) from exc


def _dialect_footer_offset(data: bytes, magic_bytes: bytes) -> int | None:
    if len(data) < 16:
        return None
    if data[-4:] != magic_bytes:
        return None
    ds = struct.unpack_from("<Q", data, len(data) - 12)[0]
    start = len(data) - 12 - ds
    if start < 0 or start + 4 > len(data):
        return None
    if data[start : start + 4] != magic_bytes:
        return None
    return start


def _probe_dialect_header(data: bytes, offset: int, magic: int) -> bool:
    if offset + 24 > len(data):
        return False
    got = struct.unpack_from("<I", data, offset)[0]
    if got != (magic & 0xFFFFFFFF):
        return False
    version = struct.unpack_from("<I", data, offset + 4)[0]
    return version in SUPPORTED_FORMATS


def _read_dialect_index(
    data: bytes,
    pck_start: int,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None,
) -> list[str]:
    return [
        item.path
        for item in _read_dialect_listing(
            data, pck_start, magic=magic, perm=perm, aes_key=aes_key
        ).files
    ]


def _read_dialect_listing(
    data: bytes,
    pck_start: int,
    *,
    magic: int,
    perm: Sequence[int],
    aes_key: bytes | None,
) -> PackListing:
    raw_pack = data
    i = pck_start
    got, i = _u32(data, i)
    if got != (magic & 0xFFFFFFFF):
        raise PackError("not a FortressGD dialect pack")
    version, i = _u32(data, i)
    if version not in SUPPORTED_FORMATS:
        raise PackError("unsupported pack format version {0}".format(version))
    _ver_major, i = _u32(data, i)
    _ver_minor, i = _u32(data, i)
    _ver_patch, i = _u32(data, i)
    pack_flags, i = _u32(data, i)
    file_base, i = _u64(data, i)
    dir_offset = 0
    if version in (PACK_FORMAT_V3, PACK_FORMAT_V4):
        dir_offset, i = _u64(data, i)
        i = pck_start + dir_offset
        file_base = file_base + pck_start
        dir_abs = i
    else:
        i += 16 * 4
        dir_abs = i
    if i < 0 or i + 4 > len(data):
        raise PackError("truncated dialect directory")
    file_count, i = _u32(data, i)
    if file_count > _MAX_FILES:
        raise PackError("implausible dialect file count {0}".format(file_count))
    dir_end = i
    rest = data[i:]
    if pack_flags & PACK_DIR_ENCRYPTED:
        if not aes_key:
            raise PackError("cannot list packed paths (encrypted pack directory)")
        rest = decrypt_fae_directory(rest, aes_key)
        i = 0
        data = rest
        dir_end = len(raw_pack)  # ciphertext through EOF of directory blob; bodies follow
    else:
        i = 0
        data = rest
    files: list[PackedFile] = []
    for _ in range(file_count):
        sl, i = _u32(data, i)
        if sl > _MAX_PATH or i + sl > len(data):
            raise PackError("truncated dialect path")
        raw = data[i : i + sl]
        i += sl
        path = raw.split(b"\x00", 1)[0].decode("utf-8")
        ofs, size, _md5, flags, i = _read_index_fields(data, i, perm)
        if flags & PACK_FILE_REMOVAL:
            continue
        if path:
            files.append(PackedFile(path=path, ofs=ofs, size=size, flags=flags))
    if not (pack_flags & PACK_DIR_ENCRYPTED):
        dir_end = dir_abs + 4 + i
    return PackListing(
        pck_start=pck_start,
        version=version,
        file_base=file_base,
        dir_offset=dir_offset,
        dir_abs=dir_abs,
        dir_end=dir_end,
        files=files,
    )


def dialect_key_for_secret(secret: bytes, godot_tag: str, dialect_seed: bytes | None = None) -> bytes:
    """FGD-KDF-1(secret, salt) — the key FileAccessEncrypted uses for a dialect pack."""
    salt = derive_dialect_salt(secret, godot_tag, dialect_seed)
    return fgd_kdf_1(secret, salt)


def dialect_params_for_secret(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> tuple[int, tuple[int, int, int, int], bytes]:
    magic = derive_pack_magic(secret, godot_tag, dialect_seed)
    perm = derive_index_perm(secret, godot_tag, dialect_seed)
    key = dialect_key_for_secret(secret, godot_tag, dialect_seed)
    return magic, perm, key

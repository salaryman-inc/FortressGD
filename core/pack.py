"""Stock GDPC pack index listing (Godot 4.6.2 / 4.7.x). No dialect, no key."""

from __future__ import annotations

import struct
from pathlib import Path

from core.errors import NEXT_VERIFY, UserError

PACK_MAGIC = 0x43504447  # "GDPC" little-endian
PACK_MAGIC_BYTES = b"GDPC"

PACK_FORMAT_V2 = 2
PACK_FORMAT_V3 = 3
PACK_FORMAT_V4 = 4
SUPPORTED_FORMATS = frozenset({PACK_FORMAT_V2, PACK_FORMAT_V3, PACK_FORMAT_V4})

PACK_DIR_ENCRYPTED = 1 << 0
PACK_REL_FILEBASE = 1 << 1
PACK_FILE_REMOVAL = 1 << 1

_MAX_FILES = 1_000_000
_MAX_PATH = 16_384


class PackError(UserError):
    """Unreadable or unsupported stock pack. CLI maps this to exit code 1."""

    def __init__(self, message: str, next_command: str = NEXT_VERIFY) -> None:
        super().__init__(message, next_command)


def list_packed_paths_from_path(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PackError("cannot read {0}: {1}".format(path, exc)) from exc
    if not data:
        raise PackError("empty file: {0}".format(path))
    return list_packed_paths(data, source=str(path))


def list_packed_paths(data: bytes, *, source: str = "pack") -> list[str]:
    """Return packed file paths from a standalone PCK or an embedded GDPC region."""
    offset = find_gdpc_offset(data)
    if offset is None:
        raise PackError("no stock GDPC pack in {0}".format(source))
    return list_packed_paths_at(data, offset, source=source)


def find_gdpc_offset(data: bytes) -> int | None:
    """Locate a stock GDPC header: start, Godot exe footer, then a scan."""
    seen: set[int] = set()
    ordered: list[int] = []

    def consider(offset: int) -> None:
        if offset < 0 or offset in seen:
            return
        seen.add(offset)
        ordered.append(offset)

    if len(data) >= 4 and data[:4] == PACK_MAGIC_BYTES:
        consider(0)
    footer = _footer_offset(data)
    if footer is not None:
        consider(footer)
    start = 0
    while True:
        idx = data.find(PACK_MAGIC_BYTES, start)
        if idx < 0:
            break
        consider(idx)
        start = idx + 1
    for offset in ordered:
        kind = _probe_pack(data, offset)
        if kind == "ok" or kind == "encrypted":
            return offset
    return None


def list_packed_paths_at(data: bytes, offset: int, *, source: str = "pack") -> list[str]:
    try:
        return _read_index(data, offset)
    except PackError:
        raise
    except (struct.error, IndexError, UnicodeDecodeError, ValueError) as exc:
        raise PackError("truncated or invalid GDPC index in {0}".format(source)) from exc


def _footer_offset(data: bytes) -> int | None:
    # Godot self-contained exe: [pck of size ds][uint64 ds][uint32 GDPC]
    if len(data) < 16:
        return None
    if data[-4:] != PACK_MAGIC_BYTES:
        return None
    ds = struct.unpack_from("<Q", data, len(data) - 12)[0]
    start = len(data) - 12 - ds
    if start < 0 or start + 4 > len(data):
        return None
    if data[start : start + 4] != PACK_MAGIC_BYTES:
        return None
    return start


def _probe_pack(data: bytes, offset: int) -> str:
    """'ok', 'encrypted', or 'no'."""
    try:
        _read_index(data, offset)
    except PackError as exc:
        if "encrypted" in str(exc):
            return "encrypted"
        return "no"
    except (struct.error, IndexError, UnicodeDecodeError, ValueError):
        return "no"
    return "ok"


def _read_index(data: bytes, pck_start: int) -> list[str]:
    i = pck_start
    magic, i = _u32(data, i)
    if magic != PACK_MAGIC:
        raise PackError("not a stock GDPC pack")
    version, i = _u32(data, i)
    if version not in SUPPORTED_FORMATS:
        raise PackError("unsupported pack format version {0}".format(version))
    _ver_major, i = _u32(data, i)
    _ver_minor, i = _u32(data, i)
    _ver_patch, i = _u32(data, i)
    pack_flags, i = _u32(data, i)
    if pack_flags & PACK_DIR_ENCRYPTED:
        raise PackError("cannot list packed paths (encrypted pack directory)")
    _file_base, i = _u64(data, i)
    if version in (PACK_FORMAT_V3, PACK_FORMAT_V4):
        dir_offset, i = _u64(data, i)
        i = pck_start + dir_offset
    else:
        i += 16 * 4  # reserved
    if i < 0 or i + 4 > len(data):
        raise PackError("truncated GDPC directory")
    file_count, i = _u32(data, i)
    if file_count > _MAX_FILES:
        raise PackError("implausible GDPC file count {0}".format(file_count))
    paths: list[str] = []
    for _ in range(file_count):
        sl, i = _u32(data, i)
        if sl > _MAX_PATH or i + sl > len(data):
            raise PackError("truncated GDPC path")
        raw = data[i : i + sl]
        i += sl
        path = raw.split(b"\x00", 1)[0].decode("utf-8")
        _ofs, i = _u64(data, i)
        _size, i = _u64(data, i)
        i += 16  # md5
        flags, i = _u32(data, i)
        if flags & PACK_FILE_REMOVAL:
            continue
        if path:
            paths.append(path)
    return paths


def _u32(data: bytes, i: int) -> tuple[int, int]:
    if i + 4 > len(data):
        raise PackError("truncated GDPC header")
    return struct.unpack_from("<I", data, i)[0], i + 4


def _u64(data: bytes, i: int) -> tuple[int, int]:
    if i + 8 > len(data):
        raise PackError("truncated GDPC header")
    return struct.unpack_from("<Q", data, i)[0], i + 8

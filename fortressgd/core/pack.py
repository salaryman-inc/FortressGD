"""Stock GDPC pack index listing (Godot 4.6.2 / 4.7.x). No dialect, no key."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from fortressgd.core.errors import NEXT_VERIFY, UserError

PACK_MAGIC = 0x43504447  # "GDPC" little-endian
PACK_MAGIC_BYTES = b"GDPC"

PACK_FORMAT_V2 = 2
PACK_FORMAT_V3 = 3
PACK_FORMAT_V4 = 4
SUPPORTED_FORMATS = frozenset({PACK_FORMAT_V2, PACK_FORMAT_V3, PACK_FORMAT_V4})

PACK_DIR_ENCRYPTED = 1 << 0  # pack header flag
PACK_REL_FILEBASE = 1 << 1
PACK_SPARSE_BUNDLE = 1 << 2  # Godot 4.7 V4 header flag
PACK_FILE_ENCRYPTED = 1 << 0  # per-file index flag (same value, different field)
PACK_FILE_REMOVAL = 1 << 1

_MAX_FILES = 1_000_000
_MAX_PATH = 16_384


class PackError(UserError):
    """Unreadable or unsupported stock pack. CLI maps this to exit code 1."""

    def __init__(self, message: str, next_command: str = NEXT_VERIFY) -> None:
        super().__init__(message, next_command)


@dataclass(frozen=True)
class PackedFile:
    path: str
    ofs: int
    size: int
    flags: int = 0


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
    return [item.path for item in list_packed_files(data, source=source)]


def list_packed_files(data: bytes, *, source: str = "pack") -> list[PackedFile]:
    listing = read_pack_listing(data, source=source)
    return listing.files


@dataclass(frozen=True)
class PackListing:
    pck_start: int
    version: int
    file_base: int
    dir_offset: int
    dir_abs: int
    dir_end: int
    files: list[PackedFile]
    # True when PACK_DIR_ENCRYPTED was set; the stock reader refuses those, so only
    # the derived-key reader in pack_dialect sets it.
    dir_encrypted: bool = False

    def blob(self, data: bytes, item: PackedFile) -> bytes:
        if item.size <= 0:
            return b""
        start = self.file_base + item.ofs
        if start < 0 or start + item.size > len(data):
            raise PackError("truncated packed file {0}".format(item.path))
        return data[start : start + item.size]

    def index_bytes(self, data: bytes) -> bytes:
        """The signed range: the on-disk directory from dir_abs to its end.

        For an encrypted directory that is the plaintext u32 file_count plus the
        FileAccessEncrypted blob, exactly what the engine patch verifies
        (patches/<tag>/0005-pack-signatures.patch).
        """
        return data[self.dir_abs : self.dir_end]


def read_pack_listing(data: bytes, *, source: str = "pack") -> PackListing:
    offset = find_gdpc_offset(data)
    if offset is None:
        raise PackError("no stock GDPC pack in {0}".format(source))
    return read_pack_listing_at(data, offset, source=source)


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
    return [item.path for item in read_pack_listing_at(data, offset, source=source).files]


def read_pack_listing_at(data: bytes, offset: int, *, source: str = "pack") -> PackListing:
    try:
        return _read_listing(data, offset)
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
    return [item.path for item in _read_listing(data, pck_start).files]


def _read_listing(data: bytes, pck_start: int) -> PackListing:
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
    file_base, i = _u64(data, i)
    dir_offset = 0
    if version in (PACK_FORMAT_V3, PACK_FORMAT_V4):
        dir_offset, i = _u64(data, i)
        i = pck_start + dir_offset
        file_base = file_base + pck_start
        dir_abs = i
    else:
        i += 16 * 4  # reserved
        dir_abs = i
    if i < 0 or i + 4 > len(data):
        raise PackError("truncated GDPC directory")
    file_count, i = _u32(data, i)
    if file_count > _MAX_FILES:
        raise PackError("implausible GDPC file count {0}".format(file_count))
    files: list[PackedFile] = []
    for _ in range(file_count):
        sl, i = _u32(data, i)
        if sl > _MAX_PATH or i + sl > len(data):
            raise PackError("truncated GDPC path")
        raw = data[i : i + sl]
        i += sl
        path = raw.split(b"\x00", 1)[0].decode("utf-8")
        ofs, i = _u64(data, i)
        size, i = _u64(data, i)
        i += 16  # md5
        flags, i = _u32(data, i)
        if flags & PACK_FILE_REMOVAL:
            continue
        if path:
            files.append(PackedFile(path=path, ofs=ofs, size=size, flags=flags))
    return PackListing(
        pck_start=pck_start,
        version=version,
        file_base=file_base,
        dir_offset=dir_offset,
        dir_abs=dir_abs,
        dir_end=i,
        files=files,
    )


def _u32(data: bytes, i: int) -> tuple[int, int]:
    if i + 4 > len(data):
        raise PackError("truncated GDPC header")
    return struct.unpack_from("<I", data, i)[0], i + 4


def _u64(data: bytes, i: int) -> tuple[int, int]:
    if i + 8 > len(data):
        raise PackError("truncated GDPC header")
    return struct.unpack_from("<Q", data, i)[0], i + 8

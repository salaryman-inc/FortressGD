"""GDSC (.gdc) debug-name-table scan (DESIGN.md §10 item 5 / Phase 5 nameless bytecode)."""

from __future__ import annotations

import struct

GDSC_MAGIC = b"GDSC"
TOKENIZER_VERSION = 101
IDENT_XOR = 0xB6
FGDN_MAGIC = b"FGDN"


def encode_ident_entry(name: str) -> bytes:
    chars = [ord(ch) for ch in name]
    buf = bytearray(struct.pack("<I", len(chars)))
    for ch in chars:
        raw = struct.pack("<I", ch)
        buf.extend(bytes(b ^ IDENT_XOR for b in raw))
    return bytes(buf)


def encode_gdsc(
    identifiers: list[str],
    *,
    nameless: bool = False,
    token_line_count: int = 0,
    token_count: int = 0,
) -> bytes:
    """
    Minimal uncompressed GDSC blob.

    nameless=True omits the stock identifier/line tables (identifier_count=0,
    token_line_count=0) and stores runtime names in an FGDN trailer — the
    same split the engine patch writes.
    """
    if nameless:
        ident_count = 0
        ident_blob = b""
        lines = 0
    else:
        ident_count = len(identifiers)
        ident_blob = b"".join(encode_ident_entry(n) for n in identifiers)
        lines = token_line_count
    contents = struct.pack("<IIII", ident_count, 0, lines, token_count) + ident_blob
    if lines:
        contents += b"\x00" * (lines * 16)
    if nameless:
        trailer = bytearray(FGDN_MAGIC)
        trailer.extend(struct.pack("<I", len(identifiers)))
        for name in identifiers:
            trailer.extend(encode_ident_entry(name))
        contents += bytes(trailer)
    header = GDSC_MAGIC + struct.pack("<II", TOKENIZER_VERSION, 0)
    return header + contents


def find_gdsc(data: bytes) -> bytes | None:
    """Return the GDSC blob inside `data`, or None."""
    if data.startswith(GDSC_MAGIC):
        return data
    idx = data.find(GDSC_MAGIC)
    if idx < 0:
        return None
    return data[idx:]


def gdsc_debug_name_counts(blob: bytes) -> tuple[int, int] | None:
    """
    (identifier_count, token_line_count) from a GDSC header.

    None if this is not an uncompressed GDSC we can parse.
    Compressed buffers (decompressed_size != 0) are treated as named
    (counts returned as (1, 0)) so verify fails closed when nameless is on.
    """
    if len(blob) < 12 or blob[:4] != GDSC_MAGIC:
        return None
    decompressed = struct.unpack_from("<I", blob, 8)[0]
    if decompressed != 0:
        return (1, 0)
    contents = blob[12:]
    if len(contents) < 16:
        return None
    ident_count, _const_count, line_count, _token_count = struct.unpack_from(
        "<IIII", contents, 0
    )
    return (ident_count, line_count)


def has_debug_name_tables(data: bytes) -> bool:
    """True if a GDSC blob in `data` still carries stock identifier/line tables."""
    blob = find_gdsc(data)
    if blob is None:
        return False
    counts = gdsc_debug_name_counts(blob)
    if counts is None:
        return False
    ident_count, line_count = counts
    return ident_count > 0 or line_count > 0

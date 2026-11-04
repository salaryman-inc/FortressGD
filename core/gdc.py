"""GDSC (.gdc) debug-name-table scan (DESIGN.md §10 item 5 / Phase 5 nameless bytecode)."""

from __future__ import annotations

import struct

GDSC_MAGIC = b"GDSC"
TOKENIZER_VERSION = 101
IDENT_XOR = 0xB6
FGDN_MAGIC = b"FGDN"

# GDScriptTokenizer::Token::Type (gdscript_tokenizer.h). IDENTIFIER looks up
# identifiers[] inside _binary_to_token.
TOKEN_EMPTY = 0
TOKEN_ANNOTATION = 1
TOKEN_IDENTIFIER = 2
TOKEN_BYTE_MASK = 0x80
TOKEN_BITS = 8
TOKEN_MASK = (1 << (TOKEN_BITS - 1)) - 1


def encode_ident_entry(name: str) -> bytes:
    chars = [ord(ch) for ch in name]
    buf = bytearray(struct.pack("<I", len(chars)))
    for ch in chars:
        raw = struct.pack("<I", ch)
        buf.extend(bytes(b ^ IDENT_XOR for b in raw))
    return bytes(buf)


def decode_ident_entry(data: bytes, i: int) -> tuple[str, int]:
    if i + 4 > len(data):
        raise ValueError("truncated identifier length")
    nchars = struct.unpack_from("<I", data, i)[0]
    i += 4
    need = nchars * 4
    if i + need > len(data):
        raise ValueError("truncated identifier")
    chars: list[str] = []
    for _ in range(nchars):
        raw = bytes(b ^ IDENT_XOR for b in data[i : i + 4])
        chars.append(chr(struct.unpack("<I", raw)[0]))
        i += 4
    return "".join(chars), i


def encode_identifier_token(ident_index: int, start_line: int = 1) -> bytes:
    token_type = (TOKEN_IDENTIFIER & TOKEN_MASK) | (ident_index << TOKEN_BITS)
    token_type |= TOKEN_BYTE_MASK
    return struct.pack("<II", token_type, start_line)


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
    token_line_count=0) and stores runtime names in an FGDN block *before*
    the token stream — the same order the engine patch reads, so
    _binary_to_token can resolve IDENTIFIER tokens.
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
    if token_count > 0:
        if not identifiers:
            raise ValueError("identifier tokens require names")
        for i in range(token_count):
            contents += encode_identifier_token(i % len(identifiers))
    header = GDSC_MAGIC + struct.pack("<II", TOKENIZER_VERSION, 0)
    return header + contents


def parse_gdsc_engine_order(blob: bytes) -> tuple[list[str], int]:
    """
    Sequential parse matching patched GDScriptTokenizerBuffer::set_code_buffer.

    Stock identifier table first; if that count is 0, load FGDN *before*
    walking tokens. IDENTIFIER tokens look up identifiers[] the same way
    _binary_to_token does — out of range is an error, not a skip.
    """
    blob = find_gdsc(blob) or blob
    if len(blob) < 12 or blob[:4] != GDSC_MAGIC:
        raise ValueError("not GDSC")
    if struct.unpack_from("<I", blob, 8)[0] != 0:
        raise ValueError("compressed GDSC")
    data = blob[12:]
    if len(data) < 16:
        raise ValueError("truncated GDSC contents")
    ident_count, const_count, line_count, token_count = struct.unpack_from("<IIII", data, 0)
    i = 16
    identifiers: list[str] = []
    for _ in range(ident_count):
        name, i = decode_ident_entry(data, i)
        identifiers.append(name)
    for _ in range(const_count):
        raise ValueError("constants not supported in this parser")
    i += line_count * 16
    if ident_count == 0 and i + 8 <= len(data) and data[i : i + 4] == FGDN_MAGIC:
        n = struct.unpack_from("<I", data, i + 4)[0]
        i += 8
        identifiers = []
        for _ in range(n):
            name, i = decode_ident_entry(data, i)
            identifiers.append(name)
    resolved = 0
    for _ in range(token_count):
        if i >= len(data):
            raise ValueError("truncated token")
        if data[i] & TOKEN_BYTE_MASK:
            if i + 8 > len(data):
                raise ValueError("truncated token")
            token_type = struct.unpack_from("<I", data, i)[0]
            i += 8
        else:
            token_type = data[i]
            i += 5
        ttype = token_type & TOKEN_MASK
        if ttype in (TOKEN_IDENTIFIER, TOKEN_ANNOTATION):
            pos = token_type >> TOKEN_BITS
            if pos >= len(identifiers):
                raise ValueError("Identifier index out of bounds.")
            resolved += 1
    return identifiers, resolved


def find_gdsc(data: bytes) -> bytes | None:
    """Return the GDSC blob inside `data`, or None."""
    if data.startswith(GDSC_MAGIC):
        return data
    idx = data.find(GDSC_MAGIC)
    if idx < 0:
        return None
    return data[idx:]


class CompressedGdscError(ValueError):
    """A compressed GDSC blob and no zstd decoder (Python < 3.14)."""


def _zstd_decompress(frame: bytes) -> bytes:
    try:
        from compression import zstd  # type: ignore[import-not-found]  # Python 3.14+
    except ImportError as exc:
        raise CompressedGdscError("compressed GDSC needs Python 3.14+ (compression.zstd)") from exc
    return zstd.decompress(frame)


def gdsc_debug_name_counts(blob: bytes) -> tuple[int, int] | None:
    """
    (identifier_count, token_line_count) from a GDSC header.

    None if this is not a GDSC we can parse. A compressed buffer
    (decompressed_size != 0, "Compressed binary tokens") is one ZSTD frame after
    the 12-byte header: it is decoded with compression.zstd on Python 3.14+, and
    raises CompressedGdscError otherwise so verify fails closed with a reason. A
    frame that does not decode to decompressed_size raises ValueError.
    """
    if len(blob) < 12 or blob[:4] != GDSC_MAGIC:
        return None
    decompressed = struct.unpack_from("<I", blob, 8)[0]
    if decompressed != 0:
        try:
            contents = _zstd_decompress(blob[12:])
        except CompressedGdscError:
            raise
        except Exception as exc:
            raise ValueError("corrupt compressed GDSC") from exc
        if len(contents) != decompressed:
            raise ValueError("compressed GDSC size mismatch")
    else:
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

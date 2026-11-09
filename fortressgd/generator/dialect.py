"""Deterministic dialect.gen.h: salt, shards, pack magic, index perm (Phase 3)."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from fortressgd.core.kdf import SALT_LEN, fgd_kdf_1, hkdf_sha256
from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.key_shards import derive_masks, encode_key, mask_pieces, shard_pieces

# Bump when header layout or derivation inputs change.
GENERATOR_VERSION = 2

DIALECT_SALT_INFO = b"fortressgd.dialect.v1"
HEADER_NAME = "dialect.gen.h"

# Stock Godot pack magic ("GDPC" little-endian). Dialect magic must not equal this.
STOCK_PACK_MAGIC = 0x43504447

INDEX_FIELD_OFS = 0
INDEX_FIELD_SIZE = 1
INDEX_FIELD_MD5 = 2
INDEX_FIELD_FLAGS = 3
INDEX_FIELD_COUNT = 4
STOCK_INDEX_PERM = (INDEX_FIELD_OFS, INDEX_FIELD_SIZE, INDEX_FIELD_MD5, INDEX_FIELD_FLAGS)

_PACK_MATERIAL_LEN = 4 + INDEX_FIELD_COUNT  # magic + Fisher-Yates entropy


def _domain_salt(godot_tag: str, purpose: str) -> bytes:
    material = "fortressgd.gen.{0}|{1}|{2}".format(
        GENERATOR_VERSION, godot_tag, purpose
    ).encode("utf-8")
    return hashlib.sha256(material).digest()


def _info(dialect_seed: bytes | None) -> bytes:
    return dialect_seed if dialect_seed is not None else DIALECT_SALT_INFO


def derive_dialect_salt(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> bytes:
    """16-byte FGD_DIALECT_SALT. Same secret + tag + generator version => same salt."""
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    return hkdf_sha256(secret, _domain_salt(godot_tag, "salt"), _info(dialect_seed), SALT_LEN)


def derive_shard_masks(secret: bytes, godot_tag: str) -> bytes:
    return derive_masks(secret, _domain_salt(godot_tag, "shards"))


def _pack_material(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> bytes:
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    return hkdf_sha256(
        secret,
        _domain_salt(godot_tag, "pack"),
        _info(dialect_seed),
        _PACK_MATERIAL_LEN,
    )


def derive_pack_magic(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> int:
    """uint32 FGD_PACK_MAGIC. Never stock GDPC. Deterministic for (secret, tag, seed)."""
    raw = _pack_material(secret, godot_tag, dialect_seed)[:4]
    magic = struct.unpack("<I", raw)[0]
    if magic == STOCK_PACK_MAGIC or magic == 0:
        magic ^= 0xA5A5A5A5
    if magic == STOCK_PACK_MAGIC or magic == 0:
        magic = STOCK_PACK_MAGIC ^ 1
    return magic & 0xFFFFFFFF


def derive_index_perm(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> tuple[int, int, int, int]:
    """Permutation of pack-index-record fields (ofs, size, md5, flags)."""
    entropy = _pack_material(secret, godot_tag, dialect_seed)[4:]
    perm = list(STOCK_INDEX_PERM)
    for i in range(INDEX_FIELD_COUNT - 1, 0, -1):
        j = entropy[i] % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return (perm[0], perm[1], perm[2], perm[3])


def dialect_id(
    salt: bytes,
    masks: bytes,
    shards: bytes,
    pack_magic: int,
    index_perm: tuple[int, int, int, int],
) -> str:
    """Non-secret identifier for manifest.json."""
    extra = struct.pack("<I", pack_magic) + bytes(index_perm)
    return hashlib.sha256(
        b"fortressgd.dialect.id.v1|" + salt + masks + shards + extra
    ).hexdigest()[:16]


def dialect_material(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> tuple[bytes, bytes, bytes, str]:
    """salt, masks, key shards, dialect_id for (secret, tag, generator version).

    The shards encode the pack AES key FGD-KDF-1(secret, salt), not the secret.
    """
    salt = derive_dialect_salt(secret, godot_tag, dialect_seed)
    masks = derive_shard_masks(secret, godot_tag)
    shards = encode_key(fgd_kdf_1(secret, salt), masks)
    magic = derive_pack_magic(secret, godot_tag, dialect_seed)
    perm = derive_index_perm(secret, godot_tag, dialect_seed)
    return salt, masks, shards, dialect_id(salt, masks, shards, magic, perm)


def _c_array(name: str, data: bytes, indent: str = "\t") -> str:
    hex_bytes = ", ".join("0x{0:02x}".format(b) for b in data)
    return "{0}static const uint8_t {1}[{2}] = {{ {3} }};".format(
        indent, name, len(data), hex_bytes
    )


def _c_array_2d(
    name: str,
    pieces: tuple[bytes, bytes, bytes, bytes],
    indent: str = "\t",
    *,
    volatile: bool = False,
) -> str:
    rows = []
    for piece in pieces:
        inner = ", ".join("0x{0:02x}".format(b) for b in piece)
        rows.append("{0}{{ {1} }}".format(indent + "\t", inner))
    qualifier = "const volatile" if volatile else "const"
    return "{0}static {1} uint8_t {2}[4][8] = {{\n{3}\n{0}}};".format(
        indent, qualifier, name, ",\n".join(rows)
    )


def _c_u32(name: str, value: int, indent: str = "\t") -> str:
    return "{0}static const uint32_t {1} = 0x{2:08x};".format(indent, name, value & 0xFFFFFFFF)


def _c_perm(name: str, perm: tuple[int, int, int, int], indent: str = "\t") -> str:
    inner = ", ".join(str(int(x)) for x in perm)
    return "{0}static const uint8_t {1}[4] = {{ {2} }};".format(indent, name, inner)


def render_dialect_header(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
    *,
    require_signature: bool = False,
) -> str:
    """
    Data-only C header. No executable snippets derived from the secret.

    Contains FGD_KEY_MASKS[4][8] and FGD_KEY_SHARDS[4][8] (the masked pack AES
    key; never the project secret), FGD_PACK_MAGIC, FGD_INDEX_PERM[4], FGD_OPCODE_MAP/UNMAP, FGD_PACK_PUBKEY, and
    FGD_REQUIRE_PACK_SIGNATURE (1 when the template must refuse unsigned packs).
    """
    from fortressgd.core.pack_sign import public_key_for_secret
    from fortressgd.generator.opcode_map import render_opcode_arrays

    _salt, masks, shards, _did = dialect_material(secret, godot_tag, dialect_seed)
    magic = derive_pack_magic(secret, godot_tag, dialect_seed)
    perm = derive_index_perm(secret, godot_tag, dialect_seed)
    pubkey = public_key_for_secret(secret, godot_tag, dialect_seed)
    lines = [
        "/* generated by fortressgd generator v{0}; do not commit */".format(GENERATOR_VERSION),
        "#ifndef FORTRESSGD_DIALECT_GEN_H",
        "#define FORTRESSGD_DIALECT_GEN_H",
        "",
        "#include <stdint.h>",
        "",
        "/* data only — masked pack key, magic, perm, opcode map, pubkey; never the project secret */",
        # FGD_KEY_SHARDS ^ FGD_KEY_MASKS is the pack AES key, FGD-KDF-1(secret,
        # salt), computed here. The project secret, the salt and the signing
        # seed are never written to the header, so extracting a template's key
        # opens packs made with that key and nothing else: not the secret, not
        # the signing seed.
        #
        # volatile: with plain `static const` arrays the compiler folds the XOR
        # at build time (GCC -O3, Godot's production=yes) and stores the
        # reassembled key in the binary. volatile forces a runtime load of every
        # byte, so only the shards and masks are stored.
        _c_array_2d("FGD_KEY_MASKS", mask_pieces(masks), volatile=True),
        _c_array_2d("FGD_KEY_SHARDS", shard_pieces(shards), volatile=True),
        _c_u32("FGD_PACK_MAGIC", magic),
        _c_perm("FGD_INDEX_PERM", perm),
    ]
    lines.extend(render_opcode_arrays(secret, godot_tag, dialect_seed))
    lines.extend(
        [
            _c_array("FGD_PACK_PUBKEY", pubkey),
            "\tstatic const uint8_t FGD_REQUIRE_PACK_SIGNATURE = {0};".format(1 if require_signature else 0),
            "",
            "#endif /* FORTRESSGD_DIALECT_GEN_H */",
            "",
        ]
    )
    return "\n".join(lines)


def write_dialect_header(
    path: Path,
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
    *,
    require_signature: bool = False,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_dialect_header(secret, godot_tag, dialect_seed, require_signature=require_signature),
        encoding="utf-8",
    )
    return path

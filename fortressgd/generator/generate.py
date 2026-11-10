"""Assemble the template build's dialect.gen.h for generator v2 (DESIGN.md §18.3).

render_gen_header() emits a self-contained C++ header: inline decode functions, an
inline fgd_derive_key(), and one inline const FgdGenData with the decoded magic,
index order, opcode tables and public key. The plaintext values are the exact
outputs of the v1 derivations, so a template built from this header opens the same
packs `fortressgd export` produces: the pack AES key is FGD-KDF-1(secret, salt),
and the magic, index permutation, opcode tables and public key match dialect.py /
opcode_map.py / pack_sign.py.

The key is split into 3-8 pieces, each stored under its own chain and reassembled
in generated order. Function definition order comes from the code stream too. None
of the generated code holds the secret, the salt or the signing seed; it holds
only what the v1 header already did, encoded differently.
"""

from __future__ import annotations

import struct

from fortressgd.core.kdf import fgd_kdf_1
from fortressgd.core.pack_sign import public_key_for_secret
from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.codeseed import CodeStream, derive_code_seed
from fortressgd.generator.dialect import (
    derive_dialect_salt,
    derive_index_perm,
    derive_pack_magic,
)
from fortressgd.generator.emit import emit_decode_fn
from fortressgd.generator.opchain import build_chain
from fortressgd.generator.opcode_map import FGD_OPCODE_COUNT, opcode_perm, opcode_unmap

KEY_LEN = 32
MIN_KEY_PIECES = 3
MAX_KEY_PIECES = 8


def plaintext_values(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
    key_epoch: int = 0,
) -> dict:
    """The exact values the generated code must reproduce (the v1 derivations)."""
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    salt = derive_dialect_salt(secret, godot_tag, dialect_seed, key_epoch)
    key = fgd_kdf_1(secret, salt)
    magic = derive_pack_magic(secret, godot_tag, dialect_seed)
    perm = derive_index_perm(secret, godot_tag, dialect_seed)
    omap = opcode_perm(secret, godot_tag, dialect_seed)
    ounmap = opcode_unmap(secret, godot_tag, dialect_seed)
    pubkey = public_key_for_secret(secret, godot_tag, dialect_seed)
    if FGD_OPCODE_COUNT > 256:  # pragma: no cover - guards the uint8 packing below
        raise ValueError("opcode count must fit in a byte for the generated tables")
    return {
        "key": key,
        "magic": magic,
        "index_perm": bytes(perm),
        "opcode_map": bytes(omap),
        "opcode_unmap": bytes(ounmap),
        "pubkey": pubkey,
    }


def _decoder(stream: CodeStream, name: str, plain: bytes, info: bytes) -> str:
    chain = build_chain(CodeStream(stream.read(32), info), len(plain))
    return emit_decode_fn(name, plain, chain)


def render_gen_header(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
    key_epoch: int = 0,
) -> str:
    """The full dialect.gen.h for a template build. Deterministic for (secret, tag, seed, epoch).

    Header-only (C++17): inline decode functions, inline fgd_derive_key(), and one
    inline const FgdGenData holding the decoded magic, index order, opcode tables
    and public key. The patches reference the FGD_* macros below; opcode dispatch
    stays a plain member-array load. No translation unit includes generated content
    other than this one header, so Godot's own objects never depend on it (§18.4).
    """
    v = plaintext_values(secret, godot_tag, dialect_seed, key_epoch)
    seed = derive_code_seed(secret, godot_tag, key_epoch)
    stream = CodeStream(seed, b"fortressgd.dialect.gen.h|" + godot_tag.encode("utf-8"))

    # Split the key into pieces with per-build sizes.
    n_pieces = stream.randrange(MIN_KEY_PIECES, MAX_KEY_PIECES)
    sizes = stream.split_sizes(KEY_LEN, n_pieces)
    offsets = []
    off = 0
    for s in sizes:
        offsets.append(off)
        off += s

    decoders: list[tuple[str, str]] = []
    key_pieces: list[tuple[str, int]] = []  # (fn name, offset)
    for i, (sz, ofs) in enumerate(zip(sizes, offsets)):
        name = "fgd__k{0}".format(i)
        decoders.append((name, _decoder(stream, name, v["key"][ofs : ofs + sz], b"key%d" % i)))
        key_pieces.append((name, ofs))
    decoders.append(("fgd__magic", _decoder(stream, "fgd__magic", struct.pack("<I", v["magic"]), b"magic")))
    decoders.append(("fgd__perm", _decoder(stream, "fgd__perm", v["index_perm"], b"perm")))
    decoders.append(("fgd__omap", _decoder(stream, "fgd__omap", v["opcode_map"], b"omap")))
    decoders.append(("fgd__ounmap", _decoder(stream, "fgd__ounmap", v["opcode_unmap"], b"ounmap")))
    decoders.append(("fgd__pubkey", _decoder(stream, "fgd__pubkey", v["pubkey"], b"pubkey")))

    # Emit the definitions in seed-chosen order (layout varies per build).
    order = list(range(len(decoders)))
    stream.shuffle(order)

    lines: list[str] = []
    lines.append("/* generated by fortressgd generator v2; do not commit */")
    lines.append("#ifndef FORTRESSGD_DIALECT_GEN_H")
    lines.append("#define FORTRESSGD_DIALECT_GEN_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("#ifndef FGD_OPCODE_COUNT")
    lines.append("#define FGD_OPCODE_COUNT {0}".format(FGD_OPCODE_COUNT))
    lines.append("#endif")
    lines.append("")
    for idx in order:
        lines.append(decoders[idx][1])
        lines.append("")

    # fgd_derive_key: reassemble the pieces into the 32-byte key. Decoded into the
    # caller's buffer and never cached; fortressgd_kdf.cpp wipes it after use.
    lines.append("inline void fgd_derive_key(uint8_t r_key[32]) {")
    for name, ofs in key_pieces:
        lines.append("\t{0}(r_key + {1});".format(name, ofs))
    lines.append("}")
    lines.append("")

    # The non-secret dialect data, decoded once into one shared instance at
    # startup. Members are plain arrays, so FGD_OPCODE_* indexing in the VM is a
    # direct load, as the v1 arrays were.
    lines.append("struct FgdGenData {")
    lines.append("\tuint32_t magic;")
    lines.append("\tuint8_t index_perm[4];")
    lines.append("\tuint16_t opcode_map[FGD_OPCODE_COUNT];")
    lines.append("\tuint16_t opcode_unmap[FGD_OPCODE_COUNT];")
    lines.append("\tuint8_t pack_pubkey[32];")
    lines.append("\tFgdGenData() {")
    lines.append("\t\tuint8_t mg[4];")
    lines.append("\t\tfgd__magic(mg);")
    lines.append(
        "\t\tmagic = (uint32_t)mg[0] | ((uint32_t)mg[1] << 8) | ((uint32_t)mg[2] << 16) | ((uint32_t)mg[3] << 24);"
    )
    lines.append("\t\tfgd__perm(index_perm);")
    lines.append("\t\tuint8_t m[FGD_OPCODE_COUNT];")
    lines.append("\t\tuint8_t u[FGD_OPCODE_COUNT];")
    lines.append("\t\tfgd__omap(m);")
    lines.append("\t\tfgd__ounmap(u);")
    lines.append("\t\tfor (int i = 0; i < FGD_OPCODE_COUNT; i++) { opcode_map[i] = m[i]; opcode_unmap[i] = u[i]; }")
    lines.append("\t\tfgd__pubkey(pack_pubkey);")
    lines.append("\t}")
    lines.append("};")
    lines.append("inline const FgdGenData fgd_gen_data;")
    lines.append("")
    lines.append("#define FGD_PACK_MAGIC (fgd_gen_data.magic)")
    lines.append("#define FGD_INDEX_PERM (fgd_gen_data.index_perm)")
    lines.append("#define FGD_OPCODE_MAP (fgd_gen_data.opcode_map)")
    lines.append("#define FGD_OPCODE_UNMAP (fgd_gen_data.opcode_unmap)")
    lines.append("#define FGD_PACK_PUBKEY (fgd_gen_data.pack_pubkey)")
    lines.append("")
    # A compile-time flag, never a stored value: in data one flipped byte would
    # turn signature checking off (DESIGN.md §18.3). The build passes
    # -DFGD_REQUIRE_PACK_SIGNATURE=1 for a signing template.
    lines.append("#ifndef FGD_REQUIRE_PACK_SIGNATURE")
    lines.append("#define FGD_REQUIRE_PACK_SIGNATURE 0")
    lines.append("#endif")
    lines.append("")
    lines.append("#endif /* FORTRESSGD_DIALECT_GEN_H */")
    lines.append("")
    return "\n".join(lines)

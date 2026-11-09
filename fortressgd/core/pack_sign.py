"""Ed25519 signatures over the pack index (DESIGN.md Phase 5 / §8.4)."""

from __future__ import annotations

from fortressgd.core import ed25519
from fortressgd.core.kdf import hkdf_sha256
from fortressgd.core.secret import SECRET_BYTES

SIG_INFO = b"fortressgd.pack.ed25519.v1"
SIG_PREFIX = b"fortressgd.pack.sig.v1"
SIG_LEN = 64
PUBKEY_LEN = 32
# v3/v4 header: 6*u32 + file_base u64 + dir_offset u64 = 40, then 64 reserved.
V3_RESERVED_OFF = 40


def signing_seed(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> bytes:
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    from fortressgd.generator.dialect import _domain_salt, _info

    return hkdf_sha256(
        secret,
        _domain_salt(godot_tag, "sign"),
        _info(dialect_seed) + b"|" + SIG_INFO,
        32,
    )


def keypair_for_secret(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> tuple[bytes, bytes]:
    """(32-byte seed, 32-byte public key). Seed is not persisted by callers."""
    return ed25519.keypair_from_seed(signing_seed(secret, godot_tag, dialect_seed))


def public_key_for_secret(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> bytes:
    return keypair_for_secret(secret, godot_tag, dialect_seed)[1]


def sign_index(
    index_bytes: bytes,
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> bytes:
    seed, _pk = keypair_for_secret(secret, godot_tag, dialect_seed)
    return ed25519.sign(seed, SIG_PREFIX + index_bytes)


def verify_index(index_bytes: bytes, signature: bytes, public_key: bytes) -> bool:
    if len(signature) != SIG_LEN or len(public_key) != PUBKEY_LEN:
        return False
    if signature == b"\x00" * SIG_LEN:
        return False
    return ed25519.verify(public_key, SIG_PREFIX + index_bytes, signature)


def reserved_offset(pck_start: int, version: int) -> int:
    if version >= 3:
        return pck_start + V3_RESERVED_OFF
    return pck_start + 32


def read_reserved_signature(data: bytes, pck_start: int, version: int) -> bytes:
    off = reserved_offset(pck_start, version)
    if off + SIG_LEN > len(data):
        return b"\x00" * SIG_LEN
    return data[off : off + SIG_LEN]


def apply_signature(data: bytes, signature: bytes, pck_start: int, version: int) -> bytes:
    if len(signature) != SIG_LEN:
        raise ValueError("signature must be {0} bytes".format(SIG_LEN))
    off = reserved_offset(pck_start, version)
    out = bytearray(data)
    out[off : off + SIG_LEN] = signature
    return bytes(out)

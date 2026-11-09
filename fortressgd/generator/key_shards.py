"""Compile-time shard encoding of the pack AES key for dialect.gen.h (DESIGN.md §5.2).

The template stores FGD-KDF-1(secret, salt) as masked shards. It never stores the
project secret: everything else the secret derives, including the pack-signing
seed, must stay off every shipped binary.
"""

from __future__ import annotations

from fortressgd.core.kdf import hkdf_sha256
from fortressgd.core.secret import SECRET_BYTES
from fortressgd.core.shards import MASK_MATERIAL_INFO, encode_shards, split_pieces


def derive_masks(secret: bytes, mask_salt: bytes) -> bytes:
    """32 mask bytes, stored separately from shards. Deterministic for (secret, salt)."""
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    return hkdf_sha256(secret, mask_salt, MASK_MATERIAL_INFO, SECRET_BYTES)


def encode_key(aes_key: bytes, masks: bytes) -> bytes:
    """XOR the 32-byte pack key with masks. Never pass the project secret."""
    return encode_shards(aes_key, masks)


def shard_pieces(shards: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    return split_pieces(shards)


def mask_pieces(masks: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    return split_pieces(masks)

"""Compile-time secret shard encoding for dialect.gen.h (DESIGN.md §5.2)."""

from __future__ import annotations

from core.kdf import hkdf_sha256
from core.secret import SECRET_BYTES
from core.shards import MASK_MATERIAL_INFO, encode_shards, split_pieces


def derive_masks(secret: bytes, mask_salt: bytes) -> bytes:
    """32 mask bytes, stored separately from shards. Deterministic for (secret, salt)."""
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    return hkdf_sha256(secret, mask_salt, MASK_MATERIAL_INFO, SECRET_BYTES)


def encode_secret(secret: bytes, masks: bytes) -> bytes:
    return encode_shards(secret, masks)


def shard_pieces(shards: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    return split_pieces(shards)


def mask_pieces(masks: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    return split_pieces(masks)

"""Shard scheme v1: 4×8-byte pieces XOR'd with compile-time masks (DESIGN.md §5.2)."""

from __future__ import annotations

from fortressgd.core.secret import SECRET_BYTES

SHARD_COUNT = 4
SHARD_LEN = 8
MASK_MATERIAL_INFO = b"fortressgd.shards.v1"


def encode_shards(secret: bytes, masks: bytes) -> bytes:
    """
    Split secret into 4×8-byte pieces and XOR with masks.

    `masks` is 32 bytes stored separately from the returned 32-byte shards.
    """
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    if len(masks) != SECRET_BYTES:
        raise ValueError("masks must be {0} bytes".format(SECRET_BYTES))
    return bytes(s ^ m for s, m in zip(secret, masks))


def decode_shards(shards: bytes, masks: bytes) -> bytes:
    """Reassemble secret from shards XOR masks (XOR is involutive)."""
    if len(shards) != SECRET_BYTES:
        raise ValueError("shards must be {0} bytes".format(SECRET_BYTES))
    if len(masks) != SECRET_BYTES:
        raise ValueError("masks must be {0} bytes".format(SECRET_BYTES))
    return bytes(s ^ m for s, m in zip(shards, masks))


def split_pieces(blob: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """View a 32-byte blob as 4×8-byte pieces."""
    if len(blob) != SECRET_BYTES:
        raise ValueError("blob must be {0} bytes".format(SECRET_BYTES))
    return (
        blob[0:8],
        blob[8:16],
        blob[16:24],
        blob[24:32],
    )

"""FGD-KDF-1 and secret_hash (DESIGN.md §5.1–5.2). Pure functions; no I/O."""

from __future__ import annotations

import hashlib
import hmac

from core.secret import SECRET_BYTES

# HKDF-SHA256 info and output length for the PCK AES key. Tests assert these.
FGD_KDF_INFO = b"fortressgd.pck.aes.v1"
FGD_KDF_LEN = 32
SECRET_HASH_PREFIX = b"fortressgd-v1|"
SECRET_HASH_HEX_LEN = 16
SALT_LEN = 16
HKDF_HASH_LEN = 32


def secret_hash(secret: bytes) -> str:
    """First 16 hex chars of SHA256(\"fortressgd-v1|\" + secret_bytes)."""
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    digest = hashlib.sha256(SECRET_HASH_PREFIX + secret).hexdigest()
    return digest[:SECRET_HASH_HEX_LEN]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 extract-then-expand."""
    if length <= 0:
        raise ValueError("HKDF length must be positive")
    if length > 255 * HKDF_HASH_LEN:
        raise ValueError("HKDF length too large")
    if not salt:
        salt = b"\x00" * HKDF_HASH_LEN
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def fgd_kdf_1(secret: bytes, dialect_salt: bytes) -> bytes:
    """
    FGD-KDF-1: aes_key = HKDF-SHA256(
        ikm=secret[32], salt=dialect_salt[16],
        info=\"fortressgd.pck.aes.v1\", L=32
    )
    """
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    if len(dialect_salt) != SALT_LEN:
        raise ValueError("dialect_salt must be {0} bytes".format(SALT_LEN))
    return hkdf_sha256(secret, dialect_salt, FGD_KDF_INFO, FGD_KDF_LEN)


def aes_key_hex(secret: bytes, dialect_salt: bytes) -> str:
    """64 lowercase hex chars of FGD-KDF-1(secret, salt)."""
    return fgd_kdf_1(secret, dialect_salt).hex()

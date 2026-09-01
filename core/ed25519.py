"""Ed25519 (RFC 8032) sign/verify. Pure Python, no extra deps.

Public-domain field arithmetic after the SUPERCOP ref10 / DJB Python ref.
Private scalars are never written to disk by FortressGD callers.
"""

from __future__ import annotations

import hashlib

_B = 256
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5)
_BX = _xrecover(_BY)
_BPOINT = (_BX % _Q, _BY % _Q)


def _edwards(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return (x3 % _Q, y3 % _Q)


def _scalarmult(point: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(point, e // 2)
    q = _edwards(q, q)
    if e & 1:
        q = _edwards(q, point)
    return q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = bytearray(_encodeint(y))
    if x & 1:
        bits[31] |= 0x80
    return bytes(bits)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    h = hashlib.sha512(m).digest()
    return int.from_bytes(h, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _isoncurve(p: tuple[int, int]) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decodepoint(s: bytes) -> tuple[int, int] | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != _bit(s, 255):
        x = _Q - x
    p = (x, y)
    if not _isoncurve(p):
        return None
    return p


def keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Return (32-byte seed, 32-byte public key). `seed` must be 32 bytes."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = 2 ** (_B - 2) + sum(2**i * _bit(h, i) for i in range(3, _B - 2))
    public = _encodepoint(_scalarmult(_BPOINT, a))
    return seed, public


def public_key_from_seed(seed: bytes) -> bytes:
    return keypair_from_seed(seed)[1]


def sign(seed: bytes, message: bytes) -> bytes:
    """64-byte signature of `message` under the 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = 2 ** (_B - 2) + sum(2**i * _bit(h, i) for i in range(3, _B - 2))
    public = _encodepoint(_scalarmult(_BPOINT, a))
    r = _hint(h[32:] + message)
    rpoint = _scalarmult(_BPOINT, r)
    renc = _encodepoint(rpoint)
    s = (r + _hint(renc + public + message) * a) % _L
    return renc + _encodeint(s)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True if `signature` is a valid Ed25519 signature of `message`."""
    if len(public) != 32 or len(signature) != 64:
        return False
    p = _decodepoint(public)
    if p is None:
        return False
    r = _decodepoint(signature[:32])
    if r is None:
        return False
    s = _decodeint(signature[32:])
    if s >= _L:
        return False
    h = _hint(signature[:32] + public + message)
    # [S]B == R + [H]A
    sb = _scalarmult(_BPOINT, s)
    ha = _scalarmult(p, h)
    rhs = _edwards(r, ha)
    return sb == rhs

"""Code seed and deterministic byte stream for generator v2 (DESIGN.md §18.3).

A code seed is derived from the project secret, the Godot tag and ``key_epoch``.
It drives a deterministic stream (HKDF-SHA256 extract, then HMAC-SHA256 in
counter mode — standard library only). Same secret, tag, epoch and CODEGEN_VERSION
give a byte-identical stream, so two runs of the generator emit identical code.

The seed is an HKDF output, never the secret, the salt or the signing seed, and
nothing here reverses it: the stream only chooses operation kinds, orders, sizes
and padding for the generated routines. The values those routines hide are passed
in separately by the caller.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from fortressgd.core.kdf import hkdf_sha256
from fortressgd.core.secret import SECRET_BYTES

# Bump when the stream construction or the seed inputs change; it appears in the
# info string, so a bump changes every generated routine. Distinct from
# dialect.GENERATOR_VERSION, which versions the v1 data header's layout.
CODEGEN_VERSION = 2

_CODEGEN_PREFIX = "fortressgd.codegen.v{0}".format(CODEGEN_VERSION).encode("ascii")
_SEED_LEN = 32


def derive_code_seed(secret: bytes, godot_tag: str, key_epoch: int = 0) -> bytes:
    """32-byte code seed for (secret, tag, epoch, CODEGEN_VERSION).

    info = "fortressgd.codegen.v<N>|<tag>|epoch=<E>" (DESIGN.md §18.3).
    """
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    if type(key_epoch) is not int or key_epoch < 0:
        raise ValueError("key_epoch must be a non-negative integer")
    info = _CODEGEN_PREFIX + b"|" + godot_tag.encode("utf-8") + b"|epoch=" + str(key_epoch).encode("ascii")
    # Domain-separated salt so this never collides with the v1 header's HKDF uses.
    salt = hashlib.sha256(_CODEGEN_PREFIX + b"|seed-salt|" + godot_tag.encode("utf-8")).digest()
    return hkdf_sha256(secret, salt, info, _SEED_LEN)


class CodeStream:
    """Deterministic, unlimited byte stream keyed by a code seed.

    block(i) = HMAC-SHA256(code_seed, info + uint32_be(i)); blocks are concatenated
    and handed out in order. Not capped at HKDF's 255-block limit, because the
    generator may draw many kilobytes of choices. Purely deterministic: no OS
    randomness, no I/O.
    """

    def __init__(self, code_seed: bytes, info: bytes = b"") -> None:
        if len(code_seed) < 16:
            raise ValueError("code seed too short")
        self._seed = code_seed
        self._info = info
        self._counter = 0
        self._buf = b""

    def _refill(self) -> None:
        block = hmac.new(
            self._seed, self._info + struct.pack(">I", self._counter), hashlib.sha256
        ).digest()
        self._counter += 1
        if self._counter > 0xFFFFFFFF:
            raise RuntimeError("code stream exhausted")
        self._buf += block

    def read(self, n: int) -> bytes:
        """The next ``n`` bytes of the stream."""
        if n < 0:
            raise ValueError("n must be non-negative")
        while len(self._buf) < n:
            self._refill()
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def byte(self) -> int:
        """One byte as an int in [0, 256)."""
        return self.read(1)[0]

    def randbelow(self, n: int) -> int:
        """Uniform int in [0, n), rejection-sampled to avoid modulo bias."""
        if n <= 0:
            raise ValueError("n must be positive")
        if n == 1:
            return 0
        k = (n.bit_length() + 7) // 8  # bytes needed to cover n
        limit = (256**k // n) * n  # largest multiple of n that fits in k bytes
        while True:
            v = int.from_bytes(self.read(k), "big")
            if v < limit:
                return v % n

    def randrange(self, lo: int, hi: int) -> int:
        """Uniform int in [lo, hi] inclusive."""
        if hi < lo:
            raise ValueError("empty range")
        return lo + self.randbelow(hi - lo + 1)

    def shuffle(self, seq: list) -> None:
        """Fisher-Yates in place, drawing from the stream."""
        for i in range(len(seq) - 1, 0, -1):
            j = self.randbelow(i + 1)
            seq[i], seq[j] = seq[j], seq[i]

    def permutation(self, n: int) -> list:
        """A shuffled list(range(n))."""
        seq = list(range(n))
        self.shuffle(seq)
        return seq

    def choice(self, seq):
        """A uniformly chosen element of a non-empty sequence."""
        if not seq:
            raise ValueError("empty sequence")
        return seq[self.randbelow(len(seq))]

    def split_sizes(self, total: int, parts: int) -> list:
        """Split ``total`` into ``parts`` positive sizes summing to total.

        Deterministic: picks parts-1 distinct interior cut points in [1, total).
        Requires total >= parts.
        """
        if parts <= 0:
            raise ValueError("parts must be positive")
        if total < parts:
            raise ValueError("total must be at least parts")
        if parts == 1:
            return [total]
        cuts: set = set()
        while len(cuts) < parts - 1:
            cuts.add(self.randrange(1, total - 1))
        bounds = [0] + sorted(cuts) + [total]
        return [bounds[i + 1] - bounds[i] for i in range(parts)]

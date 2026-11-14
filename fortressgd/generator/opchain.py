"""Invertible byte-operation chains for generator v2 (DESIGN.md §18.3).

A value is stored encoded and recovered by a chain of invertible operations:
XOR, add mod 256, rotate, byte-position permutation and an 8-bit substitution.
A chain decodes ``stored`` back to the plaintext value; encoding runs the
inverse operations in reverse so that ``decode(encode(x)) == x`` for any x.

This module is the semantic core shared by two sides that the tests cross-check:

* the Python interpreter here (``decode_value``), and
* the C++ the emitter will generate from the same chain (added separately).

It is ordinary reversible encoding — the operations are a fixed grammar with no
data-driven loops, no I/O and no system calls. The chain itself is drawn from a
CodeStream, so it is deterministic for a given (secret, tag, epoch).

Each op also carries a ``form``: a small integer, also drawn from the stream,
that selects one of several equivalent C++ shapes for the same operation (a
forward or backward loop, a different but equal arithmetic expression, and so
on; DESIGN.md §18.3). The form never changes what the op computes, so the
interpreter here ignores it; only ``emit.py`` reads it, so the same operation on
the same length compiles to different machine code across builds. ``emit.py``
provides exactly ``OP_FORM_COUNTS[kind]`` realisations for each kind.
"""

from __future__ import annotations

from dataclasses import dataclass

from fortressgd.generator.codeseed import CodeStream


def _rotl8(x: int, r: int) -> int:
    return ((x << r) | (x >> (8 - r))) & 0xFF


def _rotr8(x: int, r: int) -> int:
    return ((x >> r) | (x << (8 - r))) & 0xFF


def _invert_perm(perm: tuple[int, ...]) -> tuple[int, ...]:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return tuple(inv)


class Op:
    """Base class. Subclasses define decode (stored->plain) and encode (its inverse)."""

    def decode(self, buf: list[int]) -> list[int]:  # pragma: no cover - abstract
        raise NotImplementedError

    def encode(self, buf: list[int]) -> list[int]:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class XorKey(Op):
    """Per-position XOR. Self-inverse."""

    key: bytes
    form: int = 0

    def decode(self, buf: list[int]) -> list[int]:
        return [b ^ self.key[i] for i, b in enumerate(buf)]

    encode = decode  # type: ignore[assignment]


@dataclass(frozen=True)
class AddKey(Op):
    """Per-position add mod 256 on decode; subtract on encode."""

    key: bytes
    form: int = 0

    def decode(self, buf: list[int]) -> list[int]:
        return [(b + self.key[i]) & 0xFF for i, b in enumerate(buf)]

    def encode(self, buf: list[int]) -> list[int]:
        return [(b - self.key[i]) & 0xFF for i, b in enumerate(buf)]


@dataclass(frozen=True)
class Rotate(Op):
    """Rotate each byte left by ``bits`` on decode; right on encode."""

    bits: int
    form: int = 0

    def decode(self, buf: list[int]) -> list[int]:
        return [_rotl8(b, self.bits) for b in buf]

    def encode(self, buf: list[int]) -> list[int]:
        return [_rotr8(b, self.bits) for b in buf]


@dataclass(frozen=True)
class PermPos(Op):
    """Permute byte positions: decode gathers plain[i] = stored[perm[i]]."""

    perm: tuple[int, ...]
    form: int = 0

    def decode(self, buf: list[int]) -> list[int]:
        return [buf[self.perm[i]] for i in range(len(buf))]

    def encode(self, buf: list[int]) -> list[int]:
        inv = _invert_perm(self.perm)
        return [buf[inv[i]] for i in range(len(buf))]


@dataclass(frozen=True)
class Sbox(Op):
    """8-bit substitution: decode maps through ``table`` (a 256-byte bijection)."""

    table: bytes
    form: int = 0

    def decode(self, buf: list[int]) -> list[int]:
        return [self.table[b] for b in buf]

    def encode(self, buf: list[int]) -> list[int]:
        inv = [0] * 256
        for v, t in enumerate(self.table):
            inv[t] = v
        return [inv[b] for b in buf]


OP_KINDS = ("xor", "add", "rot", "perm", "sbox")

# How many equivalent C++ forms ``emit.py`` can emit for each kind. ``build_chain``
# draws one of them per op; ``emit.py`` must provide exactly this many (a test
# asserts the two agree). Raising a count here, with matching realisations in
# ``emit.py``, further spreads the machine code builds produce for one operation.
OP_FORM_COUNTS = {
    "xor": 6,  # 3 loop shapes x 2 equal arithmetic expressions
    "add": 6,  # 3 loop shapes x 2 equal arithmetic expressions
    "rot": 4,  # 2 loop shapes x 2 operand orders
    "perm": 2,  # temp-array gather, forwards or backwards
    "sbox": 3,  # 3 loop shapes
}


def decode_value(stored: bytes, chain: list[Op]) -> bytes:
    """Run the chain forward: stored bytes -> plaintext value."""
    buf = list(stored)
    for op in chain:
        buf = op.decode(buf)
    return bytes(buf)


def encode_value(plain: bytes, chain: list[Op]) -> bytes:
    """Inverse of decode_value: plaintext value -> stored bytes."""
    buf = list(plain)
    for op in reversed(chain):
        buf = op.encode(buf)
    return bytes(buf)


def build_chain(stream: CodeStream, length: int, min_ops: int = 3, max_ops: int = 6) -> list[Op]:
    """A deterministic chain for a value of ``length`` bytes, drawn from ``stream``."""
    if length <= 0:
        raise ValueError("length must be positive")
    n_ops = stream.randrange(min_ops, max_ops)
    chain: list[Op] = []
    for _ in range(n_ops):
        kind = stream.choice(OP_KINDS)
        form = stream.randbelow(OP_FORM_COUNTS[kind])
        if kind == "xor":
            chain.append(XorKey(stream.read(length), form))
        elif kind == "add":
            chain.append(AddKey(stream.read(length), form))
        elif kind == "rot":
            chain.append(Rotate(stream.randrange(1, 7), form))
        elif kind == "perm":
            chain.append(PermPos(tuple(stream.permutation(length)), form))
        else:  # sbox
            chain.append(Sbox(bytes(stream.permutation(256)), form))
    return chain

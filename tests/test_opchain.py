"""Invertible op chains for generator v2 (DESIGN.md §18.3): round-trip + determinism."""

from __future__ import annotations

import os
import unittest

from fortressgd.generator.codeseed import CodeStream, derive_code_seed
from fortressgd.generator.opchain import (
    AddKey,
    OP_KINDS,
    PermPos,
    Rotate,
    Sbox,
    XorKey,
    build_chain,
    decode_value,
    encode_value,
)
from fortressgd.core.secret import SECRET_BYTES


class SingleOpRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.buf = bytes(range(16))

    def test_each_op_inverts(self) -> None:
        # gcd(181, 256) == 1, so i*181+17 mod 256 is a bijection of 0..255.
        sbox = bytes((i * 181 + 17) & 0xFF for i in range(256))
        self.assertEqual(len(set(sbox)), 256)
        ops = [
            XorKey(bytes(range(16))),
            AddKey(bytes((i * 7 + 3) & 0xFF for i in range(16))),
            Rotate(3),
            PermPos(tuple(reversed(range(16)))),
            Sbox(sbox),
        ]
        for op in ops:
            with self.subTest(op=type(op).__name__):
                self.assertEqual(op.encode(op.decode(list(self.buf))), list(self.buf))
                self.assertEqual(op.decode(op.encode(list(self.buf))), list(self.buf))


class ChainRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = derive_code_seed(bytes(range(SECRET_BYTES)), "4.7.2", 0)

    def test_random_chains_round_trip(self) -> None:
        for trial in range(100):
            length = (trial % 32) + 1
            stream = CodeStream(self.seed, b"chain|" + str(trial).encode())
            chain = build_chain(stream, length)
            plain = os.urandom(length)
            stored = encode_value(plain, chain)
            self.assertEqual(decode_value(stored, chain), plain)

    def test_chain_is_deterministic(self) -> None:
        a = build_chain(CodeStream(self.seed, b"k"), 32)
        b = build_chain(CodeStream(self.seed, b"k"), 32)
        self.assertEqual(a, b)

    def test_chain_uses_only_known_kinds(self) -> None:
        stream = CodeStream(self.seed, b"kinds")
        chain = build_chain(stream, 32, min_ops=6, max_ops=6)
        names = {
            XorKey: "xor",
            AddKey: "add",
            Rotate: "rot",
            PermPos: "perm",
            Sbox: "sbox",
        }
        for op in chain:
            self.assertIn(names[type(op)], OP_KINDS)

    def test_encode_differs_from_plain(self) -> None:
        # A non-trivial chain should actually change the bytes.
        stream = CodeStream(self.seed, b"diff")
        chain = build_chain(stream, 32, min_ops=4, max_ops=5)
        plain = bytes(range(32))
        self.assertNotEqual(encode_value(plain, chain), plain)

    def test_build_chain_rejects_bad_length(self) -> None:
        with self.assertRaises(ValueError):
            build_chain(CodeStream(self.seed), 0)


if __name__ == "__main__":
    unittest.main()

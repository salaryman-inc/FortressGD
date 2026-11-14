"""Invertible op chains for generator v2 (DESIGN.md §18.3): round-trip + determinism."""

from __future__ import annotations

import os
import unittest

from fortressgd.generator.codeseed import CodeStream, derive_code_seed
from fortressgd.generator.opchain import (
    AddKey,
    OP_FORM_COUNTS,
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


class FormTests(unittest.TestCase):
    """Each op carries a code form (DESIGN.md §18.3); it never changes the value."""

    def setUp(self) -> None:
        self.seed = derive_code_seed(bytes(range(SECRET_BYTES)), "4.7.2", 0)
        self.names = {XorKey: "xor", AddKey: "add", Rotate: "rot", PermPos: "perm", Sbox: "sbox"}

    def test_forms_stay_in_range(self) -> None:
        for trial in range(200):
            length = (trial % 20) + 1
            chain = build_chain(CodeStream(self.seed, b"range|%d" % trial), length)
            for op in chain:
                self.assertIn(op.form, range(OP_FORM_COUNTS[self.names[type(op)]]))

    def test_build_chain_covers_every_form(self) -> None:
        # Enough draws that every (kind, form) the grammar allows appears, and
        # each op the generator emits round-trips whatever its form.
        seen: set[tuple[str, int]] = set()
        for trial in range(4000):
            length = (trial % 20) + 1
            chain = build_chain(CodeStream(self.seed, b"cover|%d" % trial), length)
            plain = bytes((i * 29 + trial) & 0xFF for i in range(length))
            self.assertEqual(decode_value(encode_value(plain, chain), chain), plain)
            for op in chain:
                seen.add((self.names[type(op)], op.form))
        want = {(kind, form) for kind, n in OP_FORM_COUNTS.items() for form in range(n)}
        self.assertEqual(seen, want)

    def test_form_does_not_change_the_value(self) -> None:
        # The same op in two different forms decodes identically.
        buf = list(range(16))
        sbox = bytes((i * 181 + 17) & 0xFF for i in range(256))
        for a, b in (
            (XorKey(bytes(range(16)), 0), XorKey(bytes(range(16)), 5)),
            (AddKey(bytes(range(16)), 0), AddKey(bytes(range(16)), 5)),
            (Rotate(3, 0), Rotate(3, 3)),
            (PermPos(tuple(reversed(range(16))), 0), PermPos(tuple(reversed(range(16))), 1)),
            (Sbox(sbox, 0), Sbox(sbox, 2)),
        ):
            with self.subTest(op=type(a).__name__):
                self.assertEqual(a.decode(list(buf)), b.decode(list(buf)))

    def test_form_counts_match_the_emitter(self) -> None:
        from fortressgd.generator.emit import _FORMS

        self.assertEqual(set(_FORMS), set(OP_FORM_COUNTS))
        for kind, n in OP_FORM_COUNTS.items():
            self.assertEqual(len(_FORMS[kind]), n, kind)


if __name__ == "__main__":
    unittest.main()

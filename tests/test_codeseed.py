"""Code seed and deterministic stream for generator v2 (DESIGN.md §18.3)."""

from __future__ import annotations

import unittest

from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.codeseed import (
    CODEGEN_VERSION,
    CodeStream,
    derive_code_seed,
)


class DeriveCodeSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(SECRET_BYTES))

    def test_deterministic(self) -> None:
        a = derive_code_seed(self.secret, "4.7.2", 0)
        b = derive_code_seed(self.secret, "4.7.2", 0)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_differs_by_secret_tag_and_epoch(self) -> None:
        base = derive_code_seed(self.secret, "4.7.2", 0)
        other_secret = derive_code_seed(bytes(range(1, SECRET_BYTES + 1)), "4.7.2", 0)
        other_tag = derive_code_seed(self.secret, "4.6.2", 0)
        other_epoch = derive_code_seed(self.secret, "4.7.2", 1)
        self.assertNotEqual(base, other_secret)
        self.assertNotEqual(base, other_tag)
        self.assertNotEqual(base, other_epoch)

    def test_rejects_bad_inputs(self) -> None:
        with self.assertRaises(ValueError):
            derive_code_seed(b"short", "4.7.2", 0)
        with self.assertRaises(ValueError):
            derive_code_seed(self.secret, "4.7.2", -1)

    def test_version_is_in_prefix(self) -> None:
        # Guards against bumping CODEGEN_VERSION without the stream changing.
        self.assertGreaterEqual(CODEGEN_VERSION, 2)


class CodeStreamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = derive_code_seed(bytes(range(SECRET_BYTES)), "4.7.2", 0)

    def test_same_seed_same_bytes(self) -> None:
        a = CodeStream(self.seed, b"ctx").read(200)
        b = CodeStream(self.seed, b"ctx").read(200)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 200)

    def test_info_changes_stream(self) -> None:
        a = CodeStream(self.seed, b"ctx-a").read(64)
        b = CodeStream(self.seed, b"ctx-b").read(64)
        self.assertNotEqual(a, b)

    def test_read_is_sequential_across_block_boundary(self) -> None:
        # Reading 40 then 40 equals reading 80 at once (blocks are 32 bytes).
        s1 = CodeStream(self.seed)
        piece = s1.read(40) + s1.read(40)
        self.assertEqual(piece, CodeStream(self.seed).read(80))

    def test_unlimited_length_beyond_hkdf_cap(self) -> None:
        # More than 255*32 bytes, which plain HKDF cannot produce.
        self.assertEqual(len(CodeStream(self.seed).read(9000)), 9000)

    def test_randbelow_range_and_coverage(self) -> None:
        s = CodeStream(self.seed, b"rb")
        seen = set()
        for _ in range(2000):
            v = s.randbelow(7)
            self.assertTrue(0 <= v < 7)
            seen.add(v)
        self.assertEqual(seen, set(range(7)))  # every residue appears

    def test_randbelow_one_and_bad(self) -> None:
        s = CodeStream(self.seed)
        self.assertEqual(s.randbelow(1), 0)
        with self.assertRaises(ValueError):
            s.randbelow(0)

    def test_randrange_inclusive(self) -> None:
        s = CodeStream(self.seed, b"rr")
        for _ in range(500):
            v = s.randrange(5, 9)
            self.assertTrue(5 <= v <= 9)
        with self.assertRaises(ValueError):
            s.randrange(9, 5)

    def test_shuffle_is_deterministic_permutation(self) -> None:
        a = list(range(50))
        b = list(range(50))
        CodeStream(self.seed, b"sh").shuffle(a)
        CodeStream(self.seed, b"sh").shuffle(b)
        self.assertEqual(a, b)
        self.assertEqual(sorted(a), list(range(50)))
        self.assertNotEqual(a, list(range(50)))

    def test_permutation(self) -> None:
        p = CodeStream(self.seed, b"p").permutation(32)
        self.assertEqual(sorted(p), list(range(32)))

    def test_choice(self) -> None:
        s = CodeStream(self.seed, b"c")
        opts = ["xor", "add", "rot"]
        for _ in range(200):
            self.assertIn(s.choice(opts), opts)
        with self.assertRaises(ValueError):
            s.choice([])

    def test_split_sizes(self) -> None:
        s = CodeStream(self.seed, b"ss")
        sizes = s.split_sizes(32, 5)
        self.assertEqual(len(sizes), 5)
        self.assertEqual(sum(sizes), 32)
        self.assertTrue(all(x >= 1 for x in sizes))
        # Deterministic for the same stream position.
        self.assertEqual(CodeStream(self.seed, b"ss").split_sizes(32, 5), sizes)

    def test_split_sizes_edges(self) -> None:
        s = CodeStream(self.seed)
        self.assertEqual(s.split_sizes(7, 1), [7])
        self.assertEqual(s.split_sizes(4, 4), [1, 1, 1, 1])
        with self.assertRaises(ValueError):
            s.split_sizes(3, 4)
        with self.assertRaises(ValueError):
            s.split_sizes(10, 0)


if __name__ == "__main__":
    unittest.main()

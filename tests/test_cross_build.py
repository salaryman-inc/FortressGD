"""The cross-build check's own logic (tests/cross_build.py, DESIGN.md §18.7).

The e2e workflow runs the check on real templates. These tests cover what it
relies on without a Godot build: parsing generated sources, the reference
extractor on compiled objects, the binary section parser and the instruction
comparison.
"""

from __future__ import annotations

import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.secret import SECRET_BYTES
from fortressgd.generator.generate import plaintext_values, render_gen_cpp
from tests.cross_build import (
    ExtractionFailed,
    Insn,
    _normalize,
    extract,
    file_to_va,
    longest_shared_run,
    parse_gen_cpp,
    sections,
    train,
)

_API_DIR = Path(__file__).resolve().parents[1] / "fortressgd" / "patches" / "common"
_CXX = next((c for c in ("g++", "clang++", "c++") if shutil.which(c)), None)


def _secret(n: int) -> bytes:
    return bytes((n * 37 + i * 11) & 0xFF for i in range(SECRET_BYTES))


class ParseTests(unittest.TestCase):
    def test_source_decodes_to_the_key(self) -> None:
        for n in range(12):
            for epoch in (0, 1, 7):
                secret = _secret(n)
                src = parse_gen_cpp(render_gen_cpp(secret, "4.7.2", key_epoch=epoch))
                key = bytearray(32)
                covered = 0
                for name, ofs in src.key_pieces:
                    fn = src.functions[name]
                    key[ofs : ofs + fn.length] = fn.decode(fn.arrays)
                    covered += fn.length
                self.assertEqual(covered, 32)
                self.assertEqual(bytes(key), plaintext_values(secret, "4.7.2", key_epoch=epoch)["key"])

    def test_every_chain_op_is_parsed(self) -> None:
        # Each chain array (k, p, s) is one op, and so is each rotate line.
        text = render_gen_cpp(_secret(3), "4.6.2")
        src = parse_gen_cpp(text)
        for fn in src.functions.values():
            body = text[text.index("static void {0}(".format(fn.name)) :]
            body = body[: body.index("\n}\n")]
            rotates = body.count("<< ")
            self.assertEqual(len(fn.ops), len(fn.arrays) - 1 + rotates, fn.name)

    def test_rejects_text_without_key_pieces(self) -> None:
        with self.assertRaises(ValueError):
            parse_gen_cpp("static void fgd__magic(uint8_t out[4]) {\n}\n")


def _synthetic_binary(src, filler: bytes, order_seed: int) -> bytes:
    """Each function's arrays together, functions apart, as a compiler lays out .rodata."""
    out = bytearray(filler)
    names = [n for n, _ in src.key_pieces]
    names = names[order_seed % len(names) :] + names[: order_seed % len(names)]
    for name in names:
        for data in src.functions[name].arrays.values():
            out += data + b"\0" * (16 - len(data) % 16)
        out += filler
    return bytes(out)


class ExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.a = parse_gen_cpp(render_gen_cpp(_secret(1), "4.7.2"))
        self.b = parse_gen_cpp(render_gen_cpp(_secret(2), "4.7.2"))
        self.a1 = parse_gen_cpp(render_gen_cpp(_secret(1), "4.7.2", key_epoch=1))
        self.key_a = plaintext_values(_secret(1), "4.7.2")["key"]

    def test_synthetic_layout(self) -> None:
        bin_a = _synthetic_binary(self.a, b"\xcc" * 300, 0)
        profile = train(bin_a, self.a, self.key_a)
        self.assertEqual(extract(bin_a, profile), self.key_a)
        # The same build at another place in the file still extracts.
        self.assertEqual(extract(b"\x90" * 1000 + bin_a, profile), self.key_a)
        for other in (self.b, self.a1):
            with self.assertRaises(ExtractionFailed):
                extract(_synthetic_binary(other, b"\xcc" * 300, 0), profile)

    def test_short_piece_among_random_bytes(self) -> None:
        # e2e run 42988550466: a key piece whose arrays were all 1-2 bytes long
        # matched 113 places in the template. Training must still place it.
        rng = random.Random(5)
        for n in range(200):
            secret = _secret(100 + n)
            src = parse_gen_cpp(render_gen_cpp(secret, "4.7.2"))
            if any(max(len(a) for a in src.functions[name].arrays.values()) <= 2 for name, _ in src.key_pieces):
                break
        else:  # pragma: no cover - the seeds above contain one
            self.fail("no secret with a short key piece")
        key = plaintext_values(secret, "4.7.2")["key"]
        noise = bytes(rng.randrange(256) for _ in range(4096))
        binary = _synthetic_binary(src, noise, 1)
        with self.assertRaises(ValueError):
            train(binary, src)  # ambiguous without the key
        profile = train(binary, src, key)
        self.assertEqual(extract(binary, profile), key)
        self.assertEqual(extract(noise + binary, profile), key)

    @unittest.skipUnless(_CXX, "no C++ compiler on PATH")
    def test_compiled_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            objs = {}
            for label, secret, epoch in (("a", _secret(1), 0), ("b", _secret(2), 0), ("a1", _secret(1), 1)):
                cpp = Path(tmp) / (label + ".cpp")
                cpp.write_text(render_gen_cpp(secret, "4.7.2", key_epoch=epoch), encoding="utf-8")
                obj = Path(tmp) / (label + ".o")
                subprocess.run(
                    [_CXX, "-std=c++17", "-O2", "-c", "-I", str(_API_DIR), str(cpp), "-o", str(obj)],
                    check=True,
                )
                objs[label] = obj.read_bytes()
            profile = train(objs["a"], self.a, self.key_a)
            self.assertEqual(extract(objs["a"], profile), self.key_a)
            for label in ("b", "a1"):
                with self.assertRaises(ExtractionFailed, msg=label):
                    extract(objs[label], profile)


def _elf(sections_spec: list[tuple[str, int, int, bytes]]) -> bytes:
    """A minimal ELF64 with the given (name, type, addr, data) sections."""
    names = b"\0" + b"".join(n.encode() + b"\0" for n, *_ in sections_spec) + b".shstrtab\0"
    body = bytearray(b"\0" * 64)
    offsets = []
    for _, _, _, data in sections_spec:
        offsets.append(len(body))
        body += data
    shstr_off = len(body)
    body += names
    shoff = len(body)
    hdr = bytearray(b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9)
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(sections_spec) + 2, len(sections_spec) + 1)
    body[:64] = hdr
    body += b"\0" * 64  # null section
    pos = 1
    for (name, typ, addr, data), off in zip(sections_spec, offsets):
        body += struct.pack("<IIQQQQIIQQ", pos, typ, 0, addr, off, len(data), 0, 0, 1, 0)
        pos += len(name) + 1
    body += struct.pack("<IIQQQQIIQQ", pos, 3, 0, 0, shstr_off, len(names), 0, 0, 1, 0)
    return bytes(body)


class SectionTests(unittest.TestCase):
    def test_elf_sections_and_addresses(self) -> None:
        data = _elf([(".text", 1, 0x401000, b"\x90" * 32), (".rodata", 1, 0x402000, b"KEYBYTES"), (".bss", 8, 0x403000, b"")])
        secs = {s.name: s for s in sections(data)}
        self.assertEqual(set(secs), {".text", ".rodata", ".shstrtab"})
        off = data.index(b"KEYBYTES")
        self.assertEqual(file_to_va(sections(data), off + 3), 0x402003)

    def test_rejects_other_files(self) -> None:
        with self.assertRaises(ValueError):
            sections(b"not a binary at all")


class CompareTests(unittest.TestCase):
    def test_normalize_masks_addresses(self) -> None:
        text, target = _normalize("movzbl 0x1f3b2(%rip),%eax        # 4a3c10 <foo+0x10>")
        self.assertEqual(text, "movzbl X(%rip),%eax")
        self.assertEqual(target, 0x4A3C10)
        text, target = _normalize("jmp    0x142bff766")
        self.assertEqual((text, target), ("jmp T", 0x142BFF766))
        text, target = _normalize("call   401230 <bar>")
        self.assertEqual((text, target), ("call T", 0x401230))
        self.assertEqual(_normalize("xor    %eax,%eax")[0], "xor %eax,%eax")

    def test_longest_shared_run(self) -> None:
        def run(*texts):
            return [Insn(0x1000 + i * 4, 4, t, None) for i, t in enumerate(texts)]

        a = [run("a", "b", "c", "d", "e")]
        b = [run("x", "b", "c", "d", "y"), run("a")]
        n, nbytes, texts = longest_shared_run(a, b)
        self.assertEqual((n, nbytes, texts), (3, 12, ["b", "c", "d"]))
        self.assertEqual(longest_shared_run(a, [run("z")])[0], 0)


if __name__ == "__main__":
    unittest.main()

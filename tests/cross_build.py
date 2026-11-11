"""Cross-build check for generator v2 (DESIGN.md §18.7).

Two parts, both run by the e2e workflow on real templates:

1. A reference extractor. It is what a FortressGD-aware tool written against one
   build would do: given build A's generated source (fortressgd_gen.cpp) and A's
   template, it learns where A's key pieces and their decode constants sit in the
   binary, then on a target binary finds the same bytes, reads the arrays at the
   same relative offsets and decodes them with A's operation chain. It must
   recover A's key from A, and fail on a build with another secret or epoch.

2. A machine-code comparison. In each template it finds the instructions that
   load that build's key arrays (from the build's own source), takes the code
   around them, and measures the longest run of instructions two builds share,
   with addresses and branch targets masked out. It must stay under a threshold.

These show that builds differ. They do not show that a static extractor for
builds in general is impossible (§18.7).

The extractor reads only the generated source text, never the generator.
"""

from __future__ import annotations

import argparse
import bisect
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- source parsing

_FN = re.compile(r"^static void (fgd__\w+)\(uint8_t out\[(\d+)\]\) \{$")
_ARRAY = re.compile(r"^\tstatic const volatile uint8_t (\w+)\[(\d+)\] = \{ ([0-9a-fx, ]*) \};$")
_XOR = re.compile(r"^\tfor \(int i = 0; i < \d+; i\+\+\) b\[i\] = \(uint8_t\)\(b\[i\] \^ (\w+)\[i\]\);$")
_ADD = re.compile(r"^\tfor \(int i = 0; i < \d+; i\+\+\) b\[i\] = \(uint8_t\)\(b\[i\] \+ (\w+)\[i\]\);$")
_ROT = re.compile(r"^\tfor \(int i = 0; i < \d+; i\+\+\) b\[i\] = \(uint8_t\)\(\(b\[i\] << (\d)\) \| \(b\[i\] >> \d\)\);$")
_PERM = re.compile(r"^\t\tfor \(int i = 0; i < \d+; i\+\+\) t\[i\] = b\[(\w+)\[i\]\];$")
_SBOX = re.compile(r"^\tfor \(int i = 0; i < \d+; i\+\+\) b\[i\] = (\w+)\[b\[i\]\];$")
_PIECE_CALL = re.compile(r"^\t(fgd__k\d+)\(r_key \+ (\d+)\);$")


class ExtractionFailed(Exception):
    """The extractor did not find build A's layout in the target binary."""


@dataclass
class DecodeFn:
    name: str
    length: int
    arrays: dict[str, bytes] = field(default_factory=dict)
    ops: list[tuple[str, object]] = field(default_factory=list)  # (kind, array name or rotate bits)

    def decode(self, arrays: dict[str, bytes]) -> bytes:
        """Run the chain on ``arrays`` (A's names, the target's bytes)."""
        b = bytearray(arrays["enc"])
        for kind, arg in self.ops:
            if kind == "xor":
                k = arrays[arg]
                b = bytearray(x ^ y for x, y in zip(b, k))
            elif kind == "add":
                k = arrays[arg]
                b = bytearray((x + y) & 0xFF for x, y in zip(b, k))
            elif kind == "rot":
                r = int(arg)
                b = bytearray(((x << r) | (x >> (8 - r))) & 0xFF for x in b)
            elif kind == "perm":
                p = arrays[arg]
                b = bytearray(b[i] for i in p)
            elif kind == "sbox":
                s = arrays[arg]
                b = bytearray(s[x] for x in b)
            else:  # pragma: no cover
                raise ValueError(kind)
        return bytes(b)


@dataclass
class GenSource:
    functions: dict[str, DecodeFn]
    key_pieces: list[tuple[str, int]]  # (function, offset in the key), in call order

    def key_arrays(self) -> list[bytes]:
        return [a for name, _ in self.key_pieces for a in self.functions[name].arrays.values()]


def parse_gen_cpp(text: str) -> GenSource:
    """Parse the generated decode functions and fgd_derive_key's piece order."""
    functions: dict[str, DecodeFn] = {}
    pieces: list[tuple[str, int]] = []
    cur: DecodeFn | None = None
    in_derive = False
    for line in text.splitlines():
        m = _FN.match(line)
        if m:
            cur = DecodeFn(m.group(1), int(m.group(2)))
            functions[cur.name] = cur
            continue
        if line.startswith("void fgd_derive_key("):
            in_derive = True
            continue
        if line == "}":
            cur = None
            in_derive = False
            continue
        if in_derive:
            m = _PIECE_CALL.match(line)
            if m:
                pieces.append((m.group(1), int(m.group(2))))
            continue
        if cur is None:
            continue
        m = _ARRAY.match(line)
        if m:
            data = bytes(int(x, 16) for x in m.group(3).split(", ")) if m.group(3) else b""
            if len(data) != int(m.group(2)):
                raise ValueError("array {0} in {1}: wrong length".format(m.group(1), cur.name))
            cur.arrays[m.group(1)] = data
            continue
        for kind, pat in (("xor", _XOR), ("add", _ADD), ("rot", _ROT), ("perm", _PERM), ("sbox", _SBOX)):
            m = pat.match(line)
            if m:
                cur.ops.append((kind, m.group(1)))
                break
    if not pieces:
        raise ValueError("no key pieces in fgd_derive_key")
    for name, _ in pieces:
        if name not in functions or "enc" not in functions[name].arrays:
            raise ValueError("key piece {0} not parsed".format(name))
    return GenSource(functions, pieces)


# ---------------------------------------------------------------- the extractor


def _find_all(data: bytes, needle: bytes) -> list[int]:
    out = []
    i = data.find(needle)
    while i != -1:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


@dataclass
class PieceProfile:
    fn: DecodeFn
    offset: int  # in the key
    anchor: bytes  # A's longest array of this piece
    rel: dict[str, int]  # array name -> file offset relative to the anchor


@dataclass
class Profile:
    pieces: list[PieceProfile]


def train(binary_a: bytes, source_a: GenSource) -> Profile:
    """Learn build A's layout from A's binary and A's generated source."""
    profiles = []
    for name, ofs in source_a.key_pieces:
        fn = source_a.functions[name]
        anchor_name = max(fn.arrays, key=lambda n: len(fn.arrays[n]))
        anchor = fn.arrays[anchor_name]
        hits = _find_all(binary_a, anchor)
        if len(hits) != 1:
            raise ValueError("{0}.{1} found {2} times in build A".format(name, anchor_name, len(hits)))
        base = hits[0]
        rel = {}
        for arr_name, data in fn.arrays.items():
            # Each array must sit near the anchor, where the compiler put this
            # function's constants.
            near = [h for h in _find_all(binary_a, data) if abs(h - base) < 65536]
            if not near:
                raise ValueError("{0}.{1} not found near its anchor in build A".format(name, arr_name))
            rel[arr_name] = min(near, key=lambda h: abs(h - base)) - base
        profiles.append(PieceProfile(fn, ofs, anchor, rel))
    return Profile(profiles)


def extract(binary: bytes, profile: Profile) -> bytes:
    """Recover a 32-byte key from ``binary`` the way build A stores it."""
    key = bytearray(32)
    for p in profile.pieces:
        hits = _find_all(binary, p.anchor)
        if len(hits) != 1:
            raise ExtractionFailed(
                "{0}: build A's anchor array found {1} times".format(p.fn.name, len(hits))
            )
        base = hits[0]
        arrays = {}
        for arr_name, r in p.rel.items():
            start = base + r
            length = len(p.fn.arrays[arr_name])
            if start < 0 or start + length > len(binary):
                raise ExtractionFailed("{0}.{1}: offset outside the binary".format(p.fn.name, arr_name))
            arrays[arr_name] = binary[start : start + length]
        key[p.offset : p.offset + p.fn.length] = p.fn.decode(arrays)
    return bytes(key)


# ---------------------------------------------------------------- binaries


@dataclass
class Section:
    name: str
    va: int
    offset: int
    size: int


def sections(data: bytes) -> list[Section]:
    """File-backed sections of an x86-64 ELF or PE32+ binary."""
    if data[:4] == b"\x7fELF":
        if data[4] != 2 or data[5] != 1:
            raise ValueError("only little-endian ELF64 is supported")
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
        strtab = raw[shstrndx]
        out = []
        for sh in raw:
            name_off, sh_type, _flags, addr, offset, size = sh[:6]
            if sh_type == 8 or size == 0:  # SHT_NOBITS
                continue
            s = strtab[4] + name_off
            name = data[s : data.index(b"\0", s)].decode("ascii", "replace")
            out.append(Section(name, addr, offset, size))
        return out
    if data[:2] == b"MZ":
        pe, = struct.unpack_from("<I", data, 0x3C)
        if data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        nsec, = struct.unpack_from("<H", data, pe + 6)
        opt_size, = struct.unpack_from("<H", data, pe + 20)
        opt = pe + 24
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("only PE32+ is supported")
        image_base, = struct.unpack_from("<Q", data, opt + 24)
        out = []
        for i in range(nsec):
            sh = pe + 24 + opt_size + i * 40
            name = data[sh : sh + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", data, sh + 8)
            if rawsize:
                out.append(Section(name, image_base + rva, rawptr, min(vsize, rawsize) or rawsize))
        return out
    raise ValueError("not an ELF or PE binary")


def file_to_va(secs: list[Section], offset: int) -> int:
    for s in secs:
        if s.offset <= offset < s.offset + s.size:
            return s.va + (offset - s.offset)
    raise ValueError("offset {0:#x} is in no section".format(offset))


# ---------------------------------------------------------------- code comparison

_INSN = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$")
_RIP_COMMENT = re.compile(r"#\s*(?:0x)?([0-9a-f]+)")
_HEX = re.compile(r"0x[0-9a-f]+")


@dataclass
class Insn:
    va: int
    size: int
    text: str  # normalized
    target: int | None  # RIP-relative or branch target


def _normalize(asm: str) -> tuple[str, int | None]:
    target = None
    m = _RIP_COMMENT.search(asm)
    if m:
        target = int(m.group(1), 16)
    asm = asm.split("#", 1)[0].strip()
    asm = re.sub(r"<[^>]*>", "", asm).strip()
    parts = asm.split(None, 1)
    if not parts:
        return "", target
    mnem = parts[0]
    ops = parts[1] if len(parts) > 1 else ""
    # Branches and calls: the target is an address.
    if mnem.startswith("j") or mnem.startswith("call") or mnem.startswith("loop"):
        m = re.fullmatch(r"(?:0x)?([0-9a-f]+)", ops.strip())
        if m:
            target = int(m.group(1), 16)
            ops = "T"
    # RIP-relative displacements are addresses too.
    ops = re.sub(r"-?0x[0-9a-f]+\(%rip\)", "X(%rip)", ops)
    return (mnem + " " + ops).strip(), target


def disassemble(path: Path, objdump: str, start: int | None = None, stop: int | None = None):
    """Yield the binary's instructions via GNU objdump (AT&T syntax), one at a time."""
    cmd = [objdump, "-d", "-w"]
    if start is not None:
        cmd.append("--start-address={0:#x}".format(start))
    if stop is not None:
        cmd.append("--stop-address={0:#x}".format(stop))
    proc = subprocess.Popen(cmd + [str(path)], stdout=subprocess.PIPE, text=True, errors="replace")
    assert proc.stdout is not None
    for line in proc.stdout:
        m = _INSN.match(line)
        if not m:
            continue
        text, target = _normalize(m.group(3))
        yield Insn(int(m.group(1), 16), len(m.group(2).split()), text, target)
    if proc.wait() != 0:
        raise RuntimeError("{0} failed on {1}".format(objdump, path))


def key_arrays_va(binary: bytes, source: GenSource) -> list[tuple[int, int]]:
    """[start, end) addresses of this build's key-piece arrays, from its own source."""
    secs = sections(binary)
    ranges = []
    # train() places each array next to its function's anchor, so a short array
    # never matches stray bytes elsewhere in the file.
    for p in train(binary, source).pieces:
        base = _find_all(binary, p.anchor)[0]
        for arr_name, r in p.rel.items():
            va = file_to_va(secs, base + r)
            ranges.append((va, va + len(p.fn.arrays[arr_name])))
    return sorted(ranges)


def key_code(path: Path, binary: bytes, source: GenSource, objdump: str, *, gap: int = 512) -> list[list[Insn]]:
    """The machine code that handles this build's key, as runs of instructions.

    One pass over the whole disassembly finds every instruction that addresses one
    of the build's key arrays. Hits closer than ``gap`` bytes are one routine, which
    runs from its first array access to its last; a second, narrow objdump call
    returns its instructions. Nothing else of the binary is kept in memory.
    """
    ranges = key_arrays_va(binary, source)
    if not ranges:
        raise ValueError("no key arrays found in the binary")
    starts = [r[0] for r in ranges]
    spans: list[list[int]] = []
    for ins in disassemble(path, objdump):
        t = ins.target
        if t is None:
            continue
        j = bisect.bisect_right(starts, t) - 1
        if j >= 0 and ranges[j][0] <= t < ranges[j][1]:
            if spans and ins.va - spans[-1][1] <= gap:
                spans[-1][1] = ins.va + ins.size
            else:
                spans.append([ins.va, ins.va + ins.size])
    if not spans:
        raise ValueError("no instruction addresses the key arrays")
    return [list(disassemble(path, objdump, lo, hi)) for lo, hi in spans]


def longest_shared_run(a: list[list[Insn]], b: list[list[Insn]]) -> tuple[int, int, list[str]]:
    """Longest run of identical normalized instructions between any window of a and of b.

    Returns (instructions, bytes in a, the run's text).
    """
    best = (0, 0, [])
    for wa in a:
        ta = [i.text for i in wa]
        for wb in b:
            tb = [i.text for i in wb]
            prev = [0] * (len(tb) + 1)
            for x in range(1, len(ta) + 1):
                cur = [0] * (len(tb) + 1)
                ax = ta[x - 1]
                for y in range(1, len(tb) + 1):
                    if ax == tb[y - 1]:
                        n = prev[y - 1] + 1
                        cur[y] = n
                        if n > best[0]:
                            run = wa[x - n : x]
                            best = (n, sum(i.size for i in run), [i.text for i in run])
                prev = cur
    return best


# ---------------------------------------------------------------- CLI


def _load(spec: str):
    """template=PATH,secret=FILE,epoch=N"""
    parts = dict(p.split("=", 1) for p in spec.split(","))
    return Path(parts["template"]), Path(parts["secret"]), int(parts.get("epoch", "0"))


def _source(godot: str, secret_file: Path, epoch: int) -> str:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from fortressgd.core.secret import read_secret_file, secret_bytes_from_hex
    from fortressgd.core.templates import concrete_godot_tag
    from fortressgd.generator.generate import render_gen_cpp

    secret = secret_bytes_from_hex(read_secret_file(secret_file))
    return render_gen_cpp(secret, concrete_godot_tag(godot), key_epoch=epoch)


def _expected_key(godot: str, secret_file: Path, epoch: int) -> bytes:
    from fortressgd.core.secret import read_secret_file, secret_bytes_from_hex
    from fortressgd.core.templates import concrete_godot_tag
    from fortressgd.generator.generate import plaintext_values

    secret = secret_bytes_from_hex(read_secret_file(secret_file))
    return plaintext_values(secret, concrete_godot_tag(godot), key_epoch=epoch)["key"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tests.cross_build")
    ap.add_argument("--godot", required=True)
    ap.add_argument("--a", required=True, help="template=PATH,secret=FILE[,epoch=N]: build A")
    ap.add_argument("--other", action="append", required=True, help="the same, for each other build")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--max-shared", type=int, required=True, help="most instructions two builds' key code may share")
    ap.add_argument("--summary", help="append a Markdown report here")
    args = ap.parse_args(argv)

    report: list[str] = []
    failed = False

    a_path, a_secret, a_epoch = _load(args.a)
    a_bin = a_path.read_bytes()
    a_src = parse_gen_cpp(_source(args.godot, a_secret, a_epoch))
    profile = train(a_bin, a_src)
    got = extract(a_bin, profile)
    if got != _expected_key(args.godot, a_secret, a_epoch):
        print("error: the reference extractor did not recover build A's key from build A", file=sys.stderr)
        return 1
    report.append("- Reference extractor for build A recovers A's key from A ({0} pieces).".format(len(profile.pieces)))

    a_code = key_code(a_path, a_bin, a_src, args.objdump)
    # Control: A against itself shares all of its key code, so the measure is not
    # passing because it finds nothing to compare.
    n_self, bytes_self, _ = longest_shared_run(a_code, a_code)
    if n_self <= args.max_shared:
        print("error: build A's key code is only {0} instructions; the comparison would prove nothing".format(n_self), file=sys.stderr)
        return 1
    report.append("- Control: build A's key code is {0} instructions ({1} bytes) in {2} run(s).".format(
        n_self, bytes_self, len(a_code)))
    for spec in args.other:
        path, secret, epoch = _load(spec)
        label = "{0} (epoch {1})".format(path.name, epoch)
        data = path.read_bytes()
        try:
            key = extract(data, profile)
        except ExtractionFailed as exc:
            report.append("- {0}: the extractor fails ({1}).".format(label, exc))
        else:
            if key == _expected_key(args.godot, secret, epoch):
                print("error: build A's extractor recovered the key of {0}".format(label), file=sys.stderr)
                failed = True
            report.append("- {0}: the extractor returns bytes that are not the key.".format(label))
        src = parse_gen_cpp(_source(args.godot, secret, epoch))
        code = key_code(path, data, src, args.objdump)
        n, nbytes, run = longest_shared_run(a_code, code)
        report.append(
            "- {0}: longest key-code instruction run shared with A: {1} instructions ({2} bytes); limit {3}.".format(
                label, n, nbytes, args.max_shared
            )
        )
        # The shared run goes to the log either way, so a near miss can be read.
        print("{0}: the longest run shared with A:".format(label))
        for t in run:
            print("    " + t)
        if n > args.max_shared:
            print("error: {0} shares {1} key-code instructions with A".format(label, n), file=sys.stderr)
            failed = True
    text = "\n".join(report)
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write("### Cross-build check (Godot {0})\n\n{1}\n\n".format(args.godot, text))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

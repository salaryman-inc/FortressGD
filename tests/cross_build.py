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
import itertools
import re
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------- source parsing

_FN = re.compile(r"^static void (fgd__\w+)\(uint8_t out\[(\d+)\]\) \{$")
_ARRAY = re.compile(r"^\tstatic const volatile uint8_t (\w+)\[(\d+)\] = \{ ([0-9a-fx, ]*) \};$")
_PIECE_CALL = re.compile(r"^\t(fgd__k\d+)\(r_key \+ (\d+)\);$")

# Generator v3 emits each operation in one of several equal forms (emit.py): the
# loop may run forwards, backwards or two-at-a-time, and an op may use an equal
# arithmetic expression. The loop header does not change what the op is, so these
# patterns match an operation by the per-element body it contains (``.search``,
# anchored on ``b[i]``), which is the same whichever way the loop runs. A
# grammar-aware tool would recognise exactly this fixed set of shapes. Each kind
# has one pattern per arithmetic form; the (xor|add) pairs are the two equal
# expressions emit.py chooses between, and the two rotate patterns are its two
# operand orders.
_OP_PATTERNS = (
    ("xor", re.compile(r"b\[i\] = \(uint8_t\)\(b\[i\] \^ (\w+)\[i\]\);")),
    ("xor", re.compile(r"b\[i\] = \(uint8_t\)\(\(b\[i\] \| (\w+)\[i\]\) - \(b\[i\] & \w+\[i\]\)\);")),
    ("add", re.compile(r"b\[i\] = \(uint8_t\)\(b\[i\] \+ (\w+)\[i\]\);")),
    ("add", re.compile(r"b\[i\] = \(uint8_t\)\(b\[i\] - \(uint8_t\)\(-(\w+)\[i\]\)\);")),
    ("rot", re.compile(r"b\[i\] = \(uint8_t\)\(\(b\[i\] << (\d)\) \| \(b\[i\] >> \d\)\);")),
    ("rot", re.compile(r"b\[i\] = \(uint8_t\)\(\(b\[i\] >> \d\) \| \(b\[i\] << (\d)\)\);")),
    ("perm", re.compile(r"t\[i\] = b\[(\w+)\[i\]\];")),
    ("sbox", re.compile(r"b\[i\] = (\w+)\[b\[i\]\];")),
)


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
    seen: set[str] = set()  # arrays already turned into an op, within cur
    in_derive = False
    for line in text.splitlines():
        m = _FN.match(line)
        if m:
            cur = DecodeFn(m.group(1), int(m.group(2)))
            functions[cur.name] = cur
            seen = set()
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
        for kind, pat in _OP_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            arg = m.group(1)
            if kind == "rot":
                # No array; each rotate is one line, so record every one.
                cur.ops.append((kind, arg))
            elif arg not in seen:
                # One op per array: an unrolled loop repeats the body on several
                # lines, all reading the same array, so record only the first.
                cur.ops.append((kind, arg))
                seen.add(arg)
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
    rel: dict[str, int]  # array name -> file offset relative to the profile's anchor
    certain: frozenset[str] = frozenset()  # arrays that occur once near the anchor


@dataclass
class Profile:
    anchor: bytes  # A's longest key array that occurs once in A's binary
    pieces: list[PieceProfile]


# How far from the anchor A's key arrays may sit, and how many placements of one
# piece's short arrays training may try before it gives up.
_WINDOW = 1 << 20
_MARGIN = 8192
_NEAREST = 48
_MAX_COMBOS = 2_000_000


def train(binary_a: bytes, source_a: GenSource, key_a: bytes | None = None) -> Profile:
    """Learn build A's layout from A's binary and A's generated source.

    The anchor is the longest of A's key arrays that occurs exactly once in A,
    usually a 256-byte substitution table. Every other array is placed relative to
    it. A short array (a piece can be one byte long) also occurs by chance near the
    anchor; with ``key_a``, the author of the extractor checks it against build A,
    so training keeps the placement of each piece that decodes to A's key.
    """
    arrays = [
        (len(data), name, arr_name, data)
        for name, _ in source_a.key_pieces
        for arr_name, data in source_a.functions[name].arrays.items()
    ]
    anchor = None
    for _, name, arr_name, data in sorted(arrays, reverse=True):
        hits = _find_all(binary_a, data)
        if len(hits) == 1:
            anchor, base = data, hits[0]
            break
    if anchor is None:
        raise ValueError("no key array of build A occurs exactly once in build A")

    # Arrays that occur once near the anchor are placed for certain. The compiler
    # keeps one translation unit's constants together, so the short arrays are
    # looked for only in the area those span, nearest their own piece first.
    near: dict[tuple[str, str], list[int]] = {}
    for name, _ in source_a.key_pieces:
        for arr_name, data in source_a.functions[name].arrays.items():
            hits = [h - base for h in _find_all(binary_a, data) if abs(h - base) <= _WINDOW]
            if not hits:
                raise ValueError("{0}.{1} not found near the anchor in build A".format(name, arr_name))
            near[(name, arr_name)] = hits
    fixed = {k: v[0] for k, v in near.items() if len(v) == 1}
    lo = min(fixed.values())
    hi = max(r + len(source_a.functions[k[0]].arrays[k[1]]) for k, r in fixed.items())
    lo, hi = lo - _MARGIN, hi + _MARGIN

    profiles = []
    for name, ofs in source_a.key_pieces:
        fn = source_a.functions[name]
        own = [fixed[(name, n)] for n in fn.arrays if (name, n) in fixed]
        centre = sum(own) / len(own) if own else (lo + hi) / 2
        cands: dict[str, list[int]] = {}
        for arr_name in fn.arrays:
            if (name, arr_name) in fixed:
                cands[arr_name] = [fixed[(name, arr_name)]]
                continue
            inside = [r for r in near[(name, arr_name)] if lo <= r <= hi]
            if not inside:
                raise ValueError("{0}.{1} not found among build A's key arrays".format(name, arr_name))
            cands[arr_name] = sorted(inside, key=lambda r: abs(r - centre))[:_NEAREST]
        names = list(cands)
        if all(len(cands[n]) == 1 for n in names):
            rel = {n: cands[n][0] for n in names}
        elif key_a is None:
            raise ValueError("{0}: short arrays are ambiguous in build A; pass A's key".format(name))
        else:
            want = key_a[ofs : ofs + fn.length]
            rel = None
            for tries, combo in enumerate(itertools.product(*(cands[n] for n in names))):
                if tries >= _MAX_COMBOS:
                    break
                got = {n: binary_a[base + r : base + r + len(fn.arrays[n])] for n, r in zip(names, combo)}
                if fn.decode(got) == want:
                    rel = dict(zip(names, combo))
                    break
            if rel is None:
                raise ValueError("{0}: no placement of its arrays decodes to A's key".format(name))
        certain = frozenset(n for n in fn.arrays if (name, n) in fixed)
        profiles.append(PieceProfile(fn, ofs, rel, certain))
    return Profile(anchor, profiles)


def extract(binary: bytes, profile: Profile) -> bytes:
    """Recover a 32-byte key from ``binary`` the way build A stores it."""
    hits = _find_all(binary, profile.anchor)
    if len(hits) != 1:
        raise ExtractionFailed("build A's anchor array found {0} times".format(len(hits)))
    base = hits[0]
    key = bytearray(32)
    for p in profile.pieces:
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


def key_arrays_va(binary: bytes, source: GenSource, key: bytes) -> list[tuple[int, int]]:
    """[start, end) addresses of this build's key-piece arrays, from its own source."""
    secs = sections(binary)
    ranges = []
    # Only arrays whose place is certain: a short array placed by its decoded value
    # may sit on a stray byte that unrelated code addresses.
    profile = train(binary, source, key)
    base = _find_all(binary, profile.anchor)[0]
    for p in profile.pieces:
        for arr_name, r in p.rel.items():
            if arr_name not in p.certain:
                continue
            va = file_to_va(secs, base + r)
            ranges.append((va, va + len(p.fn.arrays[arr_name])))
    return sorted(ranges)


def key_code(path: Path, binary: bytes, source: GenSource, key: bytes, objdump: str, *, gap: int = 512) -> list[list[Insn]]:
    """The machine code that handles this build's key, as runs of instructions.

    One pass over the whole disassembly finds every instruction that addresses one
    of the build's key arrays. Hits closer than ``gap`` bytes are one routine, which
    runs from its first array access to its last; a second, narrow objdump call
    returns its instructions. Nothing else of the binary is kept in memory.
    """
    ranges = key_arrays_va(binary, source, key)
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
    a_key = _expected_key(args.godot, a_secret, a_epoch)
    profile = train(a_bin, a_src, a_key)
    got = extract(a_bin, profile)
    if got != a_key:
        print("error: the reference extractor did not recover build A's key from build A", file=sys.stderr)
        return 1
    report.append("- Reference extractor for build A recovers A's key from A ({0} pieces).".format(len(profile.pieces)))

    a_code = key_code(a_path, a_bin, a_src, a_key, args.objdump)
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
        other_key = _expected_key(args.godot, secret, epoch)
        try:
            key = extract(data, profile)
        except ExtractionFailed as exc:
            report.append("- {0}: the extractor fails ({1}).".format(label, exc))
        else:
            if key == other_key:
                print("error: build A's extractor recovered the key of {0}".format(label), file=sys.stderr)
                failed = True
            report.append("- {0}: the extractor returns bytes that are not the key.".format(label))
        src = parse_gen_cpp(_source(args.godot, secret, epoch))
        code = key_code(path, data, src, other_key, args.objdump)
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

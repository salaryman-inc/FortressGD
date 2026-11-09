"""Scan build outputs and logs for the project secret and keys derived from it.

Used by `templates build` before it writes the template cache, and by the
build-templates GitHub Action before anything is uploaded or cached. Reports name
the file, the offset, and the kind of material found. They never include the value.

    python3 -m fortressgd.core.leakscan [--godot TAG] [--delete] PATH...

reads the secret from FORTRESSGD_SECRET (or --secret-file), scans every file under
each PATH, and exits 1 if any file contains secret material. With --delete, the
offending files are removed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable, NamedTuple, Sequence


class Leak(NamedTuple):
    path: Path
    label: str
    offset: int


def _encodings(label: str, raw: bytes) -> list[tuple[str, bytes]]:
    hex_lower = raw.hex()
    return [
        (label + " (raw bytes)", raw),
        (label + " (hex)", hex_lower.encode("ascii")),
        (label + " (HEX)", hex_lower.upper().encode("ascii")),
        (label + " (hex, UTF-16)", hex_lower.encode("utf-16-le")),
    ]


def secret_needles(secret: bytes, godot_tag: str | None = None, key_epoch: int = 0) -> list[tuple[str, bytes]]:
    """
    Byte strings whose presence in an output means the secret or a derived key leaked.

    Covers the secret, the mangler key, the derived AES key, and the pack-signing
    seed, each as raw bytes and as hex text. With no godot_tag the tag-dependent
    keys (AES key, signing seed) are not covered.
    """
    from fortressgd.core.mangle import derive_mangle_key

    needles = _encodings("project secret", secret)
    needles += _encodings("mangler key", bytes.fromhex(derive_mangle_key(secret)))
    if godot_tag:
        from fortressgd.core.pack_dialect import dialect_key_for_secret
        from fortressgd.core.pack_sign import signing_seed

        needles += _encodings("derived AES key", dialect_key_for_secret(secret, godot_tag, key_epoch=key_epoch))
        needles += _encodings("pack-signing seed", signing_seed(secret, godot_tag))
    return needles


def scan_bytes(data: bytes, needles: Sequence[tuple[str, bytes]]) -> list[tuple[str, int]]:
    hits = []
    for label, needle in needles:
        offset = data.find(needle)
        if offset != -1:
            hits.append((label, offset))
    return hits


def _iter_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        path = Path(path)
        if path.is_file():
            yield path
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    yield child


def scan_paths(paths: Iterable[Path], needles: Sequence[tuple[str, bytes]]) -> list[Leak]:
    """Every (file, kind, first offset) where secret material appears. Missing paths are skipped."""
    leaks = []
    for path in _iter_files(paths):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for label, offset in scan_bytes(data, needles):
            leaks.append(Leak(path, label, offset))
    return leaks


def redact(text: str, needles: Sequence[tuple[str, bytes]]) -> str:
    """Replace any textual form of the secret material in text with ***."""
    for _label, needle in needles:
        try:
            value = needle.decode("ascii")
        except UnicodeDecodeError:
            continue
        if value.isalnum():
            text = text.replace(value, "***")
            text = text.replace(value.lower(), "***")
    return text


def format_leaks(leaks: Sequence[Leak]) -> str:
    return "\n".join(
        "leak: {0} contains {1} at offset {2}".format(leak.path, leak.label, leak.offset)
        for leak in leaks
    )


def main(argv: list[str] | None = None) -> int:
    from fortressgd.core.errors import UserError
    from fortressgd.core.secret import load_secret_hex, secret_bytes_from_hex
    from fortressgd.core.templates import concrete_godot_tag

    parser = argparse.ArgumentParser(prog="python3 -m fortressgd.core.leakscan", description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("--godot", default=None, help="Godot version, to also scan for derived keys")
    parser.add_argument("--secret-file", default=None)
    parser.add_argument(
        "--key-epoch", type=int, default=0, help="[production].key_epoch the derived AES key was built for"
    )
    parser.add_argument("--delete", action="store_true", help="remove files that contain secret material")
    args = parser.parse_args(argv)
    try:
        secret = secret_bytes_from_hex(
            load_secret_hex(secret_file=args.secret_file, environ=os.environ, cwd=Path.cwd())
        )
    except UserError as err:
        sys.stderr.write(err.format() + "\n")
        return 1
    tag = concrete_godot_tag(args.godot) if args.godot else None
    leaks = scan_paths([Path(p) for p in args.paths], secret_needles(secret, tag, key_epoch=args.key_epoch))
    if not leaks:
        sys.stdout.write("ok: no secret material in {0} path(s)\n".format(len(args.paths)))
        return 0
    sys.stderr.write(format_leaks(leaks) + "\n")
    if args.delete:
        for path in sorted({leak.path for leak in leaks}):
            try:
                path.unlink()
                sys.stderr.write("deleted: {0}\n".format(path))
            except OSError as exc:
                sys.stderr.write("could not delete {0}: {1}\n".format(path, exc))
    sys.stderr.write("error: secret material found in build output\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

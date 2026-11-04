"""Artifact writer for the stub `godot` binaries used by export tests.

`fortressgd export` runs Godot with the output path as the last argument and the
project root as cwd. The stub calls `write_artifact(sys.argv)` to leave a pack there
that `verify` can read, like a real export would:

- dialect = false: stock GDPC with an encrypted directory (export always sets
  encrypt_directory), keyed with the derived AES key.
- dialect = true: FortressGD dialect pack, encrypted directory.

Environment switches (set by the test before running `fortressgd export`):

- FGD_STUB_FILES: comma-separated packed paths (default "main.tscn,main.gdc").
- FGD_STUB_SIBLING=1: write a pack-less executable at the output path and the
  pack next to it as <stem>.pck (non-embedded Linux/Windows export).
- FGD_STUB_NO_ARTIFACT=1: write nothing.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.config import load_path
from core.pack import PACK_DIR_ENCRYPTED
from core.pack_dialect import dialect_key_for_secret, dialect_params_for_secret, encode_dialect_index
from core.secret import read_secret_file, secret_bytes_from_hex
from core.templates import concrete_godot_tag
from tests.gdpc_fixture import make_gdpc


def _output_path(argv: list[str]) -> Path | None:
    if len(argv) < 2 or argv[-1].startswith("-"):
        return None
    # The last arg is the preset name when no output path was given.
    previous = argv[-2]
    if previous in ("--export-release", "--export-pack", "--export-debug"):
        return None
    return Path(argv[-1])


def build_pack(root: Path, files: list[str]) -> bytes:
    cfg = load_path(root / ".fortressgd.toml")
    tag = concrete_godot_tag(str(cfg["godot"]))
    secret = secret_bytes_from_hex(read_secret_file(root / ".fortressgd.secret"))
    if (cfg.get("production") or {}).get("dialect", False):
        magic, perm, key = dialect_params_for_secret(secret, tag)
        return encode_dialect_index(files, magic=magic, perm=perm, flags=PACK_DIR_ENCRYPTED, aes_key=key)
    return make_gdpc(files, flags=PACK_DIR_ENCRYPTED, aes_key=dialect_key_for_secret(secret, tag))


def write_artifact(argv: list[str]) -> None:
    if os.environ.get("FGD_STUB_NO_ARTIFACT") == "1":
        return
    out = _output_path(argv)
    if out is None:
        return
    root = Path.cwd()
    if not out.is_absolute():
        out = root / out
    files = [f for f in os.environ.get("FGD_STUB_FILES", "main.tscn,main.gdc").split(",") if f]
    pack = build_pack(root, files)
    out.parent.mkdir(parents=True, exist_ok=True)
    if os.environ.get("FGD_STUB_SIBLING") == "1":
        out.write_bytes(b"\x7fELF stub executable without an embedded pack")
        out.with_suffix(".pck").write_bytes(pack)
    else:
        out.write_bytes(pack)

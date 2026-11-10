"""Artifact writer for the stub `godot` binaries used by export tests.

`fortressgd export` runs Godot with the output path as the last argument and the
project root as cwd. The stub calls `write_artifact(sys.argv)` to leave a pack there
that `verify` can read, like a real export would:

- dialect = false: stock GDPC with an encrypted directory (export always sets
  encrypt_directory), keyed with the derived AES key.
- dialect = true: what the shared FortressGD export editor writes. It takes the
  magic and index field order from FORTRESSGD_PACK_PARAMS, which `fortressgd
  export` sets, and writes a stock pack when the variable is unset.
- FGD_STUB_BAKED_DIALECT=1: a patched editor built for this project, which
  ignores FORTRESSGD_PACK_PARAMS and uses the project's own values.
- FGD_STUB_IGNORE_PARAMS=1: an official editor, which ignores the variable and
  writes a stock pack.

Environment switches (set by the test before running `fortressgd export`):

- FGD_STUB_FILES: comma-separated packed paths (default "main.tscn,main.gdc").
- FGD_STUB_SIBLING=1: write a pack-less executable at the output path and the
  pack next to it as <stem>.pck (non-embedded Linux/Windows export).
- FGD_STUB_NO_ARTIFACT=1: write nothing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fortressgd.core.config import key_epoch, load_path
from fortressgd.core.pack import PACK_DIR_ENCRYPTED
from fortressgd.core.pack_dialect import (
    PACK_PARAMS_ENV,
    dialect_key_for_secret,
    dialect_params_for_secret,
    encode_dialect_index,
    parse_pack_params,
)
from fortressgd.generator.dialect import STOCK_PACK_MAGIC
from fortressgd.core.secret import read_secret_file, secret_bytes_from_hex
from fortressgd.core.templates import concrete_godot_tag
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
    epoch = key_epoch(cfg)
    # Like Godot: encrypt with GODOT_SCRIPT_ENCRYPTION_KEY, which fortressgd export sets.
    env_key = os.environ.get("GODOT_SCRIPT_ENCRYPTION_KEY", "")
    key = bytes.fromhex(env_key) if env_key else dialect_key_for_secret(secret, tag, key_epoch=epoch)
    if (cfg.get("production") or {}).get("dialect", False):
        if os.environ.get("FGD_STUB_BAKED_DIALECT") == "1":
            magic, perm, _derived = dialect_params_for_secret(secret, tag, key_epoch=epoch)
        elif os.environ.get("FGD_STUB_IGNORE_PARAMS") == "1":
            magic, perm = STOCK_PACK_MAGIC, ()
        else:
            magic, perm = parse_pack_params(os.environ.get(PACK_PARAMS_ENV))
        if magic != STOCK_PACK_MAGIC:
            return encode_dialect_index(files, magic=magic, perm=perm, flags=PACK_DIR_ENCRYPTED, aes_key=key)
    return make_gdpc(files, flags=PACK_DIR_ENCRYPTED, aes_key=key)


def write_artifact(argv: list[str]) -> None:
    if os.environ.get("FGD_STUB_NO_ARTIFACT") == "1":
        return
    out = _output_path(argv)
    if out is None:
        return
    root = Path.cwd()
    if not out.is_absolute():
        out = root / out
    if not out.parent.is_dir():
        # Real Godot does not create the output folder; fail the way it does.
        sys.stderr.write("ERROR: Prepare Template: The given export path doesn't exist.\n")
        raise SystemExit(1)
    files = [f for f in os.environ.get("FGD_STUB_FILES", "main.tscn,main.gdc").split(",") if f]
    pack = build_pack(root, files)
    if os.environ.get("FGD_STUB_SIBLING") == "1":
        out.write_bytes(b"\x7fELF stub executable without an embedded pack")
        out.with_suffix(".pck").write_bytes(pack)
    else:
        out.write_bytes(pack)

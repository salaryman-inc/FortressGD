"""Helpers for tests that drive the shipped fortressgd entry."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "fortressgd"
CLI = ROOT / "bin" / "fortressgd"
SAMPLE_PROJECT = ROOT / "testdata" / "sample_project"


def base_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("FORTRESSGD_SECRET", None)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def run_fortressgd(
    *args: str,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the shipped CLI the same way a user does: `python bin/fortressgd ...`."""
    cmd = [sys.executable, str(CLI), *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env if env is not None else base_env(),
        capture_output=True,
        text=True,
    )


def write_godot_stub(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "project.godot"
    path.write_text("config_version=5\n", encoding="utf-8")
    return path


UPSTREAM_FILES = (
    "core/io/file_access_pack.cpp",
    "core/io/file_access_pack.h",
    "core/io/pck_packer.cpp",
    "editor/doc/editor_help.cpp",
    "editor/export/editor_export_platform.cpp",
    "modules/gdscript/gdscript_tokenizer_buffer.cpp",
    "modules/gdscript/gdscript_byte_codegen.h",
    "modules/gdscript/gdscript_vm.cpp",
)

UPSTREAM_RAW = "https://raw.githubusercontent.com/godotengine/godot/{tag}-stable/{path}"


def download_upstream_file(tag: str, rel: str, dest: Path) -> None:
    from urllib.request import urlopen

    dest.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(UPSTREAM_RAW.format(tag=tag, path=rel), timeout=60) as resp:
        dest.write_bytes(resp.read())


def download_upstream_pack_cpp(tag: str, dest: Path) -> None:
    download_upstream_file(tag, "core/io/file_access_pack.cpp", dest)


def seed_mini_godot_tree(tag: str, work: Path) -> Path:
    """Git checkout with pack read/write sources so `git apply` can run without a full clone."""
    import os
    import subprocess

    for rel in UPSTREAM_FILES:
        download_upstream_file(tag, rel, work / rel)
    subprocess.run(["git", "init"], cwd=work, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=work, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "upstream"],
        cwd=work,
        check=True,
        capture_output=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "fgd",
            "GIT_AUTHOR_EMAIL": "fgd@local",
            "GIT_COMMITTER_NAME": "fgd",
            "GIT_COMMITTER_EMAIL": "fgd@local",
        },
    )
    return work

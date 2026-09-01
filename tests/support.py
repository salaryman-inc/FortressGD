"""Helpers for tests that drive the shipped fortressgd entry."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "cli" / "fortressgd"
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
    """Run the shipped CLI the same way a user does: `python cli/fortressgd ...`."""
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

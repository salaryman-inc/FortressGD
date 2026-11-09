"""Patch series helpers (DESIGN.md §3, §14). Refuse empty series or failed --check."""

from __future__ import annotations

import subprocess
from pathlib import Path

from fortressgd.core.errors import NEXT_TEMPLATES, ToolError
from fortressgd.core.paths import patches_root

SERIES_NAME = "series"


def series_path(tag_dir: Path) -> Path:
    return Path(tag_dir) / SERIES_NAME


def read_series(tag_dir: Path) -> list[str]:
    """Return ordered patch filenames from `series`. Empty list if missing/blank."""
    path = series_path(tag_dir)
    if not path.is_file():
        return []
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            names.append(stripped)
    return names


def patch_files(tag_dir: Path) -> list[Path]:
    names = require_series(tag_dir)
    return [tag_dir / name for name in names]


def require_series(tag_dir: Path) -> list[str]:
    """
    Non-empty series whose files exist. Raises ToolError (CLI exit 3).
    """
    tag_dir = Path(tag_dir)
    rel = tag_dir.as_posix()
    if not tag_dir.is_dir():
        raise ToolError(
            "missing patch directory {0}".format(rel),
            NEXT_TEMPLATES,
        )
    names = read_series(tag_dir)
    if not names:
        raise ToolError(
            "patches series is empty ({0})".format((tag_dir / SERIES_NAME).as_posix()),
            NEXT_TEMPLATES,
        )
    missing = [n for n in names if not (tag_dir / n).is_file()]
    if missing:
        raise ToolError(
            "series lists missing patch file(s): {0}".format(", ".join(missing)),
            NEXT_TEMPLATES,
        )
    return names


def patchset_id(patch_paths: list[Path]) -> str:
    """SHA256 of the concatenation of applied patch bytes, hex truncated to 12."""
    import hashlib

    blob = b"".join(Path(p).read_bytes() for p in patch_paths)
    return hashlib.sha256(blob).hexdigest()[:12]


def patch_dir_for_tag(godot_tag: str, root: Path | None = None) -> Path:
    base = patches_root() if root is None else Path(root)
    return base / godot_tag


def git_apply_check(source_tree: Path, patch_paths: list[Path]) -> None:
    """Run `git apply --check` for each patch in order, then raise ToolError on failure."""
    source_tree = Path(source_tree)
    if not (source_tree / ".git").exists():
        raise ToolError(
            "Godot source tree is not a git checkout: {0}".format(source_tree),
            NEXT_TEMPLATES,
        )
    for patch in patch_paths:
        check = subprocess.run(
            ["git", "apply", "--check", str(patch)],
            cwd=str(source_tree),
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            detail = (check.stderr or check.stdout or "").strip()
            raise ToolError(
                "git apply --check failed for {0}: {1}".format(patch.name, detail),
                NEXT_TEMPLATES,
            )


def git_apply_series(source_tree: Path, patch_paths: list[Path]) -> None:
    git_apply_check(source_tree, patch_paths)
    for patch in patch_paths:
        applied = subprocess.run(
            ["git", "apply", str(patch)],
            cwd=str(source_tree),
            capture_output=True,
            text=True,
        )
        if applied.returncode != 0:
            detail = (applied.stderr or applied.stdout or "").strip()
            raise ToolError(
                "git apply failed for {0}: {1}".format(patch.name, detail),
                NEXT_TEMPLATES,
            )

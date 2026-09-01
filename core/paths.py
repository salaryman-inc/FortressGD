"""Locate the FortressGD checkout / install files."""

from __future__ import annotations

from pathlib import Path

from core.errors import NEXT_DOCTOR, UserError


def repo_root() -> Path:
    """Directory that contains DESIGN.md and plugin/addons/fortressgd."""
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        plugin_cfg = parent / "plugin" / "addons" / "fortressgd" / "plugin.cfg"
        if plugin_cfg.is_file() and (parent / "DESIGN.md").is_file():
            return parent
    raise UserError(
        "cannot find FortressGD plugin files (expected plugin/addons/fortressgd next to DESIGN.md)",
        NEXT_DOCTOR,
    )


def plugin_source_dir() -> Path:
    return repo_root() / "plugin" / "addons" / "fortressgd"


def example_toml_path() -> Path:
    return repo_root() / ".fortressgd.example.toml"


def default_secret_path(cwd: Path | None = None) -> Path:
    base = cwd if cwd is not None else Path.cwd()
    return (base / ".fortressgd.secret").resolve()


def patches_root() -> Path:
    return repo_root() / "patches"


def docker_dir() -> Path:
    return repo_root() / "docker"


def default_cache_dir() -> Path:
    return Path("~/.cache/fortressgd").expanduser()

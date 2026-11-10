"""Locate the files FortressGD ships inside its package."""

from __future__ import annotations

from pathlib import Path

from fortressgd.core.errors import UserError


def package_root() -> Path:
    """The installed `fortressgd` package directory.

    The editor plugin, the patch quilt, the Docker build context and the example
    config ship inside the package, so a wheel install and a source checkout
    resolve them the same way.
    """
    root = Path(__file__).resolve().parents[1]
    if not (root / "plugin" / "addons" / "fortressgd" / "plugin.cfg").is_file():
        raise UserError(
            "FortressGD install is incomplete: missing {0}".format(
                (root / "plugin" / "addons" / "fortressgd").as_posix()
            ),
            "reinstall FortressGD (pip install --force-reinstall fortressgd), then: fortressgd doctor",
        )
    return root


def plugin_source_dir() -> Path:
    return package_root() / "plugin" / "addons" / "fortressgd"


def example_toml_path() -> Path:
    return package_root() / "fortressgd.example.toml"


def default_secret_path(cwd: Path | None = None) -> Path:
    base = cwd if cwd is not None else Path.cwd()
    return (base / ".fortressgd.secret").resolve()


def patches_root() -> Path:
    return package_root() / "patches"


def docker_dir() -> Path:
    return package_root() / "docker"


def images_lock_path() -> Path:
    """The build image digests a release pins (DESIGN.md §18.4). The release
    workflow writes it; a source checkout has none."""
    return package_root() / "images.lock.json"


def default_cache_dir() -> Path:
    return Path("~/.cache/fortressgd").expanduser()

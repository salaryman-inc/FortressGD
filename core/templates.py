"""Template naming, cache, Docker build (DESIGN.md §7)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from core.errors import NEXT_TEMPLATES, ToolError, UserError
from core.kdf import secret_hash
from core.patches import patch_dir_for_tag, patch_files, patchset_id, require_series
from core.leakscan import format_leaks, redact, scan_paths, secret_needles
from core.paths import default_cache_dir, docker_dir, patches_root
from core.secret import load_secret_hex, secret_bytes_from_hex
from generator.dialect import GENERATOR_VERSION, dialect_material, write_dialect_header

KDF_NAME = "FGD-KDF-1"
SUPPORTED_PLATFORMS = ("linux", "windows")
DEFAULT_ARCH = "x86_64"
DOCKER_IMAGE = "fortressgd-templates:v1"
GODOT_STABLE_SUFFIX = "-stable"


def templates_cache_dir(cache_dir: str | Path | None = None) -> Path:
    """`{cache_dir}/templates` with cache_dir defaulting to ~/.cache/fortressgd."""
    base = Path(cache_dir).expanduser() if cache_dir else default_cache_dir()
    return base / "templates"


def template_filename(
    godot: str,
    platform: str,
    arch: str,
    patchset: str,
    secrethash: str,
) -> str:
    """godot-<ver>-template_release-<platform>-<arch>-fgd<patchset12>-<secrethash16>"""
    return "godot-{0}-template_release-{1}-{2}-fgd{3}-{4}".format(
        godot, platform, arch, patchset, secrethash
    )


def templates_build_command(godot: str, platform: str) -> str:
    return "fortressgd templates build --godot {0} --platform {1}".format(godot, platform)


def missing_template_error(godot: str, secrethash: str, platform: str) -> UserError:
    return UserError(
        "missing templates for godot={0} secret_hash={1} platform={2}".format(
            godot, secrethash, platform
        ),
        templates_build_command(godot, platform),
    )


def find_cached_template(
    *,
    godot: str,
    platform: str,
    arch: str = DEFAULT_ARCH,
    patchset: str,
    secrethash: str,
    cache_dir: str | Path | None = None,
) -> Path | None:
    name = template_filename(godot, platform, arch, patchset, secrethash)
    path = templates_cache_dir(cache_dir) / name
    if path.is_file():
        return path
    return None


def list_cached_templates(cache_dir: str | Path | None = None) -> list[str]:
    directory = templates_cache_dir(cache_dir)
    if not directory.is_dir():
        return []
    names = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name.startswith("godot-") and ".manifest." not in path.name:
            names.append(path.name)
    return names


def manifest_dict(
    *,
    godot: str,
    patchset: str,
    secrethash: str,
    dialect: str,
    platform: str,
    arch: str = DEFAULT_ARCH,
) -> dict[str, str]:
    return {
        "godot": godot,
        "patchset_id": patchset,
        "secret_hash": secrethash,
        "kdf": KDF_NAME,
        "dialect_id": dialect,
        "platform": platform,
        "arch": arch,
        "generator_version": str(GENERATOR_VERSION),
    }


def write_manifest(path: Path, data: dict[str, str]) -> None:
    if "secret" in {k.lower() for k in data} or "aes_key" in {k.lower() for k in data}:
        raise ToolError("refusing to write secret or aes_key into manifest.json", NEXT_TEMPLATES)
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    lower = text.lower()
    if '"aes_key"' in lower or '"secret"' in lower:
        raise ToolError("refusing to write secret or aes_key into manifest.json", NEXT_TEMPLATES)
    path.write_text(text, encoding="utf-8")


def normalize_platform(platform: str) -> str:
    value = platform.strip().lower()
    if value in SUPPORTED_PLATFORMS:
        return value
    raise UserError(
        "unsupported template platform {0} (supported: {1})".format(
            platform, ", ".join(SUPPORTED_PLATFORMS)
        ),
        NEXT_TEMPLATES,
    )


def concrete_godot_tag(version: str) -> str:
    """Map toml/CLI godot values to a patches/<tag> folder name."""
    if version in ("4.7.x", "4.7"):
        return "4.7.2"
    return version


def patchset_for_tag(godot: str, patches_dir: Path | None = None) -> str:
    tag = concrete_godot_tag(godot)
    root = patches_root() if patches_dir is None else Path(patches_dir)
    files = patch_files(patch_dir_for_tag(tag, root))
    return patchset_id(files)


def godot_git_tag(version: str) -> str:
    tag = concrete_godot_tag(version)
    if tag.endswith("-stable"):
        return tag
    return tag + GODOT_STABLE_SUFFIX


def resolve_cache_dir_from_config(cfg: dict[str, Any] | None) -> Path:
    if cfg:
        templates = cfg.get("templates") or {}
        raw = templates.get("cache_dir")
        if isinstance(raw, str) and raw.strip():
            return Path(raw).expanduser()
    return default_cache_dir()


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def ensure_docker_image() -> None:
    dockerfile = docker_dir() / "Dockerfile.templates"
    if not dockerfile.is_file():
        raise ToolError("missing {0}".format(dockerfile.as_posix()), NEXT_TEMPLATES)
    if not _docker_available():
        raise ToolError(
            "docker is required to build templates",
            "install Docker, then: fortressgd templates build",
        )
    inspect = subprocess.run(
        ["docker", "image", "inspect", DOCKER_IMAGE],
        capture_output=True,
        text=True,
    )
    if inspect.returncode == 0:
        return
    built = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(dockerfile),
            "-t",
            DOCKER_IMAGE,
            str(docker_dir()),
        ],
        capture_output=True,
        text=True,
    )
    if built.returncode != 0:
        detail = (built.stderr or built.stdout or "").strip()
        raise ToolError("docker build failed: {0}".format(detail), NEXT_TEMPLATES)


def build_templates(
    *,
    godot: str,
    platforms: list[str],
    secret_file: str | None = None,
    environ: dict[str, str] | None = None,
    cwd: Path | None = None,
    cache_dir: str | Path | None = None,
    patches_dir: Path | None = None,
    skip_scons: bool = False,
    dialect: bool = True,
) -> list[Path]:
    """
    Generate dialect.gen.h, refuse empty/failed series, run Docker template build,
    copy artifacts into the cache. Returns cached template paths.
    """
    env = os.environ if environ is None else environ
    hex_secret = load_secret_hex(secret_file=secret_file, environ=env, cwd=cwd)
    secret = secret_bytes_from_hex(hex_secret)
    tag = concrete_godot_tag(godot)
    secrethash = secret_hash(secret)
    plats = [normalize_platform(p) for p in platforms]
    if not plats:
        raise UserError("no platforms to build", NEXT_TEMPLATES)

    root = patches_root() if patches_dir is None else Path(patches_dir)
    tag_dir = patch_dir_for_tag(tag, root)
    files = patch_files(tag_dir)
    require_series(tag_dir)
    pset = patchset_id(files)

    _salt, _masks, _shards, did = dialect_material(secret, tag)
    needles = secret_needles(secret, tag)

    dest_root = templates_cache_dir(cache_dir)
    dest_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fortressgd-tmpl-") as tmp:
        tmp_path = Path(tmp)
        header = tmp_path / "dialect.gen.h"
        write_dialect_header(header, secret, tag)
        secret_path = tmp_path / "secret"
        secret_path.write_text(hex_secret + "\n", encoding="ascii")
        os.chmod(secret_path, 0o600)
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        skip = skip_scons or env.get("FORTRESSGD_SKIP_SCONS") == "1"
        ensure_docker_image()
        produced = []
        for platform in plats:
            run = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-e",
                    "GODOT_VERSION={0}".format(godot_git_tag(tag)),
                    "-e",
                    "FGD_GODOT={0}".format(tag),
                    "-e",
                    "FGD_PLATFORM={0}".format(platform),
                    "-e",
                    "FGD_ARCH={0}".format(DEFAULT_ARCH),
                    "-e",
                    "FGD_DIALECT_ID={0}".format(did),
                    "-e",
                    "FGD_PATCHSET={0}".format(pset),
                    "-e",
                    "FORTRESSGD_SECRET_FILE=/run/secrets/fortressgd",
                    "-e",
                    "FORTRESSGD_SKIP_SCONS={0}".format("1" if skip else "0"),
                    "-e",
                    "FGD_DIALECT={0}".format("1" if dialect else "0"),
                    "-v",
                    "{0}:/run/secrets/fortressgd:ro".format(secret_path),
                    "-v",
                    "{0}:/patches:ro".format(tag_dir),
                    "-v",
                    "{0}:/src/dialect.gen.h:ro".format(header),
                    "-v",
                    "{0}:/out".format(out_dir),
                    DOCKER_IMAGE,
                ],
                capture_output=True,
                text=True,
            )
            if run.returncode != 0:
                detail = redact((run.stderr or run.stdout or "").strip(), needles)
                raise ToolError(
                    "template build failed for {0}: {1}".format(platform, detail),
                    templates_build_command(tag, platform),
                )
            name = template_filename(tag, platform, DEFAULT_ARCH, pset, secrethash)
            src_bin = out_dir / name
            src_man = out_dir / (name + ".manifest.json")
            if not src_man.is_file():
                # entrypoint may write manifest.json next to the artifact
                alt = out_dir / "manifest.json"
                if alt.is_file():
                    src_man = alt
            if not src_man.is_file():
                raise ToolError(
                    "template build did not emit manifest.json for {0}".format(platform),
                    templates_build_command(tag, platform),
                )
            dest_bin = dest_root / name
            dest_man = dest_root / (name + ".manifest.json")
            if not src_bin.is_file():
                raise ToolError(
                    "template build did not emit {0}".format(name),
                    templates_build_command(tag, platform),
                )
            leaks = scan_paths([src_bin, src_man], needles)
            if leaks:
                raise ToolError(
                    "refusing to cache template output that contains secret material:\n"
                    + format_leaks(leaks),
                    templates_build_command(tag, platform),
                )
            shutil.copy2(src_bin, dest_bin)
            shutil.copy2(src_man, dest_man)
            _assert_manifest_safe(dest_man, secrethash)
            produced.append(dest_bin)
        return produced


def _assert_manifest_safe(path: Path, secrethash: str) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("kdf") != KDF_NAME:
        raise ToolError("manifest kdf is not {0}".format(KDF_NAME), NEXT_TEMPLATES)
    if "aes_key" in data or "secret" in data:
        raise ToolError("manifest contains secret or aes_key", NEXT_TEMPLATES)
    if data.get("secret_hash") != secrethash:
        raise ToolError("manifest secret_hash mismatch", NEXT_TEMPLATES)

"""Production export: official encrypt-PCK, or dialect --export-pack (DESIGN.md §8.3)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.config import load_path
from core.errors import NEXT_DOCTOR, NEXT_EXPORT, UserError
from core.kdf import aes_key_hex, secret_hash
from core.mangle import (
    iter_gdscript_files,
    mangle_scripts,
    source_map_json,
    source_map_path,
)
from core.project import CONFIG_NAME, require_godot_root
from core.secret import load_secret_hex, secret_bytes_from_hex
from core.templates import (
    DEFAULT_ARCH,
    concrete_godot_tag,
    find_cached_template,
    missing_template_error,
    patchset_for_tag,
    resolve_cache_dir_from_config,
    templates_build_command,
)
from generator.dialect import derive_dialect_salt

PRESETS_NAME = "export_presets.cfg"
CREDENTIALS_NAME = Path(".godot") / "export_credentials.cfg"


def find_godot_bin(environ: dict[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    for key in ("FORTRESSGD_GODOT", "GODOT", "GODOT_BIN"):
        raw = env.get(key)
        if raw:
            return raw
    path_env = env.get("PATH")
    for name in ("godot", "godot4"):
        found = shutil.which(name, path=path_env)
        if found:
            return found
    raise UserError(
        "godot editor not found on PATH (set GODOT or FORTRESSGD_GODOT)",
        NEXT_EXPORT,
    )


def parse_export_presets(text: str) -> list[dict[str, Any]]:
    """Parse Godot export_presets.cfg into a list of presets (index order)."""
    sections: dict[str, dict[str, str]] = {}
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1].strip()
            sections[current] = {}
            continue
        if "=" not in stripped or not current:
            continue
        key, _, rest = stripped.partition("=")
        sections[current][key.strip()] = _unquote(rest.strip())

    presets: list[dict[str, Any]] = []
    index = 0
    while True:
        name = "preset.{0}".format(index)
        if name not in sections:
            break
        data = dict(sections[name])
        data["_index"] = str(index)
        data["_options"] = dict(sections.get(name + ".options") or {})
        presets.append(data)
        index += 1
    return presets


def find_preset(presets: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for preset in presets:
        if preset.get("name") == name:
            return preset
    raise UserError(
        "export preset not found: {0}".format(name),
        NEXT_EXPORT,
    )


def fgd_platform_for_preset(preset: dict[str, Any]) -> str:
    platform = str(preset.get("platform") or "")
    lower = platform.lower()
    if "windows" in lower:
        return "windows"
    if "linux" in lower or "x11" in lower:
        return "linux"
    raise UserError(
        "platform {0!r} is not protected in v1 (windows/linux only)".format(platform),
        NEXT_EXPORT,
    )


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def _quote_ini(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


def upsert_ini_key(text: str, section: str, key: str, value: str) -> str:
    """Set key=value in [section], inserting the section if needed. Preserves other lines."""
    header = "[{0}]".format(section)
    lines = text.splitlines(keepends=True)
    if not lines:
        return "{0}\n{1}={2}\n".format(header, key, value)
    in_section = False
    section_start = None
    next_section = None
    key_line = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip()
            if in_section:
                next_section = i
                break
            if name == section:
                in_section = True
                section_start = i
            continue
        if in_section and stripped.split("=", 1)[0].strip() == key:
            key_line = i
    assignment = "{0}={1}\n".format(key, value)
    if key_line is not None:
        nl = "" if lines[key_line].endswith("\n") else ""
        lines[key_line] = assignment if lines[key_line].endswith("\n") else assignment.rstrip("\n") + nl
        if lines[key_line].endswith("\n") is False and text.endswith("\n"):
            lines[key_line] = assignment
        lines[key_line] = assignment
        return "".join(lines)
    if in_section:
        insert_at = next_section if next_section is not None else len(lines)
        lines.insert(insert_at, assignment)
        return "".join(lines)
    extra = ""
    if lines and not "".join(lines).endswith("\n"):
        extra = "\n"
    return "".join(lines) + extra + "\n{0}\n{1}".format(header, assignment)


def load_project_config(project_root: Path) -> dict[str, Any]:
    toml_path = project_root / CONFIG_NAME
    if not toml_path.is_file():
        raise UserError("missing {0}".format(CONFIG_NAME), NEXT_DOCTOR)
    return load_path(toml_path)


def _production_dialect(cfg: dict[str, Any]) -> bool:
    production = cfg.get("production") or {}
    return bool(production.get("dialect", False))


def _production_mangle(cfg: dict[str, Any]) -> bool:
    production = cfg.get("production") or {}
    return bool(production.get("mangle_scripts", False))


def _production_sign_packs(cfg: dict[str, Any]) -> bool:
    production = cfg.get("production") or {}
    return bool(production.get("sign_packs", False))


def write_export_source_map(
    export_path: Path,
    secret_hash_value: str,
    mapping: dict[str, str],
) -> Path:
    """Write ``*.fortressgd.map.json`` next to the export artifact (not packed)."""
    dest = source_map_path(export_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(source_map_json(secret_hash_value, mapping), encoding="utf-8")
    return dest


def _production_verify_on_export(cfg: dict) -> bool:
    """[production].verify_on_export; absent means true (DESIGN.md §6, README)."""
    production = cfg.get("production") or {}
    return bool(production.get("verify_on_export", True))


def verify_target(artifact: Path, *, use_dialect: bool, secret: bytes, godot_tag: str) -> Path:
    """
    The file verify_on_export checks: the artifact when it holds a pack (a .pck, or
    an executable with an embedded pack), else the sibling <stem>.pck that a
    non-embedded Windows / Linux export writes next to the executable.
    """
    from core.pack import find_gdpc_offset
    from core.pack_dialect import dialect_params_for_secret, find_dialect_offset

    if artifact.suffix.lower() == ".zip":
        raise UserError(
            "verify_on_export does not support .zip exports yet; "
            "set verify_on_export = false or export a .pck",
            NEXT_EXPORT,
        )
    if artifact.is_file():
        data = artifact.read_bytes()
        if find_gdpc_offset(data) is not None:
            return artifact
        if use_dialect:
            magic = dialect_params_for_secret(secret, godot_tag)[0]
            if find_dialect_offset(data, magic) is not None:
                return artifact
    sibling = artifact.with_suffix(".pck")
    if sibling != artifact and sibling.is_file():
        return sibling
    raise UserError(
        "verify_on_export found no pack in {0} or {1}".format(artifact, sibling),
        NEXT_EXPORT,
    )


def _pack_output_path(export_path: str) -> str:
    """--export-pack wants a .pck/.zip path; keep those, otherwise swap the suffix."""
    if not export_path:
        return export_path
    lower = export_path.lower()
    if lower.endswith(".pck") or lower.endswith(".zip"):
        return export_path
    return str(Path(export_path).with_suffix(".pck"))


def export_preset(
    *,
    preset_name: str,
    cwd: Path | None = None,
    secret_file: str | None = None,
    environ: dict[str, str] | None = None,
    godot_bin: str | None = None,
) -> dict[str, str]:
    """
    dialect=false: official Godot --export-release with GODOT_SCRIPT_ENCRYPTION_KEY = FGD-KDF-1.
    dialect=true: FortressGD-patched headless editor --export-pack (DESIGN.md §8.3).

    Does not persist aes_key or the raw secret. Restores export_presets.cfg.
    Does not reimplement the Godot packer in Python.
    """
    env = os.environ if environ is None else environ
    root = require_godot_root(cwd if cwd is not None else Path.cwd())
    cfg = load_project_config(root)
    godot_ver = concrete_godot_tag(str(cfg["godot"]))
    use_dialect = _production_dialect(cfg)
    hex_secret = load_secret_hex(secret_file=secret_file, environ=env, cwd=root)
    secret = secret_bytes_from_hex(hex_secret)
    secrethash = secret_hash(secret)
    salt = derive_dialect_salt(secret, godot_ver)
    derived_hex = aes_key_hex(secret, salt)
    if derived_hex == hex_secret:
        raise UserError("derived AES key must not equal the project secret", NEXT_EXPORT)

    presets_path = root / PRESETS_NAME
    if not presets_path.is_file():
        raise UserError("missing {0}".format(PRESETS_NAME), NEXT_EXPORT)
    original = presets_path.read_text(encoding="utf-8")
    presets = parse_export_presets(original)
    preset = find_preset(presets, preset_name)
    platform = fgd_platform_for_preset(preset)
    pset = patchset_for_tag(godot_ver)
    cache = resolve_cache_dir_from_config(cfg)
    template = find_cached_template(
        godot=godot_ver,
        platform=platform,
        arch=DEFAULT_ARCH,
        patchset=pset,
        secrethash=secrethash,
        cache_dir=cache,
    )
    if template is None:
        raise missing_template_error(godot_ver, secrethash, platform)

    index = preset["_index"]
    options_section = "preset.{0}.options".format(index)
    modified = original
    modified = upsert_ini_key(
        modified, options_section, "custom_template/release", _quote_ini(str(template))
    )
    modified = upsert_ini_key(modified, "preset.{0}".format(index), "encrypt_pck", "true")
    modified = upsert_ini_key(modified, "preset.{0}".format(index), "encrypt_directory", "true")
    if derived_hex in modified or hex_secret in modified:
        raise UserError("refusing to write secret or aes_key into export_presets.cfg", NEXT_EXPORT)

    cred_path = root / CREDENTIALS_NAME
    cred_existed = cred_path.is_file()
    cred_backup = cred_path.read_bytes() if cred_existed else None

    try:
        binary = godot_bin if godot_bin else find_godot_bin(env)
    except UserError:
        if use_dialect:
            raise UserError(
                "FortressGD patched editor not found on PATH "
                "(set FORTRESSGD_GODOT to the headless editor built with the same patches, target=editor)",
                templates_build_command(godot_ver, platform),
            )
        raise
    export_path = preset.get("export_path") or ""
    if use_dialect:
        out_path = _pack_output_path(export_path)
        cmd = [binary, "--headless", "--path", str(root), "--export-pack", preset_name]
    else:
        out_path = export_path
        cmd = [binary, "--headless", "--path", str(root), "--export-release", preset_name]
    if out_path:
        cmd.append(str(root / out_path) if not Path(out_path).is_absolute() else out_path)

    child_env = dict(env)
    child_env["GODOT_SCRIPT_ENCRYPTION_KEY"] = derived_hex
    child_env.pop("FORTRESSGD_SECRET", None)

    mangle_on = _production_mangle(cfg)
    script_backups: dict[Path, str] = {}
    identifier_map: dict[str, str] = {}
    if mangle_on:
        gd_paths = iter_gdscript_files(root)
        sources = {
            p.resolve().relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for p in gd_paths
        }
        mangled_sources, identifier_map = mangle_scripts(
            sources, secret_hash=secrethash, rename=True
        )
        for rel, text in mangled_sources.items():
            path = root / rel
            original_src = sources[rel]
            if text != original_src:
                script_backups[path] = original_src
                path.write_text(text, encoding="utf-8")
        child_env["FORTRESSGD_CLI_EXPORT"] = "1"

    presets_path.write_text(modified, encoding="utf-8")
    try:
        proc = subprocess.run(cmd, cwd=str(root), env=child_env, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise UserError(
                "godot export failed: {0}".format(detail),
                NEXT_EXPORT,
            )
    finally:
        presets_path.write_text(original, encoding="utf-8")
        for path, original_src in script_backups.items():
            path.write_text(original_src, encoding="utf-8")
        if cred_existed and cred_backup is not None:
            cred_path.parent.mkdir(parents=True, exist_ok=True)
            cred_path.write_bytes(cred_backup)
        elif cred_path.is_file() and not cred_existed:
            try:
                cred_path.unlink()
            except OSError:
                pass

    restored = presets_path.read_text(encoding="utf-8")
    if derived_hex in restored or hex_secret in restored:
        raise UserError("export_presets.cfg contained secret or aes_key after export", NEXT_EXPORT)

    map_file = ""
    artifact = Path(out_path or export_path)
    if artifact and not artifact.is_absolute():
        artifact = root / artifact
    if mangle_on:
        written = write_export_source_map(artifact, secrethash, identifier_map)
        map_file = str(written)

    if _production_sign_packs(cfg) and artifact and artifact.is_file():
        from core.pack_sign import apply_signature, sign_index
        from core.pack import read_pack_listing
        from core.pack_dialect import dialect_params_for_secret, read_dialect_listing

        packed = artifact.read_bytes()
        if use_dialect:
            magic, perm, aes_key = dialect_params_for_secret(secret, godot_ver)
            listing = read_dialect_listing(
                packed, magic=magic, perm=perm, aes_key=aes_key, source=str(artifact)
            )
        else:
            listing = read_pack_listing(packed, source=str(artifact))
        signature = sign_index(listing.index_bytes(packed), secret, godot_ver)
        artifact.write_bytes(
            apply_signature(packed, signature, listing.pck_start, listing.version)
        )

    verify_line = ""
    if _production_verify_on_export(cfg):
        from core.verify import format_verify_ok, verify_with_config

        target = verify_target(artifact, use_dialect=use_dialect, secret=secret, godot_tag=godot_ver)
        verify_line = format_verify_ok(verify_with_config(target, cfg, secret))

    return {
        "preset": preset_name,
        "platform": platform,
        "godot": godot_ver,
        "secret_hash": secrethash,
        "template": str(template),
        "export_path": out_path or export_path,
        "dialect": "1" if use_dialect else "0",
        "export_mode": "export-pack" if use_dialect else "export-release",
        "mangle_scripts": "1" if mangle_on else "0",
        "source_map": map_file,
        "verify": verify_line,
    }

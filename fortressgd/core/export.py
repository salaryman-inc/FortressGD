"""Production export: official encrypt-PCK, or dialect --export-pack (DESIGN.md §8.3)."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

from fortressgd.core.config import key_epoch, load_path
from fortressgd.core.errors import NEXT_DOCTOR, NEXT_EXPORT, NEXT_INIT, UserError
from fortressgd.core.ini import upsert_ini_key  # noqa: F401  (also re-exported for callers)
from fortressgd.core.kdf import aes_key_hex, secret_hash
from fortressgd.core.mangle import (
    binary_resource_paths,
    collect_resource_reference_names,
    collect_scan_only_names,
    derive_mangle_key,
    iter_gdscript_files,
    iter_scan_only_gdscript_files,
    mangle_scripts,
    prepare_map_dir,
    source_map_json,
    source_map_path,
)
from fortressgd.core.project import (
    CONFIG_NAME,
    DOTNET_WARNING,
    PLUGIN_NOT_ENABLED,
    is_dotnet_project,
    plugin_enabled,
    require_godot_root,
)
from fortressgd.core.secret import load_secret_hex, secret_bytes_from_hex
from fortressgd.core.templates import (
    DEFAULT_ARCH,
    concrete_godot_tag,
    editor_build_command,
    find_cached_editor,
    find_cached_template,
    missing_template_error,
    patchset_for_tag,
    resolve_cache_dir_from_config,
    templates_build_command,
)
from fortressgd.generator.dialect import derive_dialect_salt

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


def describe_exit(returncode: int) -> str:
    """Say how a child process ended: "exit code 1" or "killed by SIGSEGV"."""
    if returncode < 0:
        try:
            name = signal.Signals(-returncode).name
        except ValueError:
            name = "signal {0}".format(-returncode)
        return "killed by {0}".format(name)
    return "exit code {0}".format(returncode)


def find_dialect_editor(
    godot_tag: str,
    *,
    environ: dict[str, str] | None = None,
    cache_dir: str | Path | None = None,
) -> str:
    """The editor that writes dialect packs (DESIGN.md §18.5), in this order:

    1. FORTRESSGD_EDITOR, an explicit path;
    2. the cached shared editor from `fortressgd templates build --editor`, on Linux,
       which is the only platform it is built for;
    3. the usual Godot lookup (FORTRESSGD_GODOT, GODOT, PATH), for a patched editor
       built by hand.

    `export_preset` checks afterwards that the pack really is in the dialect, so an
    official editor found in step 3 fails the export instead of shipping a stock pack.
    """
    env = os.environ if environ is None else environ
    explicit = env.get("FORTRESSGD_EDITOR")
    if explicit:
        return explicit
    if sys.platform.startswith("linux"):
        cached = find_cached_editor(godot=godot_tag, cache_dir=cache_dir)
        if cached is not None:
            return str(cached)
    try:
        return find_godot_bin(env)
    except UserError:
        raise UserError(
            "no FortressGD export editor for Godot {0}; dialect = true needs one".format(godot_tag),
            editor_build_command(godot_tag),
        ) from None


def _require_dialect_pack(artifact: Path, magic: int, binary: str, godot_tag: str) -> None:
    """Fail when the editor wrote a stock pack instead of the project's dialect."""
    from fortressgd.core.pack_dialect import find_dialect_offset

    if artifact.suffix.lower() == ".zip":
        return
    for candidate in (artifact, artifact.with_suffix(".pck")):
        if candidate.is_file() and find_dialect_offset(candidate.read_bytes(), magic) is not None:
            return
    raise UserError(
        "{0} did not write a dialect pack; with dialect = true, export needs the "
        "FortressGD export editor, which reads FORTRESSGD_PACK_PARAMS".format(Path(binary).name),
        editor_build_command(godot_tag),
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


# Godot encrypts a file body only when its path matches the preset's
# encryption_include_filters (EditorExportPlatform::_encrypt_and_store_data). An
# empty filter encrypts no body at all, only the directory, which leaves scripts,
# scenes and resources readable without the key. `fortressgd export` therefore
# encrypts every body unless the preset names its own filter.
DEFAULT_ENCRYPTION_INCLUDE = "*"


def encryption_include_for_preset(preset: dict[str, Any]) -> str:
    """The preset's own include filter, or "*" when it has none."""
    current = str(preset.get("encryption_include_filters") or "")
    if any(part.strip() for part in current.split(",")):
        return current
    return DEFAULT_ENCRYPTION_INCLUDE


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def _quote_ini(value: str) -> str:
    return '"' + value.replace('"', '\\"') + '"'


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
    project_root: Path,
    export_path: Path,
    secret_hash_value: str,
    mapping: dict[str, str],
) -> Path:
    """Write the source map under ``<project>/.fortressgd/maps/`` (DESIGN.md §9)."""
    prepare_map_dir(project_root)
    dest = source_map_path(project_root, export_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(source_map_json(secret_hash_value, mapping), encoding="utf-8")
    return dest


def _sign_exported_pack(
    pack_file: Path, *, use_dialect: bool, secret: bytes, godot_tag: str, key_epoch: int = 0
) -> None:
    """Write the Ed25519 index signature into the pack header's reserved area."""
    import struct

    from fortressgd.core.pack import PACK_DIR_ENCRYPTED, PACK_FORMAT_V4, PACK_SPARSE_BUNDLE
    from fortressgd.core.pack_dialect import dialect_params_for_secret, read_dialect_listing
    from fortressgd.core.pack_sign import apply_signature, sign_index
    from fortressgd.core.verify import read_stock_listing

    packed = pack_file.read_bytes()
    if use_dialect:
        magic, perm, aes_key = dialect_params_for_secret(secret, godot_tag, key_epoch=key_epoch)
        listing = read_dialect_listing(packed, magic=magic, perm=perm, aes_key=aes_key, source=str(pack_file))
    else:
        listing = read_stock_listing(
            packed, secret=secret, godot_tag=godot_tag, source=str(pack_file), key_epoch=key_epoch
        )
    flags = struct.unpack_from("<I", packed, listing.pck_start + 20)[0]
    if listing.version == PACK_FORMAT_V4 and flags & PACK_DIR_ENCRYPTED and flags & PACK_SPARSE_BUNDLE:
        # Godot 4.7 stores the sparse-bundle salt where the signature goes.
        raise UserError(
            "sign_packs does not support encrypted sparse bundles ({0}); "
            "set sign_packs = false or export a regular pack".format(pack_file.name),
            NEXT_EXPORT,
        )
    signature = sign_index(listing.index_bytes(packed), secret, godot_tag)
    pack_file.write_bytes(apply_signature(packed, signature, listing.pck_start, listing.version))


def _production_verify_on_export(cfg: dict) -> bool:
    """[production].verify_on_export; absent means true (DESIGN.md §6, README)."""
    production = cfg.get("production") or {}
    return bool(production.get("verify_on_export", True))


def verify_target(artifact: Path, *, use_dialect: bool, secret: bytes, godot_tag: str) -> Path:
    """
    The pack file to sign and verify: the artifact when it holds a pack (a .pck, or
    an executable with an embedded pack), else the sibling <stem>.pck that a
    non-embedded Windows / Linux export writes next to the executable.
    """
    from fortressgd.core.pack import find_gdpc_offset
    from fortressgd.core.pack_dialect import dialect_params_for_secret, find_dialect_offset

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
        "export produced no pack to sign or verify in {0} or {1}".format(artifact, sibling),
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
) -> dict[str, Any]:
    """
    dialect=false: official Godot --export-release with GODOT_SCRIPT_ENCRYPTION_KEY = FGD-KDF-1.
    dialect=true: FortressGD-patched headless editor --export-pack (DESIGN.md §8.3).

    Does not persist aes_key or the raw secret. Restores export_presets.cfg.
    Does not reimplement the Godot packer in Python.
    """
    env = os.environ if environ is None else environ
    root = require_godot_root(cwd if cwd is not None else Path.cwd())
    if not plugin_enabled(root):
        # The §6.3 forced excludes run in the plugin's export hook, inside Godot.
        # Without it the pack would carry addons/fortressgd/ and leftover sources.
        raise UserError(PLUGIN_NOT_ENABLED, NEXT_INIT)
    cfg = load_project_config(root)
    godot_ver = concrete_godot_tag(str(cfg["godot"]))
    use_dialect = _production_dialect(cfg)
    hex_secret = load_secret_hex(secret_file=secret_file, environ=env, cwd=root)
    secret = secret_bytes_from_hex(hex_secret)
    secrethash = secret_hash(secret)
    epoch = key_epoch(cfg)
    salt = derive_dialect_salt(secret, godot_ver, key_epoch=epoch)
    derived_hex = aes_key_hex(secret, salt)
    if derived_hex == hex_secret:
        raise UserError("derived AES key must not equal the project secret", NEXT_EXPORT)

    presets_path = root / PRESETS_NAME
    if not presets_path.is_file():
        raise UserError("missing {0}".format(PRESETS_NAME), NEXT_EXPORT)
    original = presets_path.read_text(encoding="utf-8")
    presets = parse_export_presets(original)
    preset = find_preset(presets, preset_name)
    if not str(preset.get("export_path") or "").strip():
        # Without an output path Godot picks none, the source map would land outside
        # the project, and there is no artifact to sign or verify. Fail before
        # anything is touched.
        raise UserError(
            'export preset "{0}" has no export path; set Export Path in Project → Export'.format(
                preset_name
            ),
            NEXT_EXPORT,
        )
    platform = fgd_platform_for_preset(preset)
    pset = patchset_for_tag(godot_ver)
    cache = resolve_cache_dir_from_config(cfg)
    sign_packs = _production_sign_packs(cfg)
    template = find_cached_template(
        godot=godot_ver,
        platform=platform,
        arch=DEFAULT_ARCH,
        patchset=pset,
        secrethash=secrethash,
        cache_dir=cache,
        require_signature=sign_packs,
        key_epoch=epoch,
    )
    if template is None:
        unsigned = sign_packs and find_cached_template(
            godot=godot_ver,
            platform=platform,
            arch=DEFAULT_ARCH,
            patchset=pset,
            secrethash=secrethash,
            cache_dir=cache,
            key_epoch=epoch,
        )
        if unsigned:
            raise UserError(
                "sign_packs is true, but the cached template was built without the signature "
                "requirement ({0}); a template that does not require signatures loads unsigned "
                "or tampered packs".format(Path(unsigned).name),
                templates_build_command(godot_ver, platform),
            )
        raise missing_template_error(godot_ver, secrethash, platform, epoch)

    index = preset["_index"]
    options_section = "preset.{0}.options".format(index)
    modified = original
    modified = upsert_ini_key(
        modified, options_section, "custom_template/release", _quote_ini(str(template))
    )
    modified = upsert_ini_key(modified, "preset.{0}".format(index), "encrypt_pck", "true")
    modified = upsert_ini_key(modified, "preset.{0}".format(index), "encrypt_directory", "true")
    modified = upsert_ini_key(
        modified,
        "preset.{0}".format(index),
        "encryption_include_filters",
        _quote_ini(encryption_include_for_preset(preset)),
    )
    if derived_hex in modified or hex_secret in modified:
        raise UserError("refusing to write secret or aes_key into export_presets.cfg", NEXT_EXPORT)

    cred_path = root / CREDENTIALS_NAME
    cred_existed = cred_path.is_file()
    cred_backup = cred_path.read_bytes() if cred_existed else None

    if godot_bin:
        binary = godot_bin
    elif use_dialect:
        binary = find_dialect_editor(godot_ver, environ=env, cache_dir=cache)
    else:
        binary = find_godot_bin(env)
    export_path = preset.get("export_path") or ""
    if use_dialect:
        out_path = _pack_output_path(export_path)
        cmd = [binary, "--headless", "--path", str(root), "--export-pack", preset_name]
    else:
        out_path = export_path
        cmd = [binary, "--headless", "--path", str(root), "--export-release", preset_name]
    output_file: Path | None = None
    if out_path:
        output_file = Path(out_path) if Path(out_path).is_absolute() else root / out_path
        cmd.append(str(output_file))

    from fortressgd.core.pack_dialect import PACK_PARAMS_ENV, dialect_params_for_secret, format_pack_params

    child_env = dict(env)
    child_env["GODOT_SCRIPT_ENCRYPTION_KEY"] = derived_hex
    child_env.pop("FORTRESSGD_SECRET", None)
    child_env.pop(PACK_PARAMS_ENV, None)
    dialect_magic = 0
    if use_dialect:
        # The shared editor's magic and index field order, for this export only
        # (DESIGN.md §18.5). The key is GODOT_SCRIPT_ENCRYPTION_KEY, as above.
        dialect_magic, dialect_perm, _key = dialect_params_for_secret(secret, godot_ver, key_epoch=epoch)
        child_env[PACK_PARAMS_ENV] = format_pack_params(dialect_magic, dialect_perm)

    mangle_on = _production_mangle(cfg)
    warnings: list[str] = []
    if is_dotnet_project(root):
        warnings.append(DOTNET_WARNING[len("warning: "):])
    script_backups: dict[Path, str] = {}
    identifier_map: dict[str, str] = {}
    if mangle_on:
        gd_paths = iter_gdscript_files(root)
        sources = {
            p.resolve().relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for p in gd_paths
        }
        mangled_sources, identifier_map = mangle_scripts(
            sources,
            mangle_key=derive_mangle_key(secret),
            rename=True,
            exclude=collect_resource_reference_names(root)
            | collect_scan_only_names(
                addon.read_text(encoding="utf-8") for addon in iter_scan_only_gdscript_files(root)
            ),
        )
        warnings.extend(
            "cannot scan binary resource {0} for mangled names".format(rel)
            for rel in binary_resource_paths(root)
        )
        for rel, text in mangled_sources.items():
            path = root / rel
            original_src = sources[rel]
            if text != original_src:
                script_backups[path] = original_src
                path.write_text(text, encoding="utf-8")
        child_env["FORTRESSGD_CLI_EXPORT"] = "1"

    if output_file is not None:
        # Godot's headless export fails with "The given export path doesn't exist"
        # when the output folder is missing; it never creates it.
        output_file.parent.mkdir(parents=True, exist_ok=True)

    presets_path.write_text(modified, encoding="utf-8")
    try:
        proc = subprocess.run(cmd, cwd=str(root), env=child_env, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise UserError(
                "godot export failed ({0}): {1}".format(describe_exit(proc.returncode), detail),
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
    sibling = artifact.with_suffix(".pck")
    if (out_path or export_path) and not (artifact.is_file() or sibling.is_file()):
        # The plugin deletes the artifact when it cannot filter or mangle the
        # export (Godot 4 gives it no way to fail the run), so Godot exits 0.
        detail = (proc.stderr or proc.stdout or "").strip()
        where = str(artifact) if sibling == artifact else "{0} or {1}".format(artifact, sibling)
        raise UserError(
            "godot export produced no artifact at {0}: {1}".format(
                where, detail or "no output from Godot"
            ),
            NEXT_EXPORT,
        )
    if use_dialect:
        _require_dialect_pack(artifact, dialect_magic, binary, godot_ver)
    mangle_summary = ""
    if mangle_on:
        from fortressgd.core.mangle_report import analyze_project, summary_line

        written = write_export_source_map(root, artifact, secrethash, identifier_map)
        map_file = str(written)
        mangle_summary = summary_line(analyze_project(root))

    if sign_packs:
        if artifact.suffix.lower() == ".zip":
            raise UserError(
                "sign_packs does not support .zip exports yet; export a .pck", NEXT_EXPORT
            )
        _sign_exported_pack(
            verify_target(artifact, use_dialect=use_dialect, secret=secret, godot_tag=godot_ver),
            use_dialect=use_dialect,
            secret=secret,
            godot_tag=godot_ver,
            key_epoch=epoch,
        )

    verify_line = ""
    if _production_verify_on_export(cfg):
        from fortressgd.core.verify import format_verify_ok, verify_with_config

        target = verify_target(artifact, use_dialect=use_dialect, secret=secret, godot_tag=godot_ver)
        verify_line = format_verify_ok(verify_with_config(target, cfg, secret))

    return {
        "preset": preset_name,
        "platform": platform,
        "godot": godot_ver,
        "secret_hash": secrethash,
        "key_epoch": epoch,
        "template": str(template),
        "export_path": out_path or export_path,
        "dialect": "1" if use_dialect else "0",
        "export_mode": "export-pack" if use_dialect else "export-release",
        "mangle_scripts": "1" if mangle_on else "0",
        "source_map": map_file,
        "mangle_summary": mangle_summary,
        "verify": verify_line,
        "warnings": warnings,
    }

"""Init and doctor: write config, install plugin, check toml / plugin drift."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from core.config import default_toml_text, godot_is_supported, load_path, supported_godot_message
from core.errors import NEXT_DOCTOR, NEXT_INIT, NEXT_SECRET, UserError
from core.paths import plugin_source_dir
from core.secret import secret_status
from core.version import __version__

GITIGNORE_ENTRIES = (".fortressgd.secret",)
CONFIG_NAME = ".fortressgd.toml"
PROJECT_GODOT = "project.godot"


def require_godot_root(cwd: Path) -> Path:
    root = cwd.resolve()
    if not (root / PROJECT_GODOT).is_file():
        raise UserError(
            "not a Godot project (missing {0})".format(PROJECT_GODOT),
            NEXT_INIT,
        )
    return root


def init_project(cwd: Path) -> dict[str, str]:
    root = require_godot_root(cwd)
    toml_path = root / CONFIG_NAME
    notes: list[str] = []
    if toml_path.is_file():
        load_path(toml_path)
        notes.append("kept existing {0}".format(CONFIG_NAME))
        action = "kept"
    else:
        toml_path.write_text(default_toml_text(), encoding="utf-8")
        notes.append("wrote {0}".format(CONFIG_NAME))
        action = "wrote"

    dest = install_plugin(root)
    notes.append("installed plugin at {0}".format(dest.relative_to(root).as_posix()))

    gi_note = apply_gitignore_suggestion(root)
    notes.append(gi_note)
    return {
        "root": str(root),
        "toml": str(toml_path),
        "plugin": str(dest),
        "toml_action": action,
        "gitignore": "\n".join(GITIGNORE_ENTRIES),
        "notes": "\n".join(notes),
    }


def install_plugin(project_root: Path) -> Path:
    src = plugin_source_dir()
    dest = project_root / "addons" / "fortressgd"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".DS_Store", "*.uid"))
    return dest


def apply_gitignore_suggestion(project_root: Path) -> str:
    """Append missing entries when `.gitignore` exists; always describe the suggestion."""
    gi = project_root / ".gitignore"
    suggestion = "Suggested .gitignore entries:\n" + "\n".join(
        "  {0}".format(e) for e in GITIGNORE_ENTRIES
    )
    if not gi.is_file():
        return suggestion + "\n(create .gitignore and add them; they were not written)"
    text = gi.read_text(encoding="utf-8")
    lines = {ln.strip() for ln in text.splitlines()}
    missing = [e for e in GITIGNORE_ENTRIES if e not in lines]
    if not missing:
        return suggestion + "\n(.gitignore already lists them)"
    with gi.open("a", encoding="utf-8") as fh:
        if text and not text.endswith("\n"):
            fh.write("\n")
        fh.write("# FortressGD\n")
        for entry in missing:
            fh.write(entry + "\n")
    return suggestion + "\n(appended to .gitignore)"


def plugin_file_hashes(directory: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    if not directory.is_dir():
        return files
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.name == ".DS_Store" or path.suffix == ".uid":
            continue
        rel = path.relative_to(directory).as_posix()
        files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def plugin_diff(project_root: Path) -> tuple[str, list[str]]:
    """
    Compare installed addons/fortressgd against the CLI-packaged plugin.

    Returns (status, details) where status is "match" | "missing" | "differ".
    """
    installed = project_root / "addons" / "fortressgd"
    shipped = plugin_source_dir()
    if not installed.is_dir():
        return "missing", ["addons/fortressgd is not installed"]
    got = plugin_file_hashes(installed)
    want = plugin_file_hashes(shipped)
    details: list[str] = []
    for name in sorted(set(got) | set(want)):
        if name not in got:
            details.append("missing {0}".format(name))
        elif name not in want:
            details.append("extra {0}".format(name))
        elif got[name] != want[name]:
            details.append("changed {0}".format(name))
    if details:
        return "differ", details
    return "match", []


def doctor_project(
    cwd: Path,
    *,
    godot: str | None = None,
    secret_file: str | None = None,
    environ: dict[str, str] | None = None,
) -> dict[str, object]:
    """
    Load and validate toml. Unknown keys raise ConfigError (exit 1).
    Plugin drift is a warning, not a failure.
    """
    root = require_godot_root(cwd)
    toml_path = root / CONFIG_NAME
    if not toml_path.is_file():
        raise UserError("missing {0}".format(CONFIG_NAME), NEXT_INIT)
    cfg = load_path(toml_path)
    version = godot if godot else str(cfg["godot"])
    if not godot_is_supported(version):
        raise UserError(
            "unsupported godot {0} (supported: {1})".format(
                version, supported_godot_message()
            ),
            NEXT_DOCTOR,
        )
    pstatus, pdetails = plugin_diff(root)
    secret = secret_status(secret_file=secret_file, environ=environ, cwd=root)
    warnings: list[str] = []
    if pstatus == "missing":
        warnings.append(
            "warning: plugin files missing at addons/fortressgd/\nRun: {0}".format(
                NEXT_INIT
            )
        )
    elif pstatus == "differ":
        warnings.append(
            "warning: installed plugin files differ from CLI package version {0}\n"
            "  {1}\nRun: {2}".format(__version__, "; ".join(pdetails), NEXT_INIT)
        )
    if secret["state"] == "missing":
        warnings.append(
            "warning: secret missing\nRun: {0}".format(NEXT_SECRET)
        )
    return {
        "root": str(root),
        "config": cfg,
        "plugin_status": pstatus,
        "plugin_details": pdetails,
        "secret": secret,
        "godot": version,
        "warnings": warnings,
    }


def format_doctor_ok(result: dict[str, object]) -> str:
    cfg = result["config"]  # type: ignore[assignment]
    lines = [
        "ok: {0} (schema {1}, godot {2})".format(
            CONFIG_NAME, cfg["schema"], result["godot"]
        ),
        "ok: CLI version {0}".format(__version__),
    ]
    pstatus = result["plugin_status"]
    if pstatus == "match":
        lines.append("ok: plugin files match CLI package version {0}".format(__version__))
    secret = result["secret"]  # type: ignore[assignment]
    if secret["state"] == "present":
        src = secret["source"]
        if src == "file":
            lines.append("ok: secret present (file)")
        else:
            lines.append("ok: secret present (environment {0})".format(secret["path"]))
    lines.extend(result["warnings"])  # type: ignore[arg-type]
    return "\n".join(lines)


def format_init_ok(result: dict[str, str]) -> str:
    extra = ""
    if ".fortressgd.secret" not in result["notes"]:
        extra = "\nSuggested .gitignore entries:\n  {0}".format(result["gitignore"])
    return result["notes"] + extra

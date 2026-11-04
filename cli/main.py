"""fortressgd CLI: init, doctor, secret, verify, templates, export."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from core.config import load_path
from core.errors import NEXT_HELP, NEXT_SECRET, ToolError, UserError, VerifyError
from core.export import export_preset
from core.project import (
    CONFIG_NAME,
    doctor_project,
    format_doctor_ok,
    format_init_ok,
    init_project,
)
from core.secret import (
    ENV_NAME,
    generate_secret_hex,
    load_secret_hex,
    resolve_secret_path,
    secret_bytes_from_hex,
    secret_status,
    write_secret_file,
)
from core.templates import (
    SUPPORTED_PLATFORMS,
    build_templates,
    list_cached_templates,
    resolve_cache_dir_from_config,
)
from core.verify import config_needs_secret, format_verify_ok, verify_with_config
from core.version import __version__


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        sys.stderr.write("error: {0}\nRun: {1}\n".format(message, NEXT_HELP))
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="fortressgd",
        description="FortressGD — Godot 4 release toolchain (init, doctor, secret, verify, templates, export).",
    )
    parser.add_argument("--version", action="version", version="fortressgd {0}".format(__version__))
    secret_file_help = "secret file path (64 hex chars, mode 0600). Also: {0}".format(ENV_NAME)
    parser.add_argument("--secret-file", default=None, help=secret_file_help)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="write .fortressgd.toml, suggest gitignore, install plugin")
    doc = sub.add_parser("doctor", help="validate .fortressgd.toml and plugin files")
    doc.add_argument(
        "--godot",
        default=None,
        help="override godot version from toml (DESIGN.md §4)",
    )
    doc.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)

    secret = sub.add_parser("secret", help="generate or report the 32-byte project secret")
    secret_sub = secret.add_subparsers(dest="secret_command", required=True)
    gen = secret_sub.add_parser("generate", help="write 32 CSPRNG bytes as 64 hex chars")
    gen.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)
    gen.add_argument(
        "--force",
        action="store_true",
        help="replace an existing secret (packs and templates built with the old one stop working)",
    )
    st = secret_sub.add_parser("status", help="report present/missing; never print the secret")
    st.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)

    ver = sub.add_parser(
        "verify",
        help="list packed paths (stock GDPC, or dialect + derived key); fail on §6.3 leaks",
    )
    ver.add_argument("artifact", help="PATH.pck or PATH.exe")
    ver.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)

    tmpl = sub.add_parser("templates", help="build or list FortressGD export templates")
    tmpl_sub = tmpl.add_subparsers(dest="templates_command", required=True)
    build = tmpl_sub.add_parser("build", help="build template_release via Docker")
    build.add_argument("--godot", default=None, help="Godot version (default: toml)")
    build.add_argument(
        "--platform",
        action="append",
        dest="platforms",
        choices=list(SUPPORTED_PLATFORMS),
        help="windows or linux (repeatable; default: toml platforms.build)",
    )
    build.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)
    build.add_argument(
        "--patches-dir",
        default=None,
        help="override patches/<tag> parent (tests/CI)",
    )
    build.add_argument(
        "--require-signature",
        action="store_true",
        help="build the -sig variant that refuses unsigned packs (default: toml production.sign_packs)",
    )
    tmpl_sub.add_parser("list", help="list cached templates")

    exp = sub.add_parser("export", help="production export with derived AES key")
    exp.add_argument("--preset", required=True, help="export preset name")
    exp.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)
    return parser


def cmd_init(_args: argparse.Namespace) -> int:
    result = init_project(Path.cwd())
    sys.stdout.write(format_init_ok(result) + "\n")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    result = doctor_project(
        Path.cwd(),
        godot=args.godot,
        secret_file=args.secret_file,
        environ=os.environ,
    )
    sys.stdout.write(format_doctor_ok(result) + "\n")
    return 0


def cmd_secret_generate(args: argparse.Namespace) -> int:
    path = resolve_secret_path(args.secret_file, Path.cwd())
    hex_secret = generate_secret_hex()
    written = write_secret_file(path, hex_secret, overwrite=args.force)
    try:
        rel = written.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        rel = str(written)
    sys.stdout.write(
        "Wrote 32-byte secret to {0} (mode 0600)\nDo not commit this file.\n".format(rel)
    )
    return 0


def cmd_secret_status(args: argparse.Namespace) -> int:
    info = secret_status(
        secret_file=args.secret_file,
        environ=os.environ,
        cwd=Path.cwd(),
    )
    if info["state"] == "present":
        if info["source"] == "file":
            sys.stdout.write("secret: present\nsource: file\n")
        else:
            sys.stdout.write("secret: present\nsource: environment ({0})\n".format(ENV_NAME))
        return 0
    sys.stdout.write("secret: missing\nRun: {0}\n".format(NEXT_SECRET))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    artifact = Path(args.artifact)
    cfg = _load_cwd_config()
    secret_file = getattr(args, "secret_file", None)
    # Load the secret whenever one is available: encrypted packs need it to list
    # their files. It is an error to lack one only when the pack or config needs it.
    present = secret_status(secret_file=secret_file, environ=os.environ, cwd=Path.cwd())
    secret = None
    if config_needs_secret(cfg) or present["state"] == "present":
        hex_secret = load_secret_hex(secret_file=secret_file, environ=os.environ, cwd=Path.cwd())
        secret = secret_bytes_from_hex(hex_secret)
    result = verify_with_config(artifact, cfg, secret)
    sys.stdout.write(format_verify_ok(result) + "\n")
    return 0


def _load_cwd_config() -> dict:
    toml_path = Path.cwd() / CONFIG_NAME
    if not toml_path.is_file():
        return {}
    return load_path(toml_path)


def cmd_templates_build(args: argparse.Namespace) -> int:
    cfg = _load_cwd_config()
    godot = args.godot or (str(cfg["godot"]) if cfg else None)
    if not godot:
        raise UserError("godot version required (--godot or .fortressgd.toml)", NEXT_HELP)
    platforms = list(args.platforms or [])
    if not platforms:
        listed = (cfg.get("platforms") or {}).get("build") if cfg else None
        if isinstance(listed, list) and listed:
            platforms = [str(p) for p in listed]
        else:
            platforms = list(SUPPORTED_PLATFORMS)
    cache = resolve_cache_dir_from_config(cfg) if cfg else None
    patches_dir = Path(args.patches_dir) if args.patches_dir else None
    dialect = True
    require_signature = bool(args.require_signature)
    if cfg:
        production = cfg.get("production") or {}
        if "dialect" in production:
            dialect = bool(production["dialect"])
        require_signature = require_signature or bool(production.get("sign_packs", False))
    produced = build_templates(
        godot=godot,
        platforms=platforms,
        secret_file=getattr(args, "secret_file", None),
        environ=os.environ,
        cwd=Path.cwd(),
        cache_dir=cache,
        patches_dir=patches_dir,
        dialect=dialect,
        require_signature=require_signature,
    )
    for path in produced:
        sys.stdout.write(path.name + "\n")
    sys.stdout.write("ok: {0} template(s)\n".format(len(produced)))
    return 0


def cmd_templates_list(_args: argparse.Namespace) -> int:
    cfg = _load_cwd_config()
    cache = resolve_cache_dir_from_config(cfg) if cfg else None
    names = list_cached_templates(cache)
    if not names:
        sys.stdout.write("no templates cached\n")
        return 0
    for name in names:
        sys.stdout.write(name + "\n")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    result = export_preset(
        preset_name=args.preset,
        cwd=Path.cwd(),
        secret_file=getattr(args, "secret_file", None),
        environ=os.environ,
    )
    for warning in result.get("warnings") or []:
        sys.stderr.write("warning: {0}\n".format(warning))
    sys.stdout.write(
        "ok: exported preset {0} ({1})\n".format(result["preset"], result["platform"])
    )
    if result.get("verify"):
        sys.stdout.write(result["verify"] + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return 1 if code == 2 else code
        return 1
    try:
        if args.command == "init":
            return cmd_init(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "secret":
            if args.secret_command == "generate":
                return cmd_secret_generate(args)
            if args.secret_command == "status":
                return cmd_secret_status(args)
        if args.command == "verify":
            return cmd_verify(args)
        if args.command == "templates":
            if args.templates_command == "build":
                return cmd_templates_build(args)
            if args.templates_command == "list":
                return cmd_templates_list(args)
        if args.command == "export":
            return cmd_export(args)
        raise UserError("unknown command", NEXT_HELP)
    except VerifyError as err:
        sys.stderr.write(err.format() + "\n")
        return 2
    except ToolError as err:
        sys.stderr.write(err.format() + "\n")
        return 3
    except UserError as err:
        sys.stderr.write(err.format() + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

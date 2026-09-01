"""fortressgd CLI: init, doctor, secret generate, secret status."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from core.errors import NEXT_HELP, NEXT_SECRET, UserError
from core.project import (
    doctor_project,
    format_doctor_ok,
    format_init_ok,
    init_project,
)
from core.secret import (
    ENV_NAME,
    generate_secret_hex,
    resolve_secret_path,
    secret_status,
    write_secret_file,
)
from core.version import __version__


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        sys.stderr.write("error: {0}\nRun: {1}\n".format(message, NEXT_HELP))
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="fortressgd",
        description="FortressGD — Godot 4 release toolchain (Phase 0: init, doctor, secret).",
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
    st = secret_sub.add_parser("status", help="report present/missing; never print the secret")
    st.add_argument("--secret-file", default=argparse.SUPPRESS, help=secret_file_help)
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
    written = write_secret_file(path, hex_secret)
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
        raise UserError("unknown command", NEXT_HELP)
    except UserError as err:
        sys.stderr.write(err.format() + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

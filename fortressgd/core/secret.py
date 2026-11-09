"""Project secret: 32 CSPRNG bytes stored as 64 hex chars. Never print it."""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path

from fortressgd.core.errors import NEXT_SECRET, NEXT_SECRET_FORCE, UserError
from fortressgd.core.paths import default_secret_path

SECRET_BYTES = 32
SECRET_HEX_LEN = 64
ENV_NAME = "FORTRESSGD_SECRET"
DEFAULT_FILENAME = ".fortressgd.secret"

_HEX = re.compile(r"^[0-9a-fA-F]+$")


def generate_secret_hex() -> str:
    """32 CSPRNG bytes as 64 lowercase hex characters."""
    return secrets.token_hex(SECRET_BYTES)


def validate_secret_hex(text: str) -> str:
    value = text.strip()
    if len(value) != SECRET_HEX_LEN or not _HEX.fullmatch(value):
        raise UserError(
            "secret must be {0} hex characters ({1} bytes)".format(
                SECRET_HEX_LEN, SECRET_BYTES
            ),
            NEXT_SECRET,
        )
    return value.lower()


def write_secret_file(path: Path, hex_secret: str, *, overwrite: bool = False) -> Path:
    """
    Write the secret with mode 0600.

    Refuses to replace an existing file unless ``overwrite`` is true: a new secret
    cannot load packs or use templates built with the old one.
    """
    hex_secret = validate_secret_hex(hex_secret)
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT
        flags |= os.O_TRUNC if overwrite else os.O_EXCL
        try:
            fd = os.open(str(path), flags, stat.S_IRUSR | stat.S_IWUSR)
        except FileExistsError as exc:
            raise UserError(
                "secret file already exists at {0}; replacing it makes existing packs "
                "and cached templates unusable".format(path),
                NEXT_SECRET_FORCE,
            ) from exc
        try:
            os.write(fd, (hex_secret + "\n").encode("ascii"))
        finally:
            os.close(fd)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        raise UserError(
            "cannot write secret file {0}: {1}".format(path, exc),
            NEXT_SECRET,
        ) from exc
    return path


def read_secret_file(path: Path) -> str:
    try:
        text = Path(path).read_text(encoding="ascii")
    except OSError as exc:
        raise UserError(
            "cannot read secret file {0}: {1}".format(path, exc),
            NEXT_SECRET,
        ) from exc
    return validate_secret_hex(text)


def resolve_secret_path(secret_file: str | None, cwd: Path | None = None) -> Path:
    if secret_file:
        return Path(secret_file).expanduser()
    return default_secret_path(cwd)


def secret_status(
    *,
    secret_file: str | None = None,
    environ: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> dict[str, str]:
    """
    Report whether a secret is present. Never includes the secret bytes.

    Resolution order (DESIGN.md §5.1): --secret-file, FORTRESSGD_SECRET.
    The default file is `.fortressgd.secret` in cwd when --secret-file is omitted.
    """
    env = os.environ if environ is None else environ
    path = resolve_secret_path(secret_file, cwd)
    if path.is_file():
        read_secret_file(path)
        return {"state": "present", "source": "file", "path": str(path)}
    raw = env.get(ENV_NAME)
    if raw is not None and raw.strip() != "":
        validate_secret_hex(raw)
        return {"state": "present", "source": "environment", "path": ENV_NAME}
    return {"state": "missing", "source": "", "path": str(path)}


def load_secret_hex(
    *,
    secret_file: str | None = None,
    environ: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> str:
    """
    Return the 64-hex secret. Never log the return value.

    Resolution: --secret-file (or default `.fortressgd.secret`), then FORTRESSGD_SECRET.
    The editor plugin's `_load_secret_hex` in plugin/addons/fortressgd/export_plugin.gd
    uses the same order; keep the two aligned.
    """
    env = os.environ if environ is None else environ
    path = resolve_secret_path(secret_file, cwd)
    if path.is_file():
        return read_secret_file(path)
    raw = env.get(ENV_NAME)
    if raw is not None and raw.strip() != "":
        return validate_secret_hex(raw)
    raise UserError("secret missing", NEXT_SECRET)


# A CSPRNG secret of 32 bytes has ~30 distinct byte values on average; the chance
# of fewer than this many is far below 2**-100. Fewer means a hand-typed or
# placeholder value.
MIN_DISTINCT_BYTES = 16
# A value made of one block of up to this many bytes, repeated, is a placeholder
# such as 00…, ff…, deadbeef…, or 0123456789abcdef….
MAX_PLACEHOLDER_PERIOD = 8


def secret_weakness(hex_secret: str) -> str | None:
    """
    Return why a syntactically valid secret looks weak or like a placeholder,
    or None. The reason never includes the secret.
    """
    raw = secret_bytes_from_hex(hex_secret)
    for period in range(1, MAX_PLACEHOLDER_PERIOD + 1):
        block = raw[:period]
        if block * (len(raw) // period) == raw:
            return "secret is a repeating {0}-byte pattern (placeholder value)".format(period)
    distinct = len(set(raw))
    if distinct < MIN_DISTINCT_BYTES:
        return "secret has only {0} distinct byte values (not CSPRNG output)".format(distinct)
    return None


def secret_file_mode_problem(path: Path) -> str | None:
    """Return why a secret file's permissions are too open, or None. POSIX only."""
    if os.name != "posix":
        return None
    mode = stat.S_IMODE(Path(path).stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return "secret file {0} has mode {1:04o}; group or others can access it (want 0600)".format(
            path, mode
        )
    return None


def secret_bytes_from_hex(hex_secret: str) -> bytes:
    return bytes.fromhex(validate_secret_hex(hex_secret))

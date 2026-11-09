"""Verify: stock GDPC leak-check, dialect parse, nameless bytecode, pack signatures."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from fortressgd.core.errors import NEXT_DOCTOR, NEXT_SECRET, NEXT_VERIFY, VerifyError
from fortressgd.core.filters import (
    SHADER_MARKER,
    Leak,
    find_leaks,
    glob_match,
    is_shader_path,
    shader_has_comments,
    sidecar_pdb_leaks,
)
from fortressgd.core.gdc import CompressedGdscError, has_debug_name_tables
from fortressgd.core.pack import (
    PACK_DIR_ENCRYPTED,
    PACK_FILE_ENCRYPTED,
    PackError,
    PackListing,
    find_gdpc_offset,
    list_packed_paths,
    read_pack_listing_at,
)
from fortressgd.core.pack_dialect import (
    STOCK_INDEX_PERM,
    STOCK_PACK_MAGIC,
    decrypt_fae_blob,
    dialect_key_for_secret,
    dialect_params_for_secret,
    read_dialect_listing,
    read_dialect_listing_at,
)
from fortressgd.core.pack_sign import (
    SIG_LEN,
    public_key_for_secret,
    read_reserved_signature,
    verify_index,
)


# magic, version, major, minor, patch (u32 each), then pack flags.
_HEADER_FLAGS_OFFSET = 20


@dataclass(frozen=True)
class VerifyResult:
    artifact: Path
    paths: list[str]
    leaks: list[Leak]
    dialect: bool = False
    stock_failed: bool = False


def verify_artifact(
    path: Path,
    include: Sequence[str] | None = None,
    *,
    exclude: Sequence[str] | None = None,
    dialect: bool = False,
    secret: bytes | None = None,
    godot_tag: str | None = None,
    nameless_bytecode: bool = False,
    sign_packs: bool = False,
) -> VerifyResult:
    """
    List packed paths and report §6.3 leaks.

    dialect=False: stock GDPC listing (Phase 1).
    dialect=True: FortressGD dialect + derived key must succeed; stock GDPC must fail.
    nameless_bytecode: fail if packed .gdc still has debug name tables.
    sign_packs: require a valid Ed25519 signature over the pack index.
    """
    artifact = Path(path)
    if artifact.is_dir():
        raise PackError("{0} is a directory, expected a .pck or .exe".format(artifact), NEXT_VERIFY)
    try:
        data = artifact.read_bytes()
    except OSError as exc:
        raise PackError("cannot read {0}: {1}".format(artifact, exc)) from exc
    if not data:
        raise PackError("empty file: {0}".format(artifact))

    listing: PackListing
    packed: list[str]
    stock_failed = False
    if dialect:
        if secret is None or not godot_tag:
            raise PackError(
                "dialect verify requires the project secret and godot tag",
                NEXT_VERIFY,
            )
        magic, perm, aes_key = dialect_params_for_secret(secret, godot_tag)
        listing = read_dialect_listing(
            data, magic=magic, perm=perm, aes_key=aes_key, source=str(artifact)
        )
        packed = [item.path for item in listing.files]
        try:
            list_packed_paths(data, source=str(artifact))
        except PackError:
            stock_failed = True
        if not stock_failed:
            raise VerifyError(
                "stock GDPC parser opened {0} (dialect pack must not be readable as GDPC)".format(
                    artifact.name
                ),
                NEXT_DOCTOR,
            )
    else:
        listing = read_stock_listing(data, secret=secret, godot_tag=godot_tag, source=str(artifact))
        packed = [item.path for item in listing.files]

    leaks = find_leaks(packed, include=include, exclude=exclude) + sidecar_pdb_leaks(artifact)
    body_key = dialect_key_for_secret(secret, godot_tag) if secret is not None and godot_tag else None
    leaks += _shader_source_leaks(data, listing, include, body_key)
    leaks += _plaintext_body_leaks(listing, include)
    result = VerifyResult(
        artifact=artifact,
        paths=packed,
        leaks=leaks,
        dialect=dialect,
        stock_failed=stock_failed,
    )
    if result.leaks:
        return result

    if nameless_bytecode:
        named = _named_gdc_paths(data, listing, body_key)
        if named:
            lines = ["debug name tables in packed .gdc (nameless_bytecode) in {0}".format(artifact.name)]
            for gdc_path in named:
                lines.append("  {0}".format(gdc_path))
            raise VerifyError("\n".join(lines), NEXT_DOCTOR)

    if sign_packs:
        if secret is None or not godot_tag:
            raise PackError(
                "sign_packs verify requires the project secret and godot tag",
                NEXT_VERIFY,
            )
        signature = read_reserved_signature(data, listing.pck_start, listing.version)
        pubkey = public_key_for_secret(secret, godot_tag)
        index = listing.index_bytes(data)
        if signature == b"\x00" * SIG_LEN or not verify_index(index, signature, pubkey):
            raise VerifyError(
                "missing or invalid pack signature in {0}".format(artifact.name),
                NEXT_DOCTOR,
            )
    return result


def _stock_dir_encrypted(data: bytes, offset: int) -> bool:
    """True when the stock GDPC header at offset has PACK_DIR_ENCRYPTED set."""
    flags_at = offset + _HEADER_FLAGS_OFFSET
    if flags_at + 4 > len(data):
        return False
    return bool(struct.unpack_from("<I", data, flags_at)[0] & PACK_DIR_ENCRYPTED)


def read_stock_listing(
    data: bytes,
    *,
    secret: bytes | None,
    godot_tag: str | None,
    source: str,
) -> PackListing:
    """
    Stock GDPC listing. `fortressgd export` with dialect=false always encrypts the
    directory with the derived key, so an encrypted directory is read with that key
    (stock magic and field order).
    """
    offset = find_gdpc_offset(data)
    if offset is None:
        raise PackError("no stock GDPC pack in {0}".format(source))
    if not _stock_dir_encrypted(data, offset):
        return read_pack_listing_at(data, offset, source=source)
    if secret is None:
        raise PackError(
            "encrypted pack directory; verify needs the project secret "
            "(.fortressgd.secret or FORTRESSGD_SECRET)",
            NEXT_SECRET,
        )
    if not godot_tag:
        raise PackError(
            "encrypted pack directory; verify needs the godot version from .fortressgd.toml",
            NEXT_VERIFY,
        )
    return read_dialect_listing_at(
        data,
        offset,
        magic=STOCK_PACK_MAGIC,
        perm=STOCK_INDEX_PERM,
        aes_key=dialect_key_for_secret(secret, godot_tag),
        source=source,
    )


def _packed_body(data: bytes, listing: PackListing, item, aes_key: bytes | None, purpose: str) -> bytes:
    """A packed file's bytes, decrypted when its PACK_FILE_ENCRYPTED flag is set."""
    blob = listing.blob(data, item)
    if not item.flags & PACK_FILE_ENCRYPTED:
        return blob
    if aes_key is None:
        raise VerifyError(
            "cannot inspect encrypted {0} without the project secret "
            "(.fortressgd.secret or FORTRESSGD_SECRET)".format(purpose),
            NEXT_SECRET,
        )
    try:
        return decrypt_fae_blob(blob, aes_key)
    except PackError as exc:
        raise VerifyError("cannot decrypt {0}: {1}".format(item.path, exc), NEXT_DOCTOR) from exc


# Bodies that must be encrypted whenever the directory is: compiled and text scripts.
_SCRIPT_SUFFIXES = (".gdc", ".gde", ".gd")
UNENCRYPTED_BODY = "unencrypted body; Encryption Include Filters was empty"
UNENCRYPTED_SCRIPT = "unencrypted script body"


def _plaintext_body_leaks(listing: PackListing, include: Sequence[str] | None) -> list[Leak]:
    """
    File bodies left in plaintext inside a pack whose directory is encrypted.

    Godot encrypts a body only when it matches the preset's
    encryption_include_filters; an empty filter encrypts none. A pack with an
    encrypted directory but no encrypted body is that mistake, so every body is
    reported. Otherwise a narrower filter is the project's choice (for example
    large media left plaintext for load speed), but scripts must still be
    encrypted. [filters].include exempts a path.
    """
    if not listing.dir_encrypted:
        return []
    include_list = [p for p in (include or ()) if p]
    bodies = [item for item in listing.files if item.size > 0]
    plain = [
        item
        for item in bodies
        if not item.flags & PACK_FILE_ENCRYPTED
        and not any(glob_match(item.path, pattern) for pattern in include_list)
    ]
    if bodies and not any(item.flags & PACK_FILE_ENCRYPTED for item in bodies):
        return [Leak(path=item.path, pattern=UNENCRYPTED_BODY) for item in plain]
    return [
        Leak(path=item.path, pattern=UNENCRYPTED_SCRIPT)
        for item in plain
        if item.path.lower().endswith(_SCRIPT_SUFFIXES)
    ]


def _shader_source_leaks(
    data: bytes, listing: PackListing, include: Sequence[str] | None, aes_key: bytes | None
) -> list[Leak]:
    """Packed shaders that still carry comments. Godot ships shader text verbatim;
    comments and author notes are the part that leaks intent. [filters].include
    exempts a path."""
    include_list = [p for p in (include or ()) if p]
    leaks: list[Leak] = []
    for item in listing.files:
        if not is_shader_path(item.path):
            continue
        if any(glob_match(item.path, pattern) for pattern in include_list):
            continue
        body = _packed_body(data, listing, item, aes_key, "shader for the shader-source check")
        if shader_has_comments(body.decode("utf-8", errors="replace")):
            leaks.append(Leak(path=item.path, pattern=SHADER_MARKER))
    return leaks


def _named_gdc_paths(data: bytes, listing: PackListing, aes_key: bytes | None) -> list[str]:
    """
    Packed .gdc files that still carry stock identifier or line tables.

    Encrypted bodies (PACK_FILE_ENCRYPTED, written by Godot's export with the
    script encryption key) are decrypted first. Only .gdc bodies are decrypted:
    AES here is pure Python, and the bytecode is what this check is about.
    """
    named: list[str] = []
    for item in listing.files:
        is_gdc = item.path.lower().endswith(".gdc")
        blob = listing.blob(data, item)
        if item.flags & PACK_FILE_ENCRYPTED:
            if not is_gdc:
                continue
            if aes_key is None:
                raise VerifyError(
                    "cannot inspect encrypted .gdc for nameless_bytecode without the project "
                    "secret (.fortressgd.secret or FORTRESSGD_SECRET)",
                    NEXT_SECRET,
                )
            try:
                blob = decrypt_fae_blob(blob, aes_key)
            except PackError as exc:
                raise VerifyError(
                    "cannot decrypt {0} for nameless_bytecode: {1}".format(item.path, exc),
                    NEXT_DOCTOR,
                ) from exc
        look = is_gdc or blob.startswith(b"GDSC")
        if not look and b"GDSC" not in blob:
            continue
        try:
            if has_debug_name_tables(blob):
                named.append(item.path)
        except CompressedGdscError as exc:
            raise VerifyError(
                "packed .gdc uses Compressed binary tokens ({0}); nameless_bytecode verify needs "
                "Python 3.14+ or the preset's GDScript Export Mode set to Binary tokens".format(
                    item.path
                ),
                NEXT_DOCTOR,
            ) from exc
        except ValueError as exc:
            raise VerifyError(
                "cannot decode {0} for nameless_bytecode: {1}".format(item.path, exc),
                NEXT_DOCTOR,
            ) from exc
    return named


def _filter_patterns(cfg: dict, key: str) -> list[str]:
    filters = cfg.get("filters") or {}
    values = filters.get(key) or []
    if not isinstance(values, list):
        return []
    return [p for p in values if isinstance(p, str)]


def config_needs_secret(cfg: dict) -> bool:
    """True when verify cannot run without the project secret for this config."""
    production = cfg.get("production") or {}
    return bool(production.get("dialect", False)) or bool(production.get("sign_packs", False))


def verify_with_config(artifact: Path, cfg: dict, secret: bytes | None) -> VerifyResult:
    """
    Verify an artifact the way `.fortressgd.toml` asks. Shared by `fortressgd verify`
    and `fortressgd export` (verify_on_export) so the two cannot drift apart.

    Raises the leak VerifyError from format_verify_leaks when excluded paths are packed.
    """
    production = cfg.get("production") or {}
    dialect = bool(production.get("dialect", False))
    godot_tag = None
    if cfg.get("godot"):
        from fortressgd.core.templates import concrete_godot_tag

        godot_tag = concrete_godot_tag(str(cfg["godot"]))
    if config_needs_secret(cfg) and not godot_tag:
        raise PackError("verify needs the godot version from .fortressgd.toml", NEXT_VERIFY)
    result = verify_artifact(
        artifact,
        include=_filter_patterns(cfg, "include"),
        exclude=_filter_patterns(cfg, "exclude"),
        dialect=dialect,
        secret=secret,
        godot_tag=godot_tag,
        nameless_bytecode=bool(production.get("nameless_bytecode", False)),
        sign_packs=bool(production.get("sign_packs", False)),
    )
    if result.leaks:
        raise format_verify_leaks(result)
    return result


def format_verify_ok(result: VerifyResult) -> str:
    return "ok: no production leaks in {0} ({1} packed files)".format(
        result.artifact.name, len(result.paths)
    )


def format_verify_leaks(result: VerifyResult) -> VerifyError:
    lines = ["leaked or unencrypted file(s) in {0}".format(result.artifact.name)]
    for leak in result.leaks:
        lines.append("  {0} ({1})".format(leak.path, leak.pattern))
    return VerifyError("\n".join(lines), NEXT_DOCTOR)

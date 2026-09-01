"""Verify: stock GDPC leak-check, or dialect parse + stock-must-fail (DESIGN.md §10)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from core.errors import NEXT_DOCTOR, NEXT_VERIFY, VerifyError
from core.filters import Leak, find_leaks
from core.pack import PackError, list_packed_paths, list_packed_paths_from_path
from core.pack_dialect import dialect_params_for_secret, list_dialect_paths_from_path


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
    dialect: bool = False,
    secret: bytes | None = None,
    godot_tag: str | None = None,
) -> VerifyResult:
    """
    List packed paths and report §6.3 leaks.

    dialect=False: stock GDPC listing (Phase 1).
    dialect=True: FortressGD dialect + derived key must succeed; stock GDPC must fail.
    """
    artifact = Path(path)
    if artifact.is_dir():
        raise PackError("{0} is a directory, expected a .pck or .exe".format(artifact), NEXT_VERIFY)
    if dialect:
        if secret is None or not godot_tag:
            raise PackError(
                "dialect verify requires the project secret and godot tag",
                NEXT_VERIFY,
            )
        magic, perm, aes_key = dialect_params_for_secret(secret, godot_tag)
        packed = list_dialect_paths_from_path(
            artifact, magic=magic, perm=perm, aes_key=aes_key
        )
        stock_failed = False
        try:
            data = artifact.read_bytes()
            list_packed_paths(data, source=str(artifact))
        except PackError:
            stock_failed = True
        except OSError as exc:
            raise PackError("cannot read {0}: {1}".format(artifact, exc)) from exc
        if not stock_failed:
            raise VerifyError(
                "stock GDPC parser opened {0} (dialect pack must not be readable as GDPC)".format(
                    artifact.name
                ),
                NEXT_DOCTOR,
            )
        leaks = find_leaks(packed, include=include)
        return VerifyResult(
            artifact=artifact,
            paths=packed,
            leaks=leaks,
            dialect=True,
            stock_failed=True,
        )
    packed = list_packed_paths_from_path(artifact)
    leaks = find_leaks(packed, include=include)
    return VerifyResult(artifact=artifact, paths=packed, leaks=leaks)


def format_verify_ok(result: VerifyResult) -> str:
    return "ok: no production leaks in {0} ({1} packed files)".format(
        result.artifact.name, len(result.paths)
    )


def format_verify_leaks(result: VerifyResult) -> VerifyError:
    lines = ["leaked excluded path(s) in {0}".format(result.artifact.name)]
    for leak in result.leaks:
        lines.append("  {0} ({1})".format(leak.path, leak.pattern))
    return VerifyError("\n".join(lines), NEXT_DOCTOR)

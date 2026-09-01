"""Phase 1 leak-only verify: stock GDPC listing + DESIGN.md §6.3 excludes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from core.errors import NEXT_DOCTOR, NEXT_VERIFY, VerifyError
from core.filters import Leak, find_leaks
from core.pack import PackError, list_packed_paths_from_path


@dataclass(frozen=True)
class VerifyResult:
    artifact: Path
    paths: list[str]
    leaks: list[Leak]


def verify_artifact(
    path: Path,
    include: Sequence[str] | None = None,
) -> VerifyResult:
    """List packed paths and report §6.3 leaks. Raises PackError/UserError on I/O."""
    artifact = Path(path)
    if artifact.is_dir():
        raise PackError("{0} is a directory, expected a .pck or .exe".format(artifact), NEXT_VERIFY)
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

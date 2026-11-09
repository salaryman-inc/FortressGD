"""DESIGN.md §6.3 forced release filters. Shared by verify and the export plugin."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Sequence

from fortressgd.core.paths import plugin_source_dir

FILTERS_JSON_NAME = "filters.json"

# DESIGN.md §6.3. The JSON file is the single source of truth; the editor plugin
# loads the same list. Tests fail if this set drifts from the spec.
_SPEC_FORCED_EXCLUDE: tuple[str, ...] = (
    "*.cs",
    "*.gd",
    "*.sln",
    "*.csproj",
    "*.blend",
    "*.psd",
    "*.kra",
    "*.tmp",
    "addons/fortressgd/**",
    "*.fortressgd.map.json",
    "*.pdb",
)

FEATURE_TAG = "fortressgd_production"


def filters_json_path():
    return plugin_source_dir() / FILTERS_JSON_NAME


def load_filters_file(path=None) -> dict:
    filters_path = path if path is not None else filters_json_path()
    return json.loads(filters_path.read_text(encoding="utf-8"))


def forced_exclude_patterns() -> tuple[str, ...]:
    data = load_filters_file()
    raw = data.get("forced_exclude")
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ValueError("{0}: forced_exclude must be an array of strings".format(filters_json_path()))
    return tuple(raw)


def production_feature_tag() -> str:
    data = load_filters_file()
    tag = data.get("feature_tag", FEATURE_TAG)
    if not isinstance(tag, str) or not tag:
        return FEATURE_TAG
    return tag


def spec_forced_exclude_patterns() -> tuple[str, ...]:
    """The DESIGN.md §6.3 list tests compare the shipped JSON against."""
    return _SPEC_FORCED_EXCLUDE


def normalize_pack_path(path: str) -> str:
    p = path.replace("\\", "/")
    if p.startswith("res://"):
        p = p[6:]
    while p.startswith("/"):
        p = p[1:]
    return p


def glob_match(path: str, pattern: str) -> bool:
    """Godot-style wildcard: ``*`` matches any characters including ``/``."""
    return _glob_re(normalize_pack_path(pattern)).fullmatch(normalize_pack_path(path)) is not None


@dataclass(frozen=True)
class Leak:
    path: str
    pattern: str


def effective_exclude_patterns(exclude: Sequence[str] | None = None) -> list[str]:
    """Forced §6.3 excludes, then ``[filters].exclude``, duplicates removed, order kept."""
    out: list[str] = []
    for pat in list(forced_exclude_patterns()) + [p for p in (exclude or ()) if p]:
        if pat not in out:
            out.append(pat)
    return out


DOTNET_MARKER = "*.pdb next to the artifact"
SHADER_SUFFIXES = (".gdshader", ".gdshaderinc")
SHADER_MARKER = "shader-source: comments"


def shader_has_comments(text: str) -> bool:
    """True if Godot shader text has a // or /* comment outside quoted text.

    The shader language has no string literals, but ``#include "res://x.gdshaderinc"``
    contains ``//`` inside quotes, so quoted spans are skipped.
    """
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            end = text.find('"', i + 1)
            newline = text.find("\n", i + 1)
            if end == -1 or (newline != -1 and newline < end):
                i = newline if newline != -1 else n
                continue
            i = end + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] in "/*":
            return True
        i += 1
    return False


def is_shader_path(path: str) -> bool:
    return normalize_pack_path(path).lower().endswith(SHADER_SUFFIXES)


def sidecar_pdb_leaks(artifact) -> list[Leak]:
    """.NET debug symbols shipped beside the artifact.

    A PDB restores names and line numbers when the managed assembly is
    decompiled. Checks the artifact's directory and Godot's data_<name>_* folders
    next to it, where .NET exports put their assemblies.
    """
    from pathlib import Path

    folder = Path(artifact).resolve().parent
    found: list[Leak] = []
    candidates = list(folder.glob("*.pdb"))
    for data_dir in folder.glob("data_*"):
        if data_dir.is_dir():
            candidates.extend(data_dir.rglob("*.pdb"))
    for pdb in sorted(set(candidates)):
        found.append(Leak(path=pdb.relative_to(folder).as_posix(), pattern=DOTNET_MARKER))
    return found


def find_leaks(
    paths: Iterable[str],
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> list[Leak]:
    """Packed paths that match a §6.3 forced exclude or a ``[filters].exclude``
    pattern and are not allowlisted.

    A path is exempt when it matches any ``[filters].include`` pattern (the
    same pattern, or a more specific path glob). ``Leak.pattern`` is the first
    exclude pattern that matched.
    """
    include_list = [p for p in (include or ()) if p]
    patterns = effective_exclude_patterns(exclude)
    leaks: list[Leak] = []
    for path in paths:
        if any(glob_match(path, inc) for inc in include_list):
            continue
        for pat in patterns:
            if glob_match(path, pat):
                leaks.append(Leak(path=path, pattern=pat))
                break
    return leaks


def should_force_exclude(
    path: str,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> bool:
    return bool(find_leaks([path], include=include, exclude=exclude))


@lru_cache(maxsize=64)
def _glob_re(pattern: str) -> re.Pattern[str]:
    i = 0
    out: list[str] = []
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            if i < len(pattern) and pattern[i] == "/":
                i += 1
            continue
        ch = pattern[i]
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE | re.DOTALL)

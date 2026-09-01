"""DESIGN.md §6.3 forced release filters. Shared by verify and the export plugin."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Sequence

from core.paths import plugin_source_dir

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


def find_leaks(
    paths: Iterable[str],
    include: Sequence[str] | None = None,
) -> list[Leak]:
    """Packed paths that match a §6.3 exclude and are not allowlisted.

    A path is exempt when it matches any ``[filters].include`` pattern (the
    same pattern, or a more specific path glob).
    """
    include_list = [p for p in (include or ()) if p]
    forced = forced_exclude_patterns()
    leaks: list[Leak] = []
    for path in paths:
        if any(glob_match(path, inc) for inc in include_list):
            continue
        for pat in forced:
            if glob_match(path, pat):
                leaks.append(Leak(path=path, pattern=pat))
                break
    return leaks


def should_force_exclude(path: str, include: Sequence[str] | None = None) -> bool:
    return bool(find_leaks([path], include=include))


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

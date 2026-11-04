"""GDScript identifier mangling for production export (DESIGN.md §9).

Pure rewrite / scan helpers have no Godot or filesystem I/O. CLI export and
the editor plugin apply them when [production].mangle_scripts is true.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from core.errors import NEXT_EXPORT, UserError
from core.paths import plugin_source_dir

KEEP_ANNOTATION = "fortressgd:keep"
MANGLE_INFO = "fortressgd-mangle-v1"
RESERVED_JSON_NAME = "mangle_reserved.json"
MAP_SUFFIX = ".fortressgd.map.json"
MAP_VERSION = 1
UNSAFE_CALLEES = frozenset({"call", "rpc", "set"})
DECL_KEYWORDS = frozenset({"func", "var", "const", "signal", "enum", "class", "for"})
SKIP_DIR_NAMES = frozenset({".godot", ".git", "__pycache__"})
PLUGIN_ADDON = "addons/fortressgd"
ADDONS_DIR = "addons"
# Text files that refer to script members by name (scenes, resources, autoloads).
TEXT_RESOURCE_SUFFIXES = (".tscn", ".tres")
TEXT_RESOURCE_NAMES = ("project.godot",)
# Binary resources can hold the same references but cannot be scanned as text.
BINARY_RESOURCE_SUFFIXES = (".scn", ".res")
# @export_* annotations that group inspector entries and declare no var.
EXPORT_NON_DECL = frozenset({"@export_group", "@export_subgroup", "@export_category"})

_KEEP_RE = re.compile(r"^##\s*fortressgd:keep\b")
_IDENT_START = re.compile(r"[A-Za-z_]")
_IDENT_CONT = re.compile(r"[A-Za-z0-9_]")
_IDENT_FULL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class MangleError(UserError):
    """Unsafe string call/rpc/set, or other mangler failure. CLI exit 1."""

    def __init__(self, message: str) -> None:
        super().__init__(message, NEXT_EXPORT)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    line: int
    col: int


@dataclass(frozen=True)
class UnsafeCall:
    path: str
    line: int
    kind: str


def reserved_json_path() -> Path:
    return plugin_source_dir() / RESERVED_JSON_NAME


@lru_cache(maxsize=1)
def reserved_names() -> frozenset[str]:
    data = json.loads(reserved_json_path().read_text(encoding="utf-8"))
    names: set[str] = set()
    for key in ("keywords", "lifecycle", "engine"):
        raw = data.get(key) or []
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            raise ValueError("{0}: {1} must be an array of strings".format(reserved_json_path(), key))
        names.update(raw)
    return frozenset(names)


def mangled_identifier(original: str, secret_hash: str, used: set[str] | None = None) -> str:
    """Deterministic identifier from secret_hash + original name."""
    reserved = reserved_names()
    taken = set(used) if used is not None else set()
    attempt = 0
    while True:
        msg = "{0}|{1}|{2}|{3}".format(MANGLE_INFO, secret_hash, original, attempt).encode("utf-8")
        digest_hex = hashlib.sha256(msg).hexdigest()
        name = "_f" + digest_hex[:10]
        if name not in reserved and name not in taken:
            return name
        attempt += 1


def source_map_path(export_path: str | Path) -> Path:
    """Sidecar next to the export artifact; not a packed ``res://`` path."""
    return Path(str(export_path) + MAP_SUFFIX)


def source_map_payload(secret_hash: str, mapping: dict[str, str]) -> dict[str, object]:
    ordered = {k: mapping[k] for k in sorted(mapping)}
    return {
        "version": MAP_VERSION,
        "secret_hash": secret_hash,
        "identifiers": ordered,
    }


def source_map_json(secret_hash: str, mapping: dict[str, str]) -> str:
    return json.dumps(source_map_payload(secret_hash, mapping), indent=2, sort_keys=True) + "\n"


def _iter_project_files(root: Path, wanted) -> list[tuple[Path, str]]:
    """(path, project-relative posix path) for files where wanted(rel) is true.

    Skips SKIP_DIR_NAMES (.godot, .git, __pycache__) at any depth.
    """
    root = root.resolve()
    found: list[tuple[Path, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel_parts = path.resolve().relative_to(root).parts
        except ValueError:
            continue
        if any(part in SKIP_DIR_NAMES for part in rel_parts):
            continue
        rel = "/".join(rel_parts)
        if wanted(rel):
            found.append((path, rel))
    found.sort()
    return found


def _under(rel: str, directory: str) -> bool:
    return rel == directory or rel.startswith(directory + "/")


def iter_gdscript_files(root: Path) -> list[Path]:
    """Game scripts to mangle. Never anything under ``addons/``: third-party
    plugins refer to their own members by string and expose APIs that game code
    and scenes call by name, and the user does not own that code."""

    def wanted(rel: str) -> bool:
        return rel.endswith(".gd") and not _under(rel, ADDONS_DIR)

    return [path for path, _rel in _iter_project_files(root, wanted)]


def iter_scan_only_gdscript_files(root: Path) -> list[Path]:
    """Addon scripts: never rewritten, but scanned so that names they mention stay
    unmangled in game scripts. The FortressGD addon is never packed and is skipped."""

    def wanted(rel: str) -> bool:
        return rel.endswith(".gd") and _under(rel, ADDONS_DIR) and not _under(rel, PLUGIN_ADDON)

    return [path for path, _rel in _iter_project_files(root, wanted)]


def collect_scan_only_names(sources: Iterable[str]) -> set[str]:
    """Every identifier token and identifier-shaped string piece in scan-only
    (addon) scripts. Broad on purpose: any name an addon mentions stays unmangled."""
    names: set[str] = set()
    for source in sources:
        names.update(tok.value for tok in tokenize(source) if tok.kind == "ident")
        names |= collect_string_identifier_names(source)
    return names


def collect_resource_reference_names(root: Path) -> set[str]:
    """Every identifier in the project's text scenes, text resources and project.godot.

    Scenes and resources refer to script members by their original text: @export
    values (``speed = 250.0``), editor signal connections (``method="_on_pressed"``),
    AnimationPlayer tracks (``NodePath(".:hp")``), and autoload names. None of these
    names may be renamed. This over-excludes on purpose: an extra unmangled name is
    safe, a missed one breaks the game.
    """

    def wanted(rel: str) -> bool:
        return rel.endswith(TEXT_RESOURCE_SUFFIXES) or rel.split("/")[-1] in TEXT_RESOURCE_NAMES

    names: set[str] = set()
    for path, _rel in _iter_project_files(root, wanted):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names.update(_IDENT_FULL.findall(text))
    return names


def binary_resource_paths(root: Path) -> list[str]:
    """Project-relative *.scn / *.res files, which reference scanning cannot read."""
    return [rel for _path, rel in _iter_project_files(root, lambda rel: rel.endswith(BINARY_RESOURCE_SUFFIXES))]


def find_unsafe_calls(source: str, filename: str = "<gdscript>") -> list[UnsafeCall]:
    tokens = tokenize(source)
    keep_same, keep_only, nonempty = _keep_maps(tokens)
    hits: list[UnsafeCall] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.kind == "ident" and tok.value in UNSAFE_CALLEES:
            j = _skip_ws_comments(tokens, i + 1)
            if j < n and tokens[j].kind == "punct" and tokens[j].value == "(":
                k = _skip_ws_comments(tokens, j + 1)
                if k < n and tokens[k].kind == "string":
                    if not _line_is_kept(tok.line, keep_same, keep_only, nonempty):
                        hits.append(UnsafeCall(path=filename, line=tok.line, kind=tok.value))
        i += 1
    return hits


def collect_user_identifiers(source: str) -> set[str]:
    tokens = tokenize(source)
    keep_same, keep_only, nonempty = _keep_maps(tokens)
    reserved = reserved_names()
    user: set[str] = set()
    class_names: set[str] = set()
    i = 0
    n = len(tokens)

    def skip(idx: int) -> int:
        return _skip_ws_comments(tokens, idx)

    while i < n:
        tok = tokens[i]
        if tok.kind != "ident":
            i += 1
            continue
        kept = _line_is_kept(tok.line, keep_same, keep_only, nonempty)
        if tok.value == "class_name":
            j = skip(i + 1)
            if j < n and tokens[j].kind == "ident":
                class_names.add(tokens[j].value)
                i = j + 1
                continue
        if tok.value in DECL_KEYWORDS:
            j = skip(i + 1)
            if tok.value == "enum":
                i = _collect_enum(tokens, i, j, user, reserved, kept, class_names)
                continue
            if j < n and tokens[j].kind == "ident":
                name = tokens[j].value
                name_kept = kept or _line_is_kept(
                    tokens[j].line, keep_same, keep_only, nonempty
                )
                # Scenes store @export values under the property's original name.
                exported = tok.value == "var" and _has_export_annotation(tokens, i)
                if name not in reserved and name not in class_names and not name_kept and not exported:
                    user.add(name)
                if tok.value == "func":
                    k = skip(j + 1)
                    if k < n and tokens[k].kind == "punct" and tokens[k].value == "(":
                        _collect_params(tokens, k + 1, user, reserved, class_names)
                i = j + 1
                continue
            i += 1
            continue
        i += 1
    user -= reserved
    user -= class_names
    return user


def collect_foreign_member_names(source: str) -> set[str]:
    """Names accessed as ``receiver.name`` through a receiver other than self/super.

    The rewrite cannot tell which object owns such a member (it may be an engine
    object, or a script that never declared it), so these names are not renamed
    anywhere. ``1.5`` is one number token and never yields a ``.`` here.
    """
    tokens = tokenize(source)
    names: set[str] = set()
    for i, tok in enumerate(tokens):
        if tok.kind != "ident":
            continue
        dot = _prev_code_index(tokens, i)
        if dot < 0 or tokens[dot].kind != "punct" or tokens[dot].value != ".":
            continue
        recv = _prev_code_index(tokens, dot)
        if recv >= 0 and tokens[recv].kind == "ident" and tokens[recv].value in ("self", "super"):
            continue
        names.add(tok.value)
    return names


_STRING_PATH_SEP = re.compile(r"[:/.]")
_QUOTES = ('"""', "'''", '"', "'")


def collect_string_identifier_names(source: str) -> set[str]:
    """Identifier-shaped pieces of every string literal in the source.

    Covers string-based reflection such as ``emit_signal("hit")``, ``get("hp")``,
    ``Callable(self, "go")``, ``&"go"``, ``^".:hp"`` and ``"speed:x"``. Content is
    split on ``:``, ``/`` and ``.``; each piece that is a whole identifier is kept
    out of the rename map. Over-exclusion is accepted.
    """
    names: set[str] = set()
    for tok in tokenize(source):
        if tok.kind != "string":
            continue
        text = tok.value
        if text.startswith("&") or text.startswith("^"):
            text = text[1:]
        for quote in _QUOTES:
            if text.startswith(quote):
                text = text[len(quote) :]
                if text.endswith(quote):
                    text = text[: len(text) - len(quote)]
                break
        for piece in _STRING_PATH_SEP.split(text):
            if _IDENT_FULL.fullmatch(piece):
                names.add(piece)
    return names


def rewrite_source(source: str, mapping: dict[str, str], *, strip: bool = True) -> str:
    tokens = tokenize(source)
    if strip:
        tokens = _strip_tokens(tokens)
    out: list[str] = []
    for tok in tokens:
        if tok.kind == "ident" and tok.value in mapping:
            out.append(mapping[tok.value])
        else:
            out.append(tok.value)
    return "".join(out)


def mangle_scripts(
    files: dict[str, str],
    *,
    secret_hash: str,
    rename: bool = True,
    exclude: Iterable[str] = frozenset(),
) -> tuple[dict[str, str], dict[str, str]]:
    """Transform GDScript sources. ``files`` maps relative path → source text.

    Raises MangleError on unmarked ``call("…")`` / ``rpc("…")`` / ``set("…")``.
    When ``rename`` is false, identifiers are left unchanged (no strip either).
    ``exclude`` names are never renamed (e.g. collect_resource_reference_names).
    """
    if not rename:
        return dict(files), {}

    hits: list[UnsafeCall] = []
    for path in sorted(files):
        hits.extend(find_unsafe_calls(files[path], filename=path))
    if hits:
        raise MangleError(_format_unsafe(hits))

    user: set[str] = set()
    for source in files.values():
        user |= collect_user_identifiers(source)
    # A name is renamed everywhere or nowhere. Drop every name that something
    # may reference in a way the rewrite cannot follow.
    user -= set(exclude)
    for source in files.values():
        user -= collect_foreign_member_names(source)
        user -= collect_string_identifier_names(source)

    mapping: dict[str, str] = {}
    used: set[str] = set(reserved_names())
    for original in sorted(user):
        name = mangled_identifier(original, secret_hash, used)
        mapping[original] = name
        used.add(name)

    out = {path: rewrite_source(src, mapping, strip=True) for path, src in files.items()}
    return out, mapping


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    n = len(source)
    line = 1
    col = 1

    def push(kind: str, value: str, start_line: int, start_col: int) -> None:
        tokens.append(Token(kind, value, start_line, start_col))

    while i < n:
        ch = source[i]
        sl, sc = line, col
        if ch == "\r":
            if i + 1 < n and source[i + 1] == "\n":
                push("newline", "\r\n", sl, sc)
                i += 2
            else:
                push("newline", "\r", sl, sc)
                i += 1
            line += 1
            col = 1
            continue
        if ch == "\n":
            push("newline", "\n", sl, sc)
            i += 1
            line += 1
            col = 1
            continue
        if ch in " \t":
            j = i
            while j < n and source[j] in " \t":
                j += 1
            push("space", source[i:j], sl, sc)
            col += j - i
            i = j
            continue
        if ch == "#":
            j = i
            while j < n and source[j] not in "\r\n":
                j += 1
            push("comment", source[i:j], sl, sc)
            col += j - i
            i = j
            continue
        if ch in "\"'":
            value, i, line, col = _read_string(source, i, line, col)
            push("string", value, sl, sc)
            continue
        if ch == "@" and i + 1 < n and _IDENT_START.match(source[i + 1]):
            j = i + 2
            while j < n and _IDENT_CONT.match(source[j]):
                j += 1
            push("annotation", source[i:j], sl, sc)
            col += j - i
            i = j
            continue
        if ch in "$%":
            value, i, line, col = _read_nodepath(source, i, line, col)
            push("nodepath", value, sl, sc)
            continue
        if ch in "&^" and i + 1 < n and source[i + 1] in "\"'":
            prefix = ch
            col += 1
            i += 1
            value, i, line, col = _read_string(source, i, line, col)
            push("string", prefix + value, sl, sc)
            continue
        if _IDENT_START.match(ch):
            j = i + 1
            while j < n and _IDENT_CONT.match(source[j]):
                j += 1
            push("ident", source[i:j], sl, sc)
            col += j - i
            i = j
            continue
        if ch.isdigit():
            j = i + 1
            while j < n and (source[j].isalnum() or source[j] in "._"):
                j += 1
            push("number", source[i:j], sl, sc)
            col += j - i
            i = j
            continue
        push("punct", ch, sl, sc)
        col += 1
        i += 1
    return tokens


def _read_string(source: str, i: int, line: int, col: int) -> tuple[str, int, int, int]:
    n = len(source)
    quote = source[i]
    triple = i + 2 < n and source[i : i + 3] == quote * 3
    start = i
    if triple:
        i += 3
        col += 3
        while i < n:
            if source[i] == "\n":
                line += 1
                col = 1
                i += 1
                continue
            if source[i] == "\r":
                line += 1
                col = 1
                i += 1
                if i < n and source[i] == "\n":
                    i += 1
                continue
            if source[i : i + 3] == quote * 3:
                i += 3
                col += 3
                break
            if source[i] == "\\" and i + 1 < n:
                i += 2
                col += 2
                continue
            i += 1
            col += 1
    else:
        i += 1
        col += 1
        while i < n:
            ch = source[i]
            if ch == "\n":
                line += 1
                col = 1
                i += 1
                continue
            if ch == "\\":
                i += 2 if i + 1 < n else 1
                col += 2
                continue
            i += 1
            col += 1
            if ch == quote:
                break
    return source[start:i], i, line, col


def _read_nodepath(source: str, i: int, line: int, col: int) -> tuple[str, int, int, int]:
    start = i
    i += 1
    col += 1
    n = len(source)
    if i < n and source[i] in "\"'":
        _value, i, line, col = _read_string(source, i, line, col)
        return source[start:i], i, line, col
    if i < n and _IDENT_START.match(source[i]):
        while i < n:
            if _IDENT_CONT.match(source[i]):
                i += 1
                col += 1
                continue
            if source[i] == "/" and i + 1 < n and _IDENT_START.match(source[i + 1]):
                i += 1
                col += 1
                continue
            break
    return source[start:i], i, line, col


def _skip_ws_comments(tokens: list[Token], i: int) -> int:
    n = len(tokens)
    while i < n and tokens[i].kind in ("space", "newline", "comment"):
        i += 1
    return i


def _is_keep_comment(value: str) -> bool:
    return bool(_KEEP_RE.match(value.lstrip()))


def _keep_maps(tokens: list[Token]) -> tuple[set[int], set[int], set[int]]:
    by_line: dict[int, list[Token]] = {}
    for tok in tokens:
        by_line.setdefault(tok.line, []).append(tok)
    keep_same: set[int] = set()
    keep_only: set[int] = set()
    nonempty: set[int] = set()
    for line, toks in by_line.items():
        saw_keep = False
        saw_code = False
        for tok in toks:
            if tok.kind in ("space", "newline"):
                continue
            if tok.kind == "comment":
                if _is_keep_comment(tok.value):
                    saw_keep = True
                continue
            saw_code = True
        if saw_keep or saw_code:
            nonempty.add(line)
        if saw_keep:
            keep_same.add(line)
            if not saw_code:
                keep_only.add(line)
    return keep_same, keep_only, nonempty


def _line_is_kept(line: int, keep_same: set[int], keep_only: set[int], nonempty: set[int]) -> bool:
    if line in keep_same:
        return True
    prev = line - 1
    while prev >= 1:
        if prev in nonempty:
            return prev in keep_only
        prev -= 1
    return False


def _has_export_annotation(tokens: list[Token], var_index: int) -> bool:
    """True when the `var` at var_index carries an @export* annotation.

    Walks back over annotations (and their argument lists) on the same line or on
    the lines right above. @export_group / @export_subgroup / @export_category
    declare nothing and do not count.
    """
    j = _prev_code_index(tokens, var_index)
    while j >= 0:
        tok = tokens[j]
        if tok.kind == "punct" and tok.value == ")":
            depth = 0
            while j >= 0:
                if tokens[j].kind == "punct" and tokens[j].value == ")":
                    depth += 1
                elif tokens[j].kind == "punct" and tokens[j].value == "(":
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            j = _prev_code_index(tokens, j)
            if j < 0 or tokens[j].kind != "annotation":
                return False
            continue
        if tok.kind != "annotation":
            return False
        if tok.value.startswith("@export") and tok.value not in EXPORT_NON_DECL:
            return True
        j = _prev_code_index(tokens, j)
    return False


def _prev_code_index(tokens: list[Token], i: int) -> int:
    """Index of the code token before i (skipping space/newline/comment), or -1."""
    j = i - 1
    while j >= 0 and tokens[j].kind in ("space", "newline", "comment"):
        j -= 1
    return j


def _prev_code(tokens: list[Token], i: int) -> Token | None:
    j = _prev_code_index(tokens, i)
    if j < 0:
        return None
    return tokens[j]


def _collect_params(
    tokens: list[Token],
    start: int,
    user: set[str],
    reserved: frozenset[str],
    class_names: set[str],
) -> None:
    i = start
    n = len(tokens)
    depth = 1
    arg_start = True
    while i < n and depth > 0:
        tok = tokens[i]
        if tok.kind == "punct":
            if tok.value in "([{":
                depth += 1
            elif tok.value in ")]}":
                depth -= 1
                if depth <= 0:
                    break
            elif tok.value == "," and depth == 1:
                arg_start = True
        elif tok.kind == "ident" and depth == 1 and arg_start:
            if tok.value not in reserved and tok.value not in class_names:
                user.add(tok.value)
            arg_start = False
        i += 1


def _collect_enum(
    tokens: list[Token],
    keyword_index: int,
    after_kw: int,
    user: set[str],
    reserved: frozenset[str],
    kept: bool,
    class_names: set[str],
) -> int:
    n = len(tokens)
    i = after_kw
    if i < n and tokens[i].kind == "ident":
        name = tokens[i].value
        if name not in reserved and name not in class_names and not kept:
            user.add(name)
        i += 1
        i = _skip_ws_comments(tokens, i)
    if i < n and tokens[i].kind == "punct" and tokens[i].value == "{":
        i += 1
        depth = 1
        member_start = True
        while i < n and depth > 0:
            tok = tokens[i]
            if tok.kind == "punct":
                if tok.value == "{":
                    depth += 1
                elif tok.value == "}":
                    depth -= 1
                elif tok.value == "," and depth == 1:
                    member_start = True
                elif tok.value == "=" and depth == 1:
                    member_start = False
            elif tok.kind == "ident" and depth == 1 and member_start:
                if tok.value not in reserved and tok.value not in class_names and not kept:
                    user.add(tok.value)
                member_start = False
            i += 1
        return i
    return max(keyword_index + 1, i)


def _strip_tokens(tokens: list[Token]) -> list[Token]:
    """Drop comments; replace assert / print_debug / breakpoint statements with ``pass``.

    ``pass`` is valid wherever a statement is, so a block whose only statement was
    stripped still parses.
    """
    out: list[Token] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok.kind == "comment":
            i += 1
            continue
        if tok.kind == "ident" and tok.value in ("assert", "print_debug"):
            prev = _prev_code(tokens, i)
            dotted = prev is not None and prev.kind == "punct" and prev.value == "."
            j = _skip_ws_comments(tokens, i + 1)
            if not dotted and j < n and tokens[j].kind == "punct" and tokens[j].value == "(":
                k = _consume_paren_group(tokens, j)
                out.append(Token("ident", "pass", tok.line, tok.col))
                i = _skip_trailing_semi(tokens, k)
                continue
        if tok.kind == "ident" and tok.value == "breakpoint":
            prev = _prev_code(tokens, i)
            dotted = prev is not None and prev.kind == "punct" and prev.value == "."
            if not dotted:
                out.append(Token("ident", "pass", tok.line, tok.col))
                i = _skip_trailing_semi(tokens, i + 1)
                continue
        out.append(tok)
        i += 1
    return out


def _consume_paren_group(tokens: list[Token], open_index: int) -> int:
    """Return index after the matching ``)`` for the ``(`` at open_index."""
    i = open_index
    n = len(tokens)
    depth = 0
    while i < n:
        tok = tokens[i]
        if tok.kind == "punct":
            if tok.value == "(":
                depth += 1
            elif tok.value == ")":
                depth -= 1
                i += 1
                if depth <= 0:
                    return i
                continue
        i += 1
    return i


def _skip_trailing_semi(tokens: list[Token], i: int) -> int:
    n = len(tokens)
    j = i
    while j < n and tokens[j].kind == "space":
        j += 1
    if j < n and tokens[j].kind == "punct" and tokens[j].value == ";":
        return j + 1
    return i


def _format_unsafe(hits: Iterable[UnsafeCall]) -> str:
    parts = ["{0}:{1}".format(hit.path, hit.line) for hit in hits]
    kinds = sorted({hit.kind for hit in hits})
    return (
        "unsafe {0}(\"…\") at {1} (use a Callable, or mark with ## fortressgd:keep)".format(
            "/".join(kinds),
            ", ".join(parts),
        )
    )

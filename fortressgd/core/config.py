"""Parse and validate `.fortressgd.toml`. Unknown keys are errors."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fortressgd.core.errors import NEXT_DOCTOR, ConfigError, UserError
from fortressgd.core.paths import example_toml_path, plugin_source_dir
from fortressgd.core.version import GODOT_TAG_ALIASES, SUPPORTED_GODOT, concrete_godot_tag

# DESIGN.md §6. Kept in sync with plugin/addons/fortressgd/schema.json
# (tests assert equality).
ALLOWED_KEYS: dict[str, frozenset[str]] = {
    "root": frozenset({"schema", "godot"}),
    "production": frozenset(
        {
            "dialect",
            "mangle_scripts",
            "nameless_bytecode",
            "sign_packs",
            "verify_on_export",
        }
    ),
    "filters": frozenset({"exclude", "include"}),
    "platforms": frozenset({"build"}),
    "templates": frozenset({"cache_dir"}),
}

CURRENT_SCHEMA = 1

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def load_schema_file(path: Path | None = None) -> dict[str, list[str]]:
    schema_path = path if path is not None else plugin_source_dir() / "schema.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def default_toml_text() -> str:
    return example_toml_path().read_text(encoding="utf-8")


# Must accept exactly the same subset as `_parse_toml` in
# plugin/addons/fortressgd/config.gd, with the same error text. A file one parser
# accepts and the other rejects makes CLI and editor exports diverge.
def parse_toml(text: str) -> dict[str, Any]:
    """Parse the FortressGD TOML subset used by `.fortressgd.toml`."""
    lines = text.splitlines()
    result: dict[str, Any] = {}
    current: dict[str, Any] = result
    current_name = ""
    i = 0
    while i < len(lines):
        stripped = _strip_comment(lines[i]).strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith("[") and stripped.endswith("]") and "=" not in stripped:
            name = stripped[1:-1].strip()
            if not name:
                raise ConfigError("empty table name in .fortressgd.toml", NEXT_DOCTOR)
            if name in result:
                raise ConfigError(
                    "duplicate table [{0}] in .fortressgd.toml".format(name),
                    NEXT_DOCTOR,
                )
            section: dict[str, Any] = {}
            result[name] = section
            current = section
            current_name = name
            i += 1
            continue
        if "=" not in stripped:
            raise ConfigError(
                "invalid line in .fortressgd.toml: {0}".format(stripped),
                NEXT_DOCTOR,
            )
        key, _, rest = stripped.partition("=")
        key = key.strip()
        if not key:
            raise ConfigError("empty key in .fortressgd.toml", NEXT_DOCTOR)
        if key in current:
            raise ConfigError(
                "duplicate key {0} in .fortressgd.toml".format(
                    current_name + "." + key if current_name else key
                ),
                NEXT_DOCTOR,
            )
        assembled = rest.strip()
        while not _value_complete(assembled):
            i += 1
            if i >= len(lines):
                raise ConfigError("unclosed array in .fortressgd.toml", NEXT_DOCTOR)
            assembled = assembled + " " + _strip_comment(lines[i]).strip()
        current[key] = _parse_value(assembled.strip())
        i += 1
    return result


def validate(data: dict[str, Any], *, source: str = ".fortressgd.toml") -> dict[str, Any]:
    unknown: list[str] = []
    for key, val in data.items():
        if isinstance(val, dict):
            if key not in ALLOWED_KEYS or key == "root":
                unknown.append(key)
                continue
            allowed = ALLOWED_KEYS[key]
            for subkey in val:
                if subkey not in allowed:
                    unknown.append("{0}.{1}".format(key, subkey))
        else:
            if key not in ALLOWED_KEYS["root"]:
                unknown.append(key)
    if unknown:
        raise ConfigError(
            "unknown key(s) in {0}: {1}".format(source, ", ".join(unknown)),
            NEXT_DOCTOR,
        )
    if "schema" not in data or "godot" not in data:
        raise ConfigError(
            "{0} must set schema and godot".format(source),
            NEXT_DOCTOR,
        )
    schema = data["schema"]
    if type(schema) is not int:
        raise ConfigError(
            "{0}: schema must be an integer".format(source),
            NEXT_DOCTOR,
        )
    if schema != CURRENT_SCHEMA:
        raise ConfigError(
            "{0}: unsupported schema {1} (expected {2})".format(
                source, schema, CURRENT_SCHEMA
            ),
            NEXT_DOCTOR,
        )
    if not isinstance(data["godot"], str) or not data["godot"]:
        raise ConfigError("{0}: godot must be a string".format(source), NEXT_DOCTOR)

    production = data.get("production")
    if production is not None:
        if not isinstance(production, dict):
            raise ConfigError("{0}: [production] must be a table".format(source), NEXT_DOCTOR)
        for k, v in production.items():
            if type(v) is not bool:
                raise ConfigError(
                    "{0}: production.{1} must be a boolean".format(source, k),
                    NEXT_DOCTOR,
                )

    filters = data.get("filters")
    if filters is not None:
        if not isinstance(filters, dict):
            raise ConfigError("{0}: [filters] must be a table".format(source), NEXT_DOCTOR)
        for k in ("exclude", "include"):
            if k in filters and not _is_str_list(filters[k]):
                raise ConfigError(
                    "{0}: filters.{1} must be an array of strings".format(source, k),
                    NEXT_DOCTOR,
                )

    platforms = data.get("platforms")
    if platforms is not None:
        if not isinstance(platforms, dict):
            raise ConfigError("{0}: [platforms] must be a table".format(source), NEXT_DOCTOR)
        if "build" in platforms and not _is_str_list(platforms["build"]):
            raise ConfigError(
                "{0}: platforms.build must be an array of strings".format(source),
                NEXT_DOCTOR,
            )

    templates = data.get("templates")
    if templates is not None:
        if not isinstance(templates, dict):
            raise ConfigError("{0}: [templates] must be a table".format(source), NEXT_DOCTOR)
        if "cache_dir" in templates and not isinstance(templates["cache_dir"], str):
            raise ConfigError(
                "{0}: templates.cache_dir must be a string".format(source),
                NEXT_DOCTOR,
            )

    return data


def load_path(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise UserError(
            "cannot read {0}: {1}".format(path, exc),
            NEXT_DOCTOR,
        ) from exc
    return validate(parse_toml(text), source=str(path))


def _patched_tags() -> list[str]:
    """Tags with a patches/<tag>/series file (shared folders such as common/ have none)."""
    from fortressgd.core.paths import patches_root

    root = patches_root()
    if not root.is_dir():
        return list(SUPPORTED_GODOT)
    return sorted(p.name for p in root.iterdir() if (p / "series").is_file())


def godot_is_supported(version: str) -> bool:
    """Supported means a patch series exists for the resolved tag, so `doctor`
    and `templates build` agree."""
    return concrete_godot_tag(version) in _patched_tags()


def supported_godot_message() -> str:
    aliases = " and ".join(sorted(GODOT_TAG_ALIASES))
    targets = sorted(set(GODOT_TAG_ALIASES.values()))
    return "{0} ({1} mean {2})".format(", ".join(_patched_tags()), aliases, ", ".join(targets))


def looks_like_secret_blob(text: str) -> bool:
    """True if `text` contains a standalone 64-hex token (a raw secret)."""
    for token in re.findall(r"[0-9a-fA-F]{64}", text):
        if _HEX64.fullmatch(token):
            return True
    return False


def _is_str_list(val: Any) -> bool:
    return isinstance(val, list) and all(isinstance(x, str) for x in val)


def _strip_comment(line: str) -> str:
    out: list[str] = []
    in_str = False
    esc = False
    for ch in line:
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _value_complete(s: str) -> bool:
    t = s.strip()
    if not t:
        return False
    if not t.startswith("["):
        return True
    return _brackets_balanced(t)


def _brackets_balanced(s: str) -> bool:
    depth = 0
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
    return depth == 0 and not in_str


def _parse_value(s: str) -> Any:
    if s == "true":
        return True
    if s == "false":
        return False
    if len(s) >= 2 and s.startswith('"') and s.endswith('"'):
        return _unescape_basic_string(s[1:-1])
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_value(item.strip()) for item in _split_array_items(inner)]
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    raise ConfigError(
        "unsupported value in .fortressgd.toml: {0}".format(s),
        NEXT_DOCTOR,
    )


def _unescape_basic_string(inner: str) -> str:
    out: list[str] = []
    esc = False
    for ch in inner:
        if esc:
            mapping = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}
            if ch not in mapping:
                raise ConfigError(
                    "unsupported string escape in .fortressgd.toml: \\{0}".format(ch),
                    NEXT_DOCTOR,
                )
            out.append(mapping[ch])
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        out.append(ch)
    if esc:
        raise ConfigError("unterminated escape in .fortressgd.toml string", NEXT_DOCTOR)
    return "".join(out)


def _split_array_items(inner: str) -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    in_str = False
    esc = False
    for ch in inner:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
            continue
        if ch == ",":
            item = "".join(buf).strip()
            if item:
                items.append(item)
            buf = []
            continue
        buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items

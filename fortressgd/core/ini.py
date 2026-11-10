"""Line-preserving edits of Godot's INI-style files (export_presets.cfg, project.godot)."""

from __future__ import annotations


def get_ini_value(text: str, section: str, key: str) -> str | None:
    """Raw value of key in [section], or None when the section or key is absent."""
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped[1:-1].strip() == section
            continue
        if in_section and "=" in stripped:
            name, value = stripped.split("=", 1)
            if name.strip() == key:
                return value.strip()
    return None


def upsert_ini_key(text: str, section: str, key: str, value: str) -> str:
    """Set key=value in [section], inserting the section if needed. Preserves other lines."""
    header = "[{0}]".format(section)
    lines = text.splitlines(keepends=True)
    if not lines:
        return "{0}\n{1}={2}\n".format(header, key, value)
    in_section = False
    section_start = None
    next_section = None
    key_line = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            name = stripped[1:-1].strip()
            if in_section:
                next_section = i
                break
            if name == section:
                in_section = True
                section_start = i
            continue
        if in_section and stripped.split("=", 1)[0].strip() == key:
            key_line = i
    assignment = "{0}={1}\n".format(key, value)
    if key_line is not None:
        lines[key_line] = assignment
        return "".join(lines)
    if in_section:
        insert_at = next_section if next_section is not None else len(lines)
        if insert_at > 0 and not lines[insert_at - 1].endswith("\n"):
            lines[insert_at - 1] += "\n"
        lines.insert(insert_at, assignment)
        return "".join(lines)
    extra = ""
    if lines and not "".join(lines).endswith("\n"):
        extra = "\n"
    return "".join(lines) + extra + "\n{0}\n{1}".format(header, assignment)

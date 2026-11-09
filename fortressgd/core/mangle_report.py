"""What stays readable after mangling, and why (``fortressgd mangle-report``).

Mangling is the protection that survives an extracted pack key, so the names it
leaves alone are what a decompiler shows. This module runs the same analysis as
``fortressgd export`` and says, per name left unrenamed, which rule kept it and
which file triggered the rule. It needs no secret: which names are renamed does
not depend on the key, only what they are renamed to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from fortressgd.core.mangle import (
    collect_foreign_member_names,
    collect_string_identifier_names,
    collect_user_identifiers,
    iter_gdscript_files,
    iter_scan_only_gdscript_files,
    resource_reference_index,
    tokenize,
)

# Report order: the rules most worth revisiting first.
SCENE = "referenced from a scene, resource or project.godot"
EXPORT = "@export variable"
FOREIGN = "accessed on another object (obj.name)"
STRING = "named in a string literal"
ADDON = "named in an addon script"
CLASS_NAME = "class_name"
KEEP = "marked fortressgd:keep"
REASONS = (SCENE, EXPORT, FOREIGN, STRING, ADDON, CLASS_NAME, KEEP)
_SKIPPED_REASON = {"@export": EXPORT, "class_name": CLASS_NAME, "fortressgd:keep": KEEP}


@dataclass
class MangleReport:
    renamed: list[str] = field(default_factory=list)
    # name -> reason -> project-relative files that triggered it
    kept: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    def by_reason(self) -> dict[str, dict[str, list[str]]]:
        """reason -> name -> files, in REASONS order. A name can appear under several."""
        out: dict[str, dict[str, list[str]]] = {reason: {} for reason in REASONS}
        for name, reasons in sorted(self.kept.items()):
            for reason, files in reasons.items():
                out[reason][name] = files
        return out

    def to_json(self) -> str:
        return json.dumps(
            {"renamed": self.renamed, "kept": self.kept, "reasons": list(REASONS)},
            indent=2,
            sort_keys=True,
        ) + "\n"


def _relpath(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def analyze_project(root: Path) -> MangleReport:
    """Classify every name the project's scripts declare: renamed, or kept and why."""
    root = Path(root)
    sources = {_relpath(root, p): p.read_text(encoding="utf-8") for p in iter_gdscript_files(root)}
    addons = {
        _relpath(root, p): p.read_text(encoding="utf-8") for p in iter_scan_only_gdscript_files(root)
    }
    scenes = resource_reference_index(root)
    addon_index: dict[str, set[str]] = {}
    for rel, text in addons.items():
        names = {tok.value for tok in tokenize(text) if tok.kind == "ident"}
        names |= collect_string_identifier_names(text)
        for name in names:
            addon_index.setdefault(name, set()).add(rel)

    candidates: set[str] = set()
    skipped: dict[str, dict[str, set[str]]] = {}
    foreign: dict[str, set[str]] = {}
    strings: dict[str, set[str]] = {}
    for rel, text in sorted(sources.items()):
        file_skipped: dict[str, set[str]] = {}
        candidates |= collect_user_identifiers(text, file_skipped)
        for name, reasons in file_skipped.items():
            for reason in reasons:
                skipped.setdefault(name, {}).setdefault(_SKIPPED_REASON[reason], set()).add(rel)
        for name in collect_foreign_member_names(text):
            foreign.setdefault(name, set()).add(rel)
        for name in collect_string_identifier_names(text):
            strings.setdefault(name, set()).add(rel)

    # Same rule order as mangle_scripts: exclusions remove a candidate everywhere.
    kept: dict[str, dict[str, set[str]]] = {}
    for name in candidates:
        for reason, index in ((SCENE, scenes), (ADDON, addon_index), (FOREIGN, foreign), (STRING, strings)):
            if name in index:
                kept.setdefault(name, {})[reason] = set(index[name])
    renamed = sorted(candidates - set(kept))
    for name, reasons in skipped.items():
        if name in renamed:
            continue  # declared normally elsewhere, so it is renamed
        for reason, files in reasons.items():
            kept.setdefault(name, {}).setdefault(reason, set()).update(files)
    return MangleReport(
        renamed=renamed,
        kept={
            name: {reason: sorted(files) for reason, files in reasons.items()}
            for name, reasons in sorted(kept.items())
        },
    )


def summary_line(report: MangleReport) -> str:
    return "mangle: renamed {0} name(s); {1} stay readable (run: fortressgd mangle-report)".format(
        len(report.renamed), len(report.kept)
    )


def format_report(report: MangleReport, *, mangle_on: bool = True, limit: int = 8) -> str:
    lines = []
    if not mangle_on:
        lines.append("note: [production].mangle_scripts is false; exports rename nothing.")
    lines.append("renamed: {0} name(s)".format(len(report.renamed)))
    lines.append("kept readable: {0} name(s)".format(len(report.kept)))
    for reason, names in report.by_reason().items():
        if not names:
            continue
        lines.append("  {0} ({1}):".format(reason, len(names)))
        for shown, (name, files) in enumerate(sorted(names.items())):
            if limit and shown >= limit:
                lines.append("    ... {0} more (use --all)".format(len(names) - limit))
                break
            where = ", ".join(files[:3]) + (", ..." if len(files) > 3 else "")
            lines.append("    {0}  ({1})".format(name, where))
    lines.append("Engine and lifecycle names (_ready, _process, ...) are never renamed and not listed.")
    return "\n".join(lines) + "\n"

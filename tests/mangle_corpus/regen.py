"""Golden corpus for the two manglers (fortressgd/core/mangle.py and fortressgd/plugin/.../mangle.gd).

Each case is a directory:

    <case>/input/**/*.gd       sources, keyed by path relative to input/
    <case>/exclude.txt         optional: names never to rename, one per line
    <case>/expected/**/*.gd    mangled output (absent for error cases)
    <case>/expected_map.json   identifier map, or
    <case>/expected_error.txt  the error message for cases that must fail

Every case uses CORPUS_SECRET_HEX, a fixed test secret: the Python side derives
the mangler key with derive_mangle_key and the GDScript harness derives it with
mangle.gd's mangle_key, so the corpus also holds the two key derivations
together. MAP_SAMPLES checks that both manglers place source maps alike.
Regenerate the expected files from fortressgd/core/mangle.py
deliberately and review the diff:

    python3 tests/mangle_corpus/regen.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

CORPUS = Path(__file__).resolve().parent
ROOT = CORPUS.parents[1]
# Test-only secret. Never use it for a real project.
CORPUS_SECRET_HEX = "0123456789abcdef" * 4
# Export paths whose source-map location both manglers must agree on, relative
# to the project the harness runs in (absolute paths are used as given).
MAP_SAMPLES = (
    "build/linux/game.x86_64",
    "build/windows/game.pck",
    "res://out/game.exe",
    "build/../dist/game.pck",
    "/opt/elsewhere/game.pck",
)


def corpus_mangle_key() -> str:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from fortressgd.core.mangle import derive_mangle_key

    return derive_mangle_key(bytes.fromhex(CORPUS_SECRET_HEX))


def python_map_paths(project: Path) -> dict[str, str]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from fortressgd.core.mangle import source_map_path

    out = {}
    for sample in MAP_SAMPLES:
        rel = sample[len("res://"):] if sample.startswith("res://") else sample
        out[sample] = source_map_path(project, rel).as_posix()
    return out


def iter_cases() -> list[Path]:
    return sorted(p for p in CORPUS.iterdir() if (p / "input").is_dir())


def read_tree(directory: Path) -> dict[str, str]:
    return {
        p.relative_to(directory).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(directory.rglob("*.gd"))
    }


def read_exclude(case: Path) -> list[str]:
    path = case / "exclude.txt"
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_python(case: Path) -> dict:
    """{ok, error, sources, mapping} from core.mangle, the same shape mangle.gd returns."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from fortressgd.core.mangle import MangleError, mangle_scripts

    try:
        sources, mapping = mangle_scripts(
            read_tree(case / "input"), mangle_key=corpus_mangle_key(), rename=True, exclude=read_exclude(case)
        )
    except MangleError as err:
        return {"ok": False, "error": str(err), "sources": {}, "mapping": {}}
    return {"ok": True, "error": "", "sources": sources, "mapping": mapping}


def expected(case: Path) -> dict:
    error = case / "expected_error.txt"
    if error.is_file():
        return {"ok": False, "error": error.read_text(encoding="utf-8").rstrip("\n"), "sources": {}, "mapping": {}}
    return {
        "ok": True,
        "error": "",
        "sources": read_tree(case / "expected"),
        "mapping": json.loads((case / "expected_map.json").read_text(encoding="utf-8")),
    }


def regenerate(case: Path) -> None:
    result = run_python(case)
    shutil.rmtree(case / "expected", ignore_errors=True)
    for name in ("expected_map.json", "expected_error.txt"):
        if (case / name).exists():
            (case / name).unlink()
    if not result["ok"]:
        (case / "expected_error.txt").write_text(result["error"] + "\n", encoding="utf-8")
        return
    for rel, text in result["sources"].items():
        dest = case / "expected" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    (case / "expected_map.json").write_text(
        json.dumps(result["mapping"], indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    for case in iter_cases():
        regenerate(case)
        print("regenerated", case.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

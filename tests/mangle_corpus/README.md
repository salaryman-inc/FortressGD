# Mangler golden corpus

The GDScript mangler exists twice: `fortressgd/core/mangle.py` (used by `fortressgd export`) and `fortressgd/plugin/addons/fortressgd/mangle.gd` (used by editor exports). These cases hold both to the same output.

## Layout

```text
<case>/input/**/*.gd       sources
<case>/exclude.txt         optional: names never to rename, one per line
<case>/expected/**/*.gd    mangled output
<case>/expected_map.json   identifier map
<case>/expected_error.txt  instead of the two above, for cases that must fail
```

Every case uses the test secret `CORPUS_SECRET_HEX` from `regen.py`. Each side derives the mangler key from it itself (`derive_mangle_key` in Python, `mangle_key` in `mangle.gd`), so the corpus also checks that the two key derivations agree. The Godot run also checks that both manglers put source maps in the same place (`MAP_SAMPLES`).

## Adding a case

1. Create `<case>/input/` with one or more `.gd` files (and `exclude.txt` if the case needs project-wide exclusions, as scenes and addons provide in a real export).
2. Run `python3 tests/mangle_corpus/regen.py` from the repo root. It writes the expected files from `fortressgd/core/mangle.py`.
3. Read the diff. The expected files are the spec: commit them only if the output is right.

## Running

- `python3 tests/run.py` runs the Python side (`tests/test_mangle_corpus.py`).
- With a Godot 4.6.2 or 4.7.2 binary, `FORTRESSGD_GODOT_TESTS=1 python3 tests/run.py` also runs `tests/gd/run_mangle_corpus.gd` under Godot and compares `mangle.gd` against the same expected files. Point `GODOT` or `FORTRESSGD_GODOT` at the binary if it is not on `PATH`.

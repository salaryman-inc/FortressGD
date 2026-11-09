# Contributing to FortressGD

Thanks for helping. Read [`DESIGN.md`](DESIGN.md) (the normative spec) and [`THREAT_MODEL.md`](THREAT_MODEL.md) before changing behavior. Security problems go through [`SECURITY.md`](SECURITY.md), not public issues.

## Setup

FortressGD needs Python 3.9+ and has no required dependencies.

```bash
git clone https://github.com/salaryman-inc/FortressGD
cd FortressGD
python3 tests/run.py                 # the full default test suite
python3 bin/fortressgd --help        # run the CLI from the checkout
pip install -e .                     # or put `fortressgd` on PATH from the checkout
```

Optional extras the default suite skips:

| Variable | Needs | Runs |
|---|---|---|
| `FORTRESSGD_GODOT_TESTS=1` | Godot 4.6.2 / 4.7.2 (`GODOT=/path/to/godot`) | The GDScript mangler against the golden corpus |
| `FORTRESSGD_DOCKER_TESTS=1` | Docker | A build of the template image |
| `FORTRESSGD_UNPACKER_TESTS=1` | KeyDot and a protected `.exe` (see [`docs/ci.md`](docs/ci.md)) | The KeyDot regression test |

`tests/test_generator.py` compiles the secret-shard reassembly with each C++ compiler it finds (`g++`, `clang++`, `x86_64-w64-mingw32-g++`) and fails if the optimizer folds the secret into the object; set `FORTRESSGD_REQUIRE_COMPILERS=g++,clang++` to fail instead of skipping a missing one.

`pip install cryptography` exercises the OpenSSL AES path; without it the pure-Python AES runs. CI runs both.

## Layout

The Python package is `fortressgd/`. The editor plugin (`fortressgd/plugin/addons/fortressgd/`), the engine patches (`fortressgd/patches/<tag>/`), the Docker build (`fortressgd/docker/`) and the example config ship inside it, so code must find them through `fortressgd/core/paths.py`, never relative to the repository root. See DESIGN.md §3.

## Rules

From DESIGN.md §15, in short:

- Do not add packers, VMs, anti-debug, license servers, or network checks.
- Do not vendor Godot source. Keep engine patches small; one folder per Godot tag.
- Fail the export rather than ship a recoverable or broken build.
- Errors print `error: …` and the next command to run.
- Update DESIGN.md in the same pull request when behavior changes.
- Never print, log or persist the project secret or anything derived from it.

## Common changes

- **Mangler.** It exists twice: `fortressgd/core/mangle.py` (CLI exports) and `fortressgd/plugin/addons/fortressgd/mangle.gd` (editor exports). Change both, then add or update a case in `tests/mangle_corpus/` (see its README) so CI holds them to the same output.
- **Config keys.** `fortressgd/core/config.py`, `fortressgd/plugin/addons/fortressgd/schema.json` and the GDScript parser in `config.gd` must accept exactly the same input.
- **A new Godot tag.** Follow DESIGN.md §4. The tag is supported only once `fortressgd/patches/<tag>/series` exists and the patches apply.
- **Version bump.** `fortressgd/core/version.py` and `fortressgd/plugin/addons/fortressgd/plugin.cfg` must match; `doctor` and the tests check it.

## Pull requests

- `python3 tests/run.py` passes.
- New behavior has a test.
- Commit messages say what changed and why in plain words.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).

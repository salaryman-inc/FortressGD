# CI and template factory

## GitHub Action

Reference the action from this repository at a release tag, and install the CLI from the same tag so the patches, the Docker build and the CLI agree:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install "fortressgd @ git+https://github.com/salaryman-inc/FortressGD@v0.1.0"

- uses: salaryman-inc/FortressGD/actions/build-templates@v0.1.0
  with:
    godot_version: "4.6.2"
    platforms: "linux,windows"
    secret: ${{ secrets.FORTRESSGD_SECRET }}
```

The action builds from its own checkout of FortressGD, so it needs Docker (GitHub's Ubuntu runners have it) and Python 3.9+, but not an installed CLI. `fortressgd export` and `verify` in later steps do need the CLI and `FORTRESSGD_SECRET`.

Cache key: `fgd-templates-{godot}-{patchset}-{secret_hash}-{platform}` (the Action restores `~/.cache/fortressgd/templates` under that key).

Set `sign_packs: "true"` when the project has `[production].sign_packs = true`. The Action then builds the `-sig` template variant, which refuses unsigned or tampered packs, and appends `-sig` to the cache key.

The secret is an Actions secret passed at **run** time. It is not a Docker build-arg and must not land in image layers.

### Keeping the secret out of logs and caches

On a public repository, Actions logs are world-readable and `actions/cache` entries are readable by any workflow in the repo. One leaked log line gives away the secret, and with it every protected build.

- Pass the secret only from an encrypted **Actions secret** (`${{ secrets.FORTRESSGD_SECRET }}`). Never from a repository or organization variable (`vars.*`), an `env:` value written in the workflow file, or a matrix value: those appear in the run metadata.
- The Action's first step registers `::add-mask::` for the secret, the derived AES key, and the pack-signing seed (hex, both cases), so an accidental print is redacted. Masking is defense in depth, not the control. `secret_hash` is not masked: it is a public identifier that appears in template filenames and in the cache key.
- The build step's output is captured with `tee`. A final `always()` step runs `python3 -m fortressgd.core.leakscan` over the template cache directory, the build log, and any extra `scan_paths` you pass (for example a source-map directory). It looks for the secret, the derived AES key, and the signing seed as raw bytes, hex, and UTF-16 hex. On a hit it deletes the file, prints only the file name, the kind of material, and the offset, and fails the job. A failed job does not save the `actions/cache` entry.
- `fortressgd templates build` runs the same scan on each template and manifest before it writes them to the cache, so a local Docker build has the same guard. It also redacts secret material from a failed container's output before printing it.

You can run the scan on anything yourself:

```bash
FORTRESSGD_SECRET="$SECRET" python3 -m fortressgd.core.leakscan --godot 4.6.2 build/ ~/.cache/fortressgd/templates
```

## Docker templates

`fortressgd/docker/Dockerfile.templates` is digest-pinned. `fortressgd/docker/entrypoint.sh` shallow-clones the Godot tag, `git apply --check` then `git apply` of `fortressgd/patches/<tag>/series` (including `0002-pack-hooks.patch`), copies `dialect.gen.h`, and runs `scons target=template_release production=yes debug_symbols=no`. When `FGD_DIALECT=1`, scons gets `CCFLAGS=-DFORTRESSGD_DIALECT` so pack read/write use `FGD_PACK_MAGIC` and `FGD_INDEX_PERM`.

`SCRIPT_AES256_ENCRYPTION_KEY` is **not** set. The template derives the AES key at runtime via FGD-KDF-1.

Set `FORTRESSGD_SKIP_SCONS=1` only when a full scons cannot finish (local smoke). The entrypoint still applies the series, installs the generated header, and writes the §7 filename plus `manifest.json` with `"kdf": "FGD-KDF-1"`.

## Windows-x86_64

The image installs MinGW and runs `scons platform=windows use_mingw=yes` when `--platform windows` is requested.

If that cross-compile fails in your environment, build on a Windows runner with the same patches and `dialect.gen.h`, then copy the binary to the §7 name. Do not claim a Windows artifact unless that job produced one.

## Unpacker fixtures (optional)

`testdata/fixtures/unpackers.lock.json` pins KeyDot **v1.0.3** (`https://github.com/Titoot/KeyDot`).

Only KeyDot is pinned today. GDRE Tools (gdsdecomp), gdke and GodotPCKExplorer, which DESIGN.md §1 also names, have no regression test yet.

CI obtains the binary from GitHub Releases (do not vendor it):

```bash
curl -L -o keydot.exe \
  https://github.com/Titoot/KeyDot/releases/download/v1.0.3/keydot.exe
# sha256 048cd2db98af3d09612284bdebd7b4f899dfef085edce9f24d3d2b921248f326
export FORTRESSGD_UNPACKER_TESTS=1
export FORTRESSGD_KEYDOT="$PWD/keydot.exe"
python3 tests/run.py
```

When those env vars are set and the binary is present, KeyDot failing to extract the 32-byte key / recover the project from a Phase-2 protected exe is a **pass**. Absence of the binary must not fail the default test run.

## Mangler parity (optional, needs Godot)

`tests/mangle_corpus/` holds golden cases for the GDScript mangler, which exists in Python (`fortressgd/core/mangle.py`, CLI exports) and GDScript (`fortressgd/plugin/addons/fortressgd/mangle.gd`, editor exports). `python3 tests/run.py` always checks the Python side. To check the GDScript side on the same cases, run with a Godot 4.6.2 / 4.7.2 binary:

```bash
export FORTRESSGD_GODOT_TESTS=1
export GODOT=/path/to/Godot_v4.6.2-stable_linux.x86_64
python3 tests/run.py
```

See [`tests/mangle_corpus/README.md`](../tests/mangle_corpus/README.md) for adding cases.

## CI for this repository

`.github/workflows/ci.yml` runs on every push and pull request:

- `python3 tests/run.py` on Python 3.9 (in the official `python:3.9` image, since `setup-python` no longer ships it for current runners), 3.11, 3.13 and 3.14, plus once with `cryptography` installed. This includes `git apply --check` of every patch series against the upstream Godot tag.
- A wheel and sdist build, installed outside the checkout, that must run `init`, `secret generate` and `doctor` and ship the plugin, patches and Docker files.
- The GDScript mangler under the official Godot 4.6.2 and 4.7.2 editors against `tests/mangle_corpus/`.
- The shard reassembly from the engine patch compiled with g++, clang++ and MinGW at `-O2` and `-O3`; the job fails if any bytes of the pack key or the secret reach an object file (DESIGN.md §5.2).

`.github/workflows/e2e.yml` compiles Godot, so it runs weekly, on demand, and on pushes to `main` that touch the patches, the Docker build, the generator or the export code. For each supported tag it:

1. builds Linux and Windows templates in Docker with a throwaway secret,
2. exports `testdata/sample_project` with the official editor (derived key and mangling, `dialect = false`) and runs `verify`,
3. checks `export_presets.cfg` is restored, and runs the exported Linux game headless,
4. runs the pinned KeyDot against the protected Windows build on a Windows runner.

Not covered yet: the dialect path (it needs a patched headless editor build), `sign_packs`, and GDRE Tools, gdke and GodotPCKExplorer.

# CI and template factory

## GitHub Action

```yaml
- uses: ./actions/build-templates
  with:
    godot_version: "4.6.2"
    platforms: "linux,windows"
    secret: ${{ secrets.FORTRESSGD_SECRET }}
```

Cache key: `fgd-templates-{godot}-{patchset}-{secret_hash}-{platform}` (the Action restores `~/.cache/fortressgd/templates` under that key).

The secret is an Actions secret passed at **run** time. It is not a Docker build-arg and must not land in image layers.

## Docker templates

`docker/Dockerfile.templates` is digest-pinned. `docker/entrypoint.sh` shallow-clones the Godot tag, `git apply --check` then `git apply` of `patches/<tag>/series` (including `0002-pack-hooks.patch`), copies `dialect.gen.h`, and runs `scons target=template_release production=yes debug_symbols=no`. When `FGD_DIALECT=1`, scons gets `CCFLAGS=-DFORTRESSGD_DIALECT` so pack read/write use `FGD_PACK_MAGIC` and `FGD_INDEX_PERM`.

`SCRIPT_AES256_ENCRYPTION_KEY` is **not** set. The template derives the AES key at runtime via FGD-KDF-1.

Set `FORTRESSGD_SKIP_SCONS=1` only when a full scons cannot finish (local smoke). The entrypoint still applies the series, installs the generated header, and writes the §7 filename plus `manifest.json` with `"kdf": "FGD-KDF-1"`.

## Windows-x86_64

The image installs MinGW and runs `scons platform=windows use_mingw=yes` when `--platform windows` is requested.

If that cross-compile fails in your environment, build on a Windows runner with the same patches and `dialect.gen.h`, then copy the binary to the §7 name. Do not claim a Windows artifact unless that job produced one.

## Unpacker fixtures (optional)

`testdata/fixtures/unpackers.lock.json` pins KeyDot **v1.0.3** (`https://github.com/Titoot/KeyDot`).

CI obtains the binary from GitHub Releases (do not vendor it):

```bash
curl -L -o keydot.exe \
  https://github.com/Titoot/KeyDot/releases/download/v1.0.3/keydot.exe
# sha256 048cd2db98af3d09612284bdebd7b4f8-99dfef085edce9f24d3d2b921248f326
export FORTRESSGD_UNPACKER_TESTS=1
export FORTRESSGD_KEYDOT="$PWD/keydot.exe"
python3 tests/run.py
```

When those env vars are set and the binary is present, KeyDot failing to extract the 32-byte key / recover the project from a Phase-2 protected exe is a **pass**. Absence of the binary must not fail the default test run.

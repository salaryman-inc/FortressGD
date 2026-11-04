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

Set `sign_packs: "true"` when the project has `[production].sign_packs = true`. The Action then builds the `-sig` template variant, which refuses unsigned or tampered packs, and appends `-sig` to the cache key.

The secret is an Actions secret passed at **run** time. It is not a Docker build-arg and must not land in image layers.

### Keeping the secret out of logs and caches

On a public repository, Actions logs are world-readable and `actions/cache` entries are readable by any workflow in the repo. One leaked log line gives away the secret, and with it every protected build.

- Pass the secret only from an encrypted **Actions secret** (`${{ secrets.FORTRESSGD_SECRET }}`). Never from a repository or organization variable (`vars.*`), an `env:` value written in the workflow file, or a matrix value: those appear in the run metadata.
- The Action's first step registers `::add-mask::` for the secret, the derived AES key, and the pack-signing seed (hex, both cases), so an accidental print is redacted. Masking is defense in depth, not the control. `secret_hash` is not masked: it is a public identifier that appears in template filenames and in the cache key.
- The build step's output is captured with `tee`. A final `always()` step runs `python3 -m core.leakscan` over the template cache directory, the build log, and any extra `scan_paths` you pass (for example a source-map directory). It looks for the secret, the derived AES key, and the signing seed as raw bytes, hex, and UTF-16 hex. On a hit it deletes the file, prints only the file name, the kind of material, and the offset, and fails the job. A failed job does not save the `actions/cache` entry.
- `fortressgd templates build` runs the same scan on each template and manifest before it writes them to the cache, so a local Docker build has the same guard. It also redacts secret material from a failed container's output before printing it.

You can run the scan on anything yourself:

```bash
FORTRESSGD_SECRET="$SECRET" python3 -m core.leakscan --godot 4.6.2 build/ ~/.cache/fortressgd/templates
```

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
# sha256 048cd2db98af3d09612284bdebd7b4f899dfef085edce9f24d3d2b921248f326
export FORTRESSGD_UNPACKER_TESTS=1
export FORTRESSGD_KEYDOT="$PWD/keydot.exe"
python3 tests/run.py
```

When those env vars are set and the binary is present, KeyDot failing to extract the 32-byte key / recover the project from a Phase-2 protected exe is a **pass**. Absence of the binary must not fail the default test run.

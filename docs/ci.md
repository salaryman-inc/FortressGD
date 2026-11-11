# CI and template factory

## GitHub Action

Reference the action from this repository at a release tag, and install the CLI wheel from the same release so the patches, the build images and the CLI agree:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install "fortressgd @ https://github.com/salaryman-inc/FortressGD/releases/download/v0.2.0/fortressgd-0.2.0-py3-none-any.whl"

- uses: salaryman-inc/FortressGD/actions/build-templates@v0.2.0
  with:
    godot_version: "4.6.2"
    platforms: "linux,windows"
    secret: ${{ secrets.FORTRESSGD_SECRET }}
```

The action builds from its own checkout of FortressGD, so it needs Docker (GitHub's Ubuntu runners have it) and Python 3.9+, but not an installed CLI. `fortressgd export` and `verify` in later steps do need the CLI and `FORTRESSGD_SECRET`.

A checkout of the tag cannot contain the digests of build images that only exist after the tag is built. So at a release tag, or at a commit SHA a release tag points at, the action downloads the release's `images.lock.json` and checks it with `gh attestation verify`: it must come from this repository's `release.yml`, at that tag (and that commit, for a SHA ref), on a GitHub-hosted runner. Then `templates build` pulls the pinned images and relinks. At any other ref the action prints a notice and `templates build` compiles the build image on the runner, which takes 35–45 minutes per platform. It uses `github.token` for the download and the check.

Cache key: `fgd-templates-{godot}-{patchset}-{secret_hash}-g{generator}-{platforms}-e{key_epoch}` (the Action restores `~/.cache/fortressgd/templates` under that key).

Set `key_epoch` to the project's `[production].key_epoch` (default `"0"`). The Action builds templates for that pack key, masks it in logs, and scans outputs for it.

Set `sign_packs: "true"` when the project has `[production].sign_packs = true`. The Action then builds the `-sig` template variant, which refuses unsigned or tampered packs, and appends `-sig` to the cache key.

The secret is an Actions secret that only the host-side `fortressgd` process reads. It never enters the Docker build container: the container gets `fortressgd_gen.cpp` (the encoded pack key and public values, DESIGN.md §18.3) and the public `secret_hash`.

### Keeping the secret out of logs and caches

On a public repository, Actions logs are world-readable and `actions/cache` entries are readable by any workflow in the repo. One leaked log line gives away the secret, and with it every protected build.

- Pass the secret only from an encrypted **Actions secret** (`${{ secrets.FORTRESSGD_SECRET }}`). Never from a repository or organization variable (`vars.*`), an `env:` value written in the workflow file, or a matrix value: those appear in the run metadata.
- The Action's first step registers `::add-mask::` for the secret, the mangler key, the derived AES key, and the pack-signing seed (hex, both cases), so an accidental print is redacted. Masking is defense in depth, not the control. `secret_hash` is not masked: it is a public identifier that appears in template filenames and in the cache key.
- The build step's output is captured with `tee`. A final `always()` step runs `python3 -m fortressgd.core.leakscan` over the template cache directory, the build log, and any extra `scan_paths` you pass (for example a source-map directory). It looks for the secret, the mangler key, the derived AES key, and the signing seed as raw bytes, hex, and UTF-16 hex. On a hit it deletes the file, prints only the file name, the kind of material, and the offset, and fails the job. A failed job does not save the `actions/cache` entry.
- `fortressgd templates build` runs the same scan on each template and manifest before it writes them to the cache, so a local Docker build has the same guard. It also redacts secret material from a failed container's output before printing it.

You can run the scan on anything yourself:

```bash
FORTRESSGD_SECRET="$SECRET" python3 -m fortressgd.core.leakscan --godot 4.6.2 build/ ~/.cache/fortressgd/templates
```

## Docker templates

Three images, all from `fortressgd/docker/`:

- **The toolchain image**, `fortressgd-templates:<hash>`, from `Dockerfile.templates` (digest-pinned Ubuntu, SCons, GCC, MinGW). `<hash>` covers the Dockerfile and `entrypoint.sh`.
- **A build image** per Godot tag and platform, `fortressgd-build:godot<tag>-<platform>-<arch>-fgd<patchset>-<h8>`, from `Dockerfile.build` on top of the toolchain image. Its entrypoint run (`FGD_MODE=prebuild`) clones the Godot tag, applies `fortressgd/patches/<tag>/series` and compiles the whole tree against `patches/common/fortressgd_gen_placeholder.cpp`, whose functions trap. It keeps the object files and SCons state and records what a relink must match (patchset, tag, platform, arch, defines, LTO mode). It holds no secret. Releases publish these images (`docs/releasing.md`); the wheel pins their digests.
- **A template** is built in the build image with `FGD_MODE=relink`. The host mounts the project's generated `fortressgd_gen.cpp` read-only. The entrypoint refuses the placeholder and any file the generator did not write, replays the prebuild's SCons arguments with no network, and fails unless SCons recompiled `core/fortressgd_gen.cpp`. Then it strips the binary and writes the §7 filename plus `manifest.json`.

The SCons build is `target=template_release production=yes debug_symbols=no` with full LTO (DESIGN.md §18.4). The FortressGD defines go through Godot's lowercase `cppdefines` option: `FORTRESSGD_OPCODE_MAP`, `FORTRESSGD_NAMELESS`, `FORTRESSGD_SIGN_PACKS` and `FORTRESSGD_DIALECT`. Godot 4 drops an uppercase `CCFLAGS=` without a warning, so after the build the entrypoint checks that the binary contains the pack-signature error message and fails if it does not. `sign_packs` reaches only `core/io/file_access_pack.cpp`, through a header the build writes per template, so the `-sig` variant also relinks.

`SCRIPT_AES256_ENCRYPTION_KEY` is **not** set. The template derives the AES key at runtime from its generated code.

Build images are built with the dialect on, because the dialect changes a header included across the engine. A template with `dialect = false` is therefore compiled from source in a fresh toolchain container (`FGD_MODE=source`), and so is any template built with `--from-source`. Set `FORTRESSGD_SKIP_SCONS=1` only when a full scons cannot finish (local smoke); it applies to source builds only.

`fortressgd templates build --editor` runs the entrypoint from source with `FGD_TARGET=editor`. It mounts the fixed `fortressgd/patches/common/fortressgd_editor_dialect.h` as `dialect.gen.h` instead of generated code and passes no secret hash, so the editor holds nothing project-specific. It builds `scons platform=linuxbsd target=editor debug_symbols=no` with only `FORTRESSGD_DIALECT`, without LTO, since the editor is never shipped. The entrypoint refuses generated code for the editor and the editor header for a template, and checks that the editor binary reads `FORTRESSGD_PACK_PARAMS`. `fortressgd export` sets that variable to `1:<magic hex>:<field order>` for the one export it runs.

## Template build times

Measured on GitHub-hosted `ubuntu-latest` runners by the e2e workflow (Godot 4.6.2 and 4.7.2), and locally where noted:

| Build | Time |
|---|---|
| Warm Linux template: relink in a pulled build image (DESIGN.md §18.2 goal: under 600 s) | 358–562 s |
| Warm Windows template (MinGW relinks without the LTO plugin; local) | 8–10 s |
| Build image compiled on the runner, including the first relink (no pinned image) | about 21–34 min (1248–2040 s) |
| Linux template from source (`dialect = false` or `--from-source`) | about 18–25 min |
| Windows template from source | about 30–40 min |
| Shared export editor (`--editor`), from source, once per Godot tag | about 35 min |

A full-LTO relink reoptimizes the whole program, so it gains little from more cores (252 s on 4 local cores, about 165 s on 16). If hosted-runner times go over 600 s, DESIGN.md §18.4 switches templates to ThinLTO with a link cache.

## Windows-x86_64

The image installs MinGW and runs `scons platform=windows use_mingw=yes` when `--platform windows` is requested.

If that cross-compile fails in your environment, build on a Windows runner with the same patches and the project's generated `fortressgd_gen.cpp`, then copy the binary to the §7 name. Do not claim a Windows artifact unless that job produced one.

## Unpacker fixtures (optional)

`testdata/fixtures/unpackers.lock.json` pins KeyDot **v1.0.3** (`https://github.com/Titoot/KeyDot`).

Only KeyDot is pinned today. The end-to-end workflow also runs the latest GDRE Tools release (below). gdke and GodotPCKExplorer, which DESIGN.md §1 also names, have no regression test yet.

CI obtains the binary from GitHub Releases (do not vendor it):

```bash
curl -L -o keydot.exe \
  https://github.com/Titoot/KeyDot/releases/download/v1.0.3/keydot.exe
# sha256 048cd2db98af3d09612284bdebd7b4f899dfef085edce9f24d3d2b921248f326
export FORTRESSGD_UNPACKER_TESTS=1
export FORTRESSGD_KEYDOT="$PWD/keydot.exe"
python3 tests/run.py
```

Set `FORTRESSGD_PROTECTED_EXE` to the protected `game.exe`, and `FORTRESSGD_PROTECTED_PCK` to its `game.pck` (it defaults to `game.pck` next to the exe). KeyDot prints a 32-byte "key" whenever its pattern scan lands somewhere, even on unrelated bytes, so the test does not count output as a recovery. It tries every 64-hex value KeyDot prints against the pack's encrypted directory, whose plaintext MD5 shows whether a key is right. The test fails only if one of them decrypts it. It also fails if KeyDot printed nothing or the pack directory is not encrypted, because then the check proves nothing. Absence of the binary must not fail the default test run.

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
- The shard reassembly from the engine patch compiled with g++, clang++ and MinGW at `-O2` and `-O3`; the job fails if any bytes of the pack key or the secret reach an object file (DESIGN.md §5.2). The same job compiles the engine's Ed25519 verifier and the shared export editor's `FORTRESSGD_PACK_PARAMS` reader and checks them against the Python side.

`.github/workflows/e2e.yml` compiles Godot, so it runs weekly, on demand, and on pushes to `main` that touch the patches, the Docker build, the generator or the export code. Every build is its own job, so a run takes about as long as its slowest build (about 45–55 minutes). The toolchain image comes from an `actions/cache` entry keyed by its hash, so it is built once per `Dockerfile.templates` change rather than in every job. For each supported tag it:

1. builds Linux and Windows templates in Docker with a throwaway secret,
2. exports `testdata/sample_project` with the official editor (derived key and mangling, `dialect = false`) and runs `verify`,
3. checks `export_presets.cfg` is restored, and runs the exported Linux game headless,
4. runs the **latest** GDRE Tools release (gdsdecomp) with `--recover` on the protected Linux pack and fails if any script contents come back (`.github/actions/gdre-check`). A control run first lists a plain pack, so a GDRE that cannot run on the runner fails the job instead of passing it. The version tested is in the job summary.
5. turns on `sign_packs`, builds the `-sig` Linux template, exports a signed pack and runs it, then checks the same template refuses the earlier unsigned pack and a copy with a corrupted signature,
6. runs the pinned KeyDot against the protected Windows build on a Windows runner,
7. in a separate job with `dialect = true` (and mangling), builds the shared export editor, and builds a dialect Linux template the 0.2 way: it compiles the build image, then relinks the template in it. It exports with the official editor also on `FORTRESSGD_GODOT`, checks the pack is not stock GDPC, runs GDRE Tools against it as in step 4, runs it with the template, and checks the editor exits on a malformed `FORTRESSGD_PACK_PARAMS` without writing a pack.
8. on Godot 4.7.2, measures two warm relinks in that build image: a second project's template (another secret), and the first project's at `key_epoch = 1`. Then it runs the cross-build check below on the three templates.

### Cross-build check

DESIGN.md §18.7 requires that builds of different projects, and of one project at different key epochs, differ in what a static tool could rely on. `tests/cross_build.py` checks two things on the three Linux templates, A (the project), B (another secret) and A at epoch 1:

- **A reference extractor.** It is written from A's generated `fortressgd_gen.cpp` only, as a FortressGD-aware tool for one build would be. It finds A's key pieces and their decode constants in A's template, records where they sit relative to A's one unique long array, and decodes them with A's chain of operations. Pieces of one or two bytes have arrays that also occur by chance; for those it keeps the placement that decodes to A's key, which the author of such a tool would check against A. It must recover A's key from A, and it must fail on B and on A at epoch 1.
- **Shared machine code.** In each template it finds the instructions that address that build's key arrays, using the build's own source, and takes the code from the first such instruction to the last. Two builds' key code must not share a run of more than 32 instructions once addresses and branch targets are masked out. A against itself is the control: it must share more than 32, or the comparison found nothing to compare.

Results go to the job summary, and the longest shared run of each pair goes to the log.

| Where | Key code per build | Longest run shared with A |
|---|---|---|
| e2e run 42951715331, Linux 4.7.2 (full LTO) | 494 instructions | B: 4 instructions (29 bytes); A at epoch 1: 12 (54 bytes) |
| Local, Windows 4.6.2 templates | 325–453 instructions | B: 3 (22 bytes); A at epoch 1: 4 (24 bytes) |
| 580 random secrets at two epochs each, `fortressgd_gen.cpp` compiled alone (MinGW `-O2`), 1,157 pairs | 82–424 instructions | median 4, 99th percentile 10–17 per sample, maximum 26 |

What two builds share is one operation's loop. The generator emits a fixed loop for each kind of operation, so when two builds each have a key piece of the same length whose chain starts with the same operations, those loops compile to the same instructions. Different secrets and different epochs of one secret behave the same way. The limit of 32 sits above everything measured, so a run's random secrets do not fail it by chance, and below the 82 instructions of the smallest key routine measured.

These checks show that builds differ. They do not show that no static extractor for FortressGD builds in general can be written: a tool that recognizes the generator's grammar of operations, rather than one build's bytes, is not ruled out, and the fixed loop per operation is exactly what such a tool would look for. The unit tests in `tests/test_cross_build.py` cover the extractor and the comparison without a Godot build.

GDRE is deliberately unpinned: the point is to notice when a new release learns to read FortressGD builds. KeyDot stays pinned by sha256 in `unpackers.lock.json`.

Not covered yet: exporting and running a build at a key epoch above 0, signed packs with the dialect, Windows dialect templates, gdke and GodotPCKExplorer.

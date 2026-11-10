# FortressGD

Open-source **release toolchain** for Godot 4. Not a fork. Not DRM. Not anti-cheat.

> Export a Godot game that stock GDRE/KeyDot cannot one-click recover, without maintaining a fork. This raises the cost of automated recovery. It does not make a local client unextractable.

Designers keep the official Godot editor. Custom **export templates** are built in Docker or CI from a pinned Godot tag plus a small patch quilt. Production exports refuse to ship source, and `fortressgd verify` fails CI if they did.

Supported engine tags: **Godot 4.6.2** and **4.7.2** stable (`4.7` and `4.7.x` in config mean 4.7.2). Other 4.7 patch releases are not supported until they have a patch folder. See [`DESIGN.md`](DESIGN.md) §4.

Start with leak checks on the official editor — no Docker, no custom templates. Add derived-key encryption, pack dialect, and mangling when you are ready to ship a Release PCK.

---

## Features

**Export hygiene**

- Production presets skip GDScript **text**, C# source files, .NET `.pdb` symbols, DCC work files, plugin internals, and source maps unless you allowlist a path
- **Shaders:** Godot ships `.gdshader` / `.gdshaderinc` as plain text. `verify` fails if a packed shader still contains `//` or `/* */` comments; strip them before release, or list the path in `[filters].include` to accept it. FortressGD does not minify shaders yet
- **C# caveat:** a .NET game still ships its compiled assembly, which decompiles to near-original C#. FortressGD does not obfuscate it; `doctor` and `export` warn on .NET projects (see [`THREAT_MODEL.md`](THREAT_MODEL.md))
- Official-editor workflow: add the `fortressgd_production` feature tag and export as usual
- `fortressgd verify` lists packed paths and fails CI if excluded files leaked

**Derived encryption key**

- PCK AES-256 key is derived from the project secret (`FGD-KDF-1`, HKDF-SHA256) when the template is built, and stored only as masked shards, never as a raw 32-byte blob next to a known error string
- The project secret itself never ships: no template or pack contains it, so extracting a build's key does not reveal the secret or the signing seed. That key does open every build of the project for the same Godot version and key epoch, until you bump `key_epoch` or rotate the secret
- Custom `template_release` binaries built in Docker from `fortressgd/patches/<godot-tag>/`
- CLI injects the derived key for one export process only; it is never written to `export_presets.cfg`

**Per-project pack dialect** (optional, on by default in the example config)

- Pack magic and index field order come from the project secret
- Stock GDPC parsers cannot list the pack; `verify` requires that they fail
- Export uses the shared FortressGD export editor (`--export-pack`), built once per Godot tag; designers still use the official editor day-to-day

**GDScript mangling** (optional, on by default in the example config)

- Strips comments, `assert`, `print_debug`, and `breakpoint`
- Renames user identifiers with an HMAC keyed from the project secret, so names cannot be reversed without it (not from `secret_hash`, which appears in logs and cache keys)
- Unmarked `call("name")` / `rpc("name")` / `set("prop")` **fail the export** — use Callables
- Never rewrites scripts under `addons/`; names an addon mentions stay unmangled in your scripts
- Leaves names alone that it cannot follow: members accessed on other objects, names in string literals, `@export` vars, and names used in scenes, resources and `project.godot`
- `fortressgd mangle-report` lists every name left readable, the rule that kept it and the file that triggered it (no secret needed); `export` prints a one-line summary
- Writes the source map (`*.fortressgd.map.json`) to `.fortressgd/maps/` in the project, never inside the pack or next to the artifact: the map reverses all mangling, and build folders get uploaded whole. `fortressgd init` suggests git-ignoring `.fortressgd/`, and `verify` fails if a map sits next to an artifact

**Nameless bytecode** (off by default)

- Packed `.gdc` omits stock identifier/line tables; runtime names live in an `FGDN` trailer
- `verify` fails if those debug tables are still present

**Pack signatures** (off by default)

- Ed25519 signature over the pack index
- Public key is compiled into the template; the private seed is derived from the project secret and is not persisted. The secret never ships, so extracting a template's pack key does not let anyone sign packs

**Toolchain**

- One config file (`.fortressgd.toml`, committed, no secrets)
- CLI + editor plugin share the same backend
- GitHub Action to build and cache templates
- `doctor` checks config, Godot version, plugin drift, and secret presence

---

## What it does / does not

**Does**

- Keep the official editor for day-to-day work
- Build `template_release` binaries in Docker from `fortressgd/patches/<godot-tag>/`
- Derive the PCK AES key (`FGD-KDF-1`) instead of embedding the raw blob
- Optionally change pack magic and index layout per project secret
- Strip source (`.gd` text, `.cs`, DCC files, source maps) from Release
- Optionally mangle GDScript identifiers at export
- Fail export or CI when the artifact is still a recoverable project

**Does not**

- Maintain a Godot fork
- Virtualize the exe (no VMProtect-class packer)
- Stop debugger memory dumps
- Protect macOS / Android / iOS / Web in v1 (vanilla export only; do not claim those are protected)
- Replace a server for secrets or anti-cheat

A debugger can still dump decrypted resources from a running client. That is accepted and written down in [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## Requirements

- Python **3.9+**
- Godot **4.6.2** or **4.7.2** (official editor on `PATH`, or `GODOT` / `FORTRESSGD_GODOT`)
- Docker, for template builds
- A 32-byte secret, 64 hex chars, **not in git** (`.fortressgd.secret` or `FORTRESSGD_SECRET`)

You do not need SCons or a local Godot source tree on designer machines.

Protected platforms in v1: **Windows** and **Linux** (x86_64). Other Godot export presets may still run vanilla; they are not FortressGD-protected.

---

## Install

Install a tagged release with pip. The editor plugin, the engine patches and the Docker build files ship inside the package, so you do not need a checkout:

```bash
pip install "fortressgd @ git+https://github.com/salaryman-inc/FortressGD@v0.1.0"
cd /path/to/your/godot/project
fortressgd --version
```

Run every command from your **Godot project root** (the directory with `project.godot`).

To run from a source checkout without installing, use `bin/fortressgd` (or `python3 -m fortressgd` from the checkout root):

```bash
python3 /path/to/FortressGD/bin/fortressgd --help
```

FortressGD has no required dependencies. For large projects, install the optional `fast` extra: it adds the `cryptography` package so pack encryption and decryption (in `verify`, `export` signing, and the nameless-bytecode check) run through OpenSSL, roughly 700× faster than the built-in pure-Python AES. Both produce identical bytes.

```bash
pip install "fortressgd[fast] @ git+https://github.com/salaryman-inc/FortressGD@v0.1.0"
```

---

## Quick start

Hygiene-only (official editor, no Docker): see [`docs/getting-started.md`](docs/getting-started.md).

Full production export (derived key + dialect + mangling):

```bash
cd /path/to/your/godot/project

# 1. Config, plugin, .gitignore
fortressgd init

# 2. 32-byte secret (mode 0600). Never commit this file.
fortressgd secret generate
export FORTRESSGD_SECRET="$(cat .fortressgd.secret)"

# 3. init already enabled the FortressGD plugin in project.godot.
#    On the Release preset: GDScript Export Mode = Binary tokens (or compressed),
#    and add the custom feature tag fortressgd_production.

# 4. Build custom templates (Docker). Repeat per platform you ship.
fortressgd templates build --godot 4.6.2 --platform linux
fortressgd templates build --godot 4.6.2 --platform windows

# 5. Export. With verify_on_export = true (the default) export also runs verify
#    and exits 2 on a leak. Run verify on its own in CI or on any artifact.
fortressgd export --preset Linux
fortressgd verify path/to/your_game.pck
```

Rotating `FORTRESSGD_SECRET` requires rebuilding templates. Old packs will not load. That is intended. See the rotation runbook in [`docs/secrets.md`](docs/secrets.md).

---

## Usage

### Hygiene only (no custom templates)

Use this first. It keeps source and work files out of a Release pack and proves it with `verify`.

```bash
cd /path/to/your/godot/project
fortressgd init
```

`init` also enables the **FortressGD** plugin in `project.godot`. Then in the official editor:

1. Open **Project → Export** on the Release preset (not debug).
2. Set **GDScript Export Mode** to **Binary tokens** or **Compressed binary tokens**.
3. Add the custom feature tag `fortressgd_production`.
4. Export PCK/ZIP or a full project as usual.

```bash
fortressgd verify path/to/game.pck
# also: fortressgd verify path/to/game.exe
```

Example success:

```text
ok: no production leaks in game.pck (42 packed files)
```

Example failure (exit 2):

```text
error: leaked or unencrypted file(s) in game.pck
  res://main.gd (*.gd)
  res://icon.psd (*.psd)
Run: fortressgd doctor
```

Allowlist a path that would otherwise fail (for example a text script a mod hook needs):

```toml
[filters]
include = ["mods/hook.gd"]
```

Re-export, then `fortressgd verify` again.

Presets **without** `fortressgd_production` are not force-filtered. Keep a debug preset without the tag.

### Encrypted Release PCK (derived AES key)

When you are ready so stock KeyDot cannot one-click extract a 32-byte key. Turn dialect off to stay on official encrypt-PCK:

```toml
[production]
dialect = false
mangle_scripts = false
```

```bash
export FORTRESSGD_SECRET="$(cat .fortressgd.secret)"
fortressgd doctor
fortressgd templates build --godot 4.6.2 --platform linux
fortressgd export --preset Linux      # verifies the artifact when verify_on_export = true
fortressgd verify build/game.pck      # the same check, for CI or a copied artifact
```

`export` sets `GODOT_SCRIPT_ENCRYPTION_KEY` to `FGD-KDF-1(secret, salt)` for that process only, points the preset at the cached FortressGD template, turns on PCK and directory encryption, and restores `export_presets.cfg` afterwards.

Godot encrypts a file's contents only when its path matches the preset's **Encryption Include Filters**, and an empty filter encrypts no contents at all, only the file list. So when that filter is empty, `export` sets it to `*` for its run and every file body is encrypted. A filter you set yourself is kept, for example to leave large media unencrypted for load speed; scripts must still match it. Missing templates print the exact `templates build` command to run.

The exported pack's directory is encrypted with that derived key, so `verify` reads it with the project secret and the `godot` version from `.fortressgd.toml`. Without the secret, `verify` exits 1 and says so. In a pack with an encrypted directory, `verify` exits 2 if no file body is encrypted (the empty-filter mistake) or if any script body is unencrypted; `[filters].include` exempts a path.

### Full production (dialect + mangling)

This is the example `.fortressgd.toml` default:

```toml
[production]
dialect = true
mangle_scripts = true
nameless_bytecode = false
sign_packs = false
```

```bash
export FORTRESSGD_SECRET="$(cat .fortressgd.secret)"

fortressgd templates build --editor --godot 4.6.2      # once per Godot tag; needs no secret
fortressgd templates build --godot 4.6.2 --platform linux
fortressgd export --preset Linux      # verifies the artifact when verify_on_export = true
fortressgd verify build/game.pck      # the same check, for CI or a copied artifact
```

`templates build` produces `template_release` binaries (the runtime). Dialect **packing** needs the FortressGD **export editor**: a headless Godot editor with the same patches. `templates build --editor` builds it in Docker for Linux and caches it as `godot-<ver>-editor-linux-x86_64-fgd<patchset>-p<id>`. It is the same for every project. `export` passes the project's pack magic and index field order to it in `FORTRESSGD_PACK_PARAMS`, for that one export only, and runs `--export-pack`. The pack key goes in `GODOT_SCRIPT_ENCRYPTION_KEY`, as for a stock export.

`export` fails if the pack it gets back is not in the project's dialect, for example when it ran the official editor. A stock GDPC listing of the pack must fail; `verify` checks that. `--export-pack` writes only the pack: ship the cached template as the game's executable, with the pack next to it under the same name ending in `.pck`.

On a host other than Linux, build or point at a patched editor yourself with `FORTRESSGD_EDITOR`.

With mangling on, unmarked string `call` / `rpc` / `set` fail the export. Use Callables, or mark a required string API:

```gdscript
## fortressgd:keep
call("public_mod_hook")
```

See [`docs/agent-rules.md`](docs/agent-rules.md).

### Nameless bytecode and pack signatures

Both stay **off** until you opt in.

- `nameless_bytecode` is checked by `verify` only. Every FortressGD template can load nameless bytecode, so toggling it needs no template rebuild.
- `sign_packs` needs the signature-required template variant (its name ends in `-sig`). Rebuild templates after turning it on: `templates build` reads `sign_packs` from `.fortressgd.toml` (or pass `--require-signature`; the GitHub Action takes `sign_packs: "true"`). That template refuses packs whose index signature is missing, zeroed, or invalid, including encrypted packs. `export` signs the pack and fails if only the non-`-sig` template is cached. Encrypted sparse bundles (Godot 4.7) cannot be signed.

```toml
[production]
nameless_bytecode = true
sign_packs = true
```

```bash
fortressgd templates build --godot 4.6.2 --platform linux
fortressgd export --preset Linux
fortressgd verify build/game.pck
```

`verify` then fails if packed `.gdc` still has debug name tables, or if the Ed25519 index signature is missing or invalid.

With `nameless_bytecode = true`, set the preset's GDScript Export Mode to **Binary tokens** unless CI runs Python 3.14+: `verify` decodes "Compressed binary tokens" (ZSTD) only with Python 3.14's `compression.zstd`, and otherwise fails with that reason rather than passing unchecked. Encrypted `.gdc` bodies are decrypted with the project secret before the check.

---

## Configuration

`.fortressgd.toml` lives at the project root and **is committed**. It must not contain the secret. `fortressgd init` writes the example file. Unknown keys are errors.

```toml
schema = 1
godot = "4.6.2"

[production]
dialect = true
key_epoch = 0
mangle_scripts = true
nameless_bytecode = false
sign_packs = false
verify_on_export = true

[filters]
exclude = [
  "*.cs",
  "*.sln",
  "*.csproj",
  "*.blend",
  "*.psd",
  "*.kra",
  "*.tmp",
  "*.fortressgd.map.json",
]
include = []

[platforms]
build = ["windows", "linux"]

[templates]
cache_dir = "~/.cache/fortressgd"
```

| Key | Meaning |
|---|---|
| `schema` | Config version. Must be `1`. |
| `godot` | Engine tag: `4.6.2` or `4.7.2` (`4.7` / `4.7.x` are aliases for 4.7.2). `doctor` rejects tags without a patch folder. |
| `production.dialect` | Per-secret pack magic + index layout. |
| `production.mangle_scripts` | Rename identifiers and strip debug statements. |
| `production.nameless_bytecode` | Omit stock `.gdc` debug name tables. |
| `production.sign_packs` | Ed25519 signature over the pack index. |
| `production.key_epoch` | Integer, default `0`. Changes only the pack AES key; the pack format, signing key and mangled names stay the same. Bump it for a new release line so a key extracted from one release does not open the next; rebuild templates afterwards (their names gain `-e<N>`). Patch or DLC packs must use the same epoch as the game that loads them. |
| `production.verify_on_export` | Keep true (the default when absent). `export` then runs the same check as `fortressgd verify` on the artifact, or on the `<name>.pck` next to an executable without an embedded pack, and exits 2 on a leak. `.zip` exports are not supported yet. |
| `filters.exclude` | Extra exclude globs (forced excludes still apply). |
| `filters.include` | Allowlist that overrides a forced exclude. |
| `platforms.build` | Default platforms for `templates build`. |
| `templates.cache_dir` | Template cache root (default `~/.cache/fortressgd`). |

Production exports also force-exclude GDScript **text** (bytecode only) and `addons/fortressgd/**` unless the same pattern is in `include`.

Secret sources, in order: `--secret-file` (default `.fortressgd.secret`), then `FORTRESSGD_SECRET`. Never print the secret; `secret status` only reports present/missing. For managed stores (KMS, CI secrets) and rotation, see [`docs/secrets.md`](docs/secrets.md).

---

## Commands

```text
fortressgd init
fortressgd doctor [--godot X.Y.Z]
fortressgd secret generate | fortressgd secret status
fortressgd templates build [--godot X.Y.Z] [--platform windows|linux]
fortressgd templates list
fortressgd export --preset NAME
fortressgd verify PATH.pck|PATH.exe
fortressgd mangle-report [--json] [--all]
```

Every command accepts `--secret-file PATH`. `--platform` is repeatable (`--platform linux --platform windows`).

| Command | What it does |
|---|---|
| `init` | Write `.fortressgd.toml` if missing, install `addons/fortressgd`, suggest/append `.gitignore` for `.fortressgd.secret`. |
| `doctor` | Validate toml, supported Godot tag, plugin files vs CLI package, secret presence and hygiene. Fails on a weak or placeholder secret, or a secret file readable by group or others. A missing secret and plugin drift are warnings, not failures. |
| `secret generate [--force]` | Write 32 CSPRNG bytes as 64 hex chars, mode `0600`. Refuses to replace an existing secret without `--force`; a new secret cannot load packs or use templates built with the old one. |
| `secret status` | `present` / `missing`; never prints the secret. |
| `templates build` | Docker-build `template_release` for `(godot, secret_hash, platform)`. |
| `templates list` | Names of cached templates. |
| `export` | Production export with derived AES key (and dialect/mangle/sign when enabled), then `verify` when `verify_on_export` is true. |
| `mangle-report` | List the script names mangling leaves readable, grouped by the rule that keeps each one (scene/resource reference, `@export`, `obj.name` access, string literal, addon, `class_name`, `fortressgd:keep`) with the file responsible. Needs no secret. `--json` for the full report, `--all` for every name. |
| `verify` | List packed paths; fail on leaked excludes, shipped `.pdb` files or source maps next to the artifact, shaders that still contain comments, unencrypted bodies in an encrypted pack, leftover debug tables, or bad signatures. |

Exit codes: `0` ok, `1` config/user error, `2` verify/policy failure, `3` tool or engine build failure. Errors print `error: …` and `Run: <next command>`.

### Examples

```bash
# Check the project is wired correctly
fortressgd doctor

# Secret from CI, not a local file
FORTRESSGD_SECRET="$SECRET_FROM_CI" fortressgd secret status

# Build both platforms from toml [platforms].build
fortressgd templates build --godot 4.6.2

# See what is already cached
fortressgd templates list
# godot-4.6.2-template_release-linux-x86_64-fgd…………-………………

# Export a named preset from export_presets.cfg
fortressgd export --preset "Linux"
fortressgd export --preset "Windows Desktop"

# Verify an embedded PCK inside an exe
fortressgd verify build/my_game.x86_64
```

Godot binary resolution for `export`: `FORTRESSGD_GODOT`, then `GODOT`, then `GODOT_BIN`, then `godot` / `godot4` on `PATH`. With `dialect = true`, `FORTRESSGD_EDITOR` comes first, then the cached export editor (on Linux), then the same list. That editor runs with its own Godot cache under `<cache_dir>/editor-cache/`, so it never shares one with your own Godot editor.

---

## Editor plugin

`fortressgd init` copies `addons/fortressgd` and enables it in `project.godot`. The release filters only run while it is enabled, so `fortressgd export` refuses to run if it is turned off, and `fortressgd doctor` warns. Run `fortressgd init` again, or re-enable it in **Project → Project Settings → Plugins**.

On presets tagged `fortressgd_production` the export plugin:

- Skips forced-exclude paths (unless allowlisted)
- Optionally mangles GDScript before bytecode remap
- Restores original scripts after export
- Writes the source map to `.fortressgd/maps/` in the project (mirroring the export path), never next to the artifact

It never compiles the engine and never writes the raw secret into `export_presets.cfg`. If you export from the editor without FortressGD templates, use `fortressgd export` (or build templates first) for encrypted / dialect packs.

---

## CI

Build templates once per `(godot version, patchset, secret hash, platform)` and cache them. Pin the action and the CLI to the same release tag:

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

- run: fortressgd export --preset Linux
  env:
    FORTRESSGD_SECRET: ${{ secrets.FORTRESSGD_SECRET }}
- run: fortressgd verify path/to/your_game.pck
  env:
    FORTRESSGD_SECRET: ${{ secrets.FORTRESSGD_SECRET }}
```

Cache key: `fgd-templates-{godot}-{patchset}-{secret_hash}-{platforms}-e{key_epoch}[-sig]`. Pass `key_epoch` to the Action when the project sets `[production].key_epoch`. The secret never enters the build container: `templates build` writes `dialect.gen.h` (the masked pack key and public values) on the host and passes only that file and the public `secret_hash` to Docker.

The weekly end-to-end workflow (`.github/workflows/e2e.yml`) builds real templates, exports the sample project, and runs a pinned KeyDot version against the protected Windows build; KeyDot failing to recover the key or project is a pass. Locally the same test is opt-in (`FORTRESSGD_UNPACKER_TESTS=1`). The same workflow runs the latest GDRE Tools release with `--recover` on the protected Linux build and fails if any script contents come back, and checks that a `sign_packs` template refuses unsigned and tampered packs. gdke and GodotPCKExplorer are not tested yet, so the claim that they fail rests on design reasoning, not on a test run. See [`docs/ci.md`](docs/ci.md).

---

## Repository layout

```text
DESIGN.md                         source of truth for implementers
THREAT_MODEL.md                   short threat model
bin/fortressgd                    run the CLI from a checkout
fortressgd/                       the Python package (everything below ships in the wheel)
  cli/                            fortressgd CLI
  core/                           shared library
  generator/                      writes dialect.gen.h (build artifact, not committed)
  plugin/addons/fortressgd/       editor plugin, copied by `fortressgd init`
  patches/<godot-tag>/            quilt applied to a pinned upstream tag
  docker/                         template build image
  fortressgd.example.toml         config written by `fortressgd init`
actions/build-templates/          CI template factory
.github/workflows/                CI for this repo
testdata/                         sample project + unpacker fixtures
tests/                            test suite
docs/                             getting-started, CI, secrets, agent rules + the docs site
```

There is **no** Godot source tree in this repo. A tag without `fortressgd/patches/<tag>/series` is unsupported.

Tests: `python3 tests/run.py`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Comparison

| | [Official encrypt][official] | [Godot-Secure][godot-secure] | [GDMaim][gdmaim] | [ChaosProtector][chaos] | FortressGD |
|---|---|---|---|---|---|
| Stock KeyDot/GDRE | Usually succeed (KeyDot reads Windows and Web builds) | Project claims fail | Pack opens; scripts are obfuscated | Vendor claims fail (Windows x86-64) | Target: fail (KeyDot and latest GDRE checked by the e2e workflow) |
| Editor | Official + custom templates | Patched editor | Official (4.5+) | Official | Official |
| Source leaks | Your problem | Your problem | Your problem (strips comments only) | Not advertised | `verify` fails the build |
| Script names | Intact | Intact (token IDs optionally scrambled) | Identifiers mangled; file paths intact | Not advertised | Optional mangler |
| You compile Godot how? | By hand | By hand (in-place patch script) | No | No (post-build tool) | Docker / Action |
| License | MIT engine | MIT | MIT | Commercial, closed source (free tier) | MIT |

Third-party columns summarize each project's own documentation as of November 2026; claims marked "claims" are the project's own and were not tested by FortressGD. Corrections are welcome.

[official]: https://docs.godotengine.org/en/stable/engine_details/development/compiling/compiling_with_script_encryption_key.html
[godot-secure]: https://github.com/KnifeXRage/Godot-Secure
[gdmaim]: https://github.com/cherriesandmochi/gdmaim
[chaos]: https://chaosprotector.com/godot

---

## Docs

All of these are also published as a website: **https://salaryman-inc.github.io/FortressGD/**

- [`docs/getting-started.md`](docs/getting-started.md) — leak checks with the official editor
- [`docs/ci.md`](docs/ci.md) — template factory, Docker, unpacker fixtures
- [`docs/secrets.md`](docs/secrets.md) — where to keep the secret, what `doctor` checks, rotation runbook
- [`docs/agent-rules.md`](docs/agent-rules.md) — Callables vs string `call`/`rpc`, no secrets under `res://`
- [`DESIGN.md`](DESIGN.md) — normative spec
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — in-scope vs out-of-scope attacks
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability or a bypass
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development setup, tests, project rules

When implementing or changing behavior: do not add packers, VMs, anti-debug, or license servers; do not vendor Godot source; fail export rather than ship a recoverable or broken build; update `DESIGN.md` in the same change if behavior shifts.

---

## License

MIT.

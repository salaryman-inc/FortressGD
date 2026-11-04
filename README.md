# FortressGD

Open-source **release toolchain** for Godot 4. Not a fork. Not DRM. Not anti-cheat.

> Export a Godot game that stock GDRE/KeyDot cannot one-click recover, without maintaining a fork. This raises the cost of automated recovery. It does not make a local client unextractable.

Designers keep the official Godot editor. Custom **export templates** are built in Docker or CI from a pinned Godot tag plus a small patch quilt. Production exports refuse to ship source, and `fortressgd verify` fails CI if they did.

Supported engine tags: **Godot 4.6.2** and **4.7.x** stable. See [`DESIGN.md`](DESIGN.md) §4.

Start with leak checks on the official editor — no Docker, no custom templates. Add derived-key encryption, pack dialect, and mangling when you are ready to ship a Release PCK.

---

## Features

**Export hygiene**

- Production presets skip GDScript **text**, C# source, DCC work files, plugin internals, and source maps unless you allowlist a path
- Official-editor workflow: add the `fortressgd_production` feature tag and export as usual
- `fortressgd verify` lists packed paths and fails CI if excluded files leaked

**Derived encryption key**

- PCK AES-256 key is derived at runtime (`FGD-KDF-1`, HKDF-SHA256) instead of embedding the raw 32-byte blob next to a known error string
- Custom `template_release` binaries built in Docker from `patches/<godot-tag>/`
- CLI injects the derived key for one export process only; it is never written to `export_presets.cfg`

**Per-project pack dialect** (optional, on by default in the example config)

- Pack magic and index field order come from the project secret
- Stock GDPC parsers cannot list the pack; `verify` requires that they fail
- Export uses a FortressGD-patched headless editor (`--export-pack`); designers still use the official editor day-to-day

**GDScript mangling** (optional, on by default in the example config)

- Strips comments, `assert`, `print_debug`, and `breakpoint`
- Renames user identifiers with a PRNG seeded from `secret_hash`
- Unmarked `call("name")` / `rpc("name")` / `set("prop")` **fail the export** — use Callables
- Writes `*.fortressgd.map.json` next to the artifact, not inside the pack

**Nameless bytecode** (off by default)

- Packed `.gdc` omits stock identifier/line tables; runtime names live in an `FGDN` trailer
- `verify` fails if those debug tables are still present

**Pack signatures** (off by default)

- Ed25519 signature over the pack index
- Public key is compiled into the template; the private seed is derived from the project secret and is not persisted

**Toolchain**

- One config file (`.fortressgd.toml`, committed, no secrets)
- CLI + editor plugin share the same backend
- GitHub Action to build and cache templates
- `doctor` checks config, Godot version, plugin drift, and secret presence

---

## What it does / does not

**Does**

- Keep the official editor for day-to-day work
- Build `template_release` binaries in Docker from `patches/<godot-tag>/`
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
- Godot **4.6.2** or **4.7.x** (official editor on `PATH`, or `GODOT` / `FORTRESSGD_GODOT`)
- Docker, for template builds
- A 32-byte secret, 64 hex chars, **not in git** (`.fortressgd.secret` or `FORTRESSGD_SECRET`)

You do not need SCons or a local Godot source tree on designer machines.

Protected platforms in v1: **Windows** and **Linux** (x86_64). Other Godot export presets may still run vanilla; they are not FortressGD-protected.

---

## Install

From a FortressGD checkout:

```bash
python3 cli/fortressgd --help
# equivalent:
python3 -m cli --help
```

After `pip install .` the `fortressgd` script is on `PATH`. Run every command from your **Godot project root** (the directory with `project.godot`).

```bash
pip install /path/to/FortressGD
cd /path/to/your/godot/project
fortressgd --version
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

# 3. Enable the FortressGD plugin in Project → Project Settings → Plugins.
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
python3 /path/to/FortressGD/cli/fortressgd init
```

Then in the official editor:

1. Enable **FortressGD** under **Project → Project Settings → Plugins**.
2. Open **Project → Export** on the Release preset (not debug).
3. Set **GDScript Export Mode** to **Binary tokens** or **Compressed binary tokens**.
4. Add the custom feature tag `fortressgd_production`.
5. Export PCK/ZIP or a full project as usual.

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
error: leaked excluded path(s) in game.pck
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

`export` sets `GODOT_SCRIPT_ENCRYPTION_KEY` to `FGD-KDF-1(secret, salt)` for that process only, points the preset at the cached FortressGD template, and restores `export_presets.cfg` afterwards. Missing templates print the exact `templates build` command to run.

The exported pack's directory is encrypted with that derived key, so `verify` reads it with the project secret and the `godot` version from `.fortressgd.toml`. Without the secret, `verify` exits 1 and says so.

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
export FORTRESSGD_GODOT=/path/to/fortressgd-headless-editor   # patched, target=editor

fortressgd templates build --godot 4.6.2 --platform linux
fortressgd export --preset Linux      # verifies the artifact when verify_on_export = true
fortressgd verify build/game.pck      # the same check, for CI or a copied artifact
```

`templates build` produces `template_release` binaries (the runtime). Dialect **packing** needs a separate FortressGD-patched **headless editor** (`scons target=editor`, same patches and `dialect.gen.h`). Point `FORTRESSGD_GODOT` at that binary. `export` then runs `--export-pack`. A stock GDPC listing of the resulting pack must fail; `verify` checks that.

With mangling on, unmarked string `call` / `rpc` / `set` fail the export. Use Callables, or mark a required string API:

```gdscript
## fortressgd:keep
call("public_mod_hook")
```

See [`docs/agent-rules.md`](docs/agent-rules.md).

### Nameless bytecode and pack signatures

Both stay **off** until you opt in. They need FortressGD templates rebuilt after you flip the flag.

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
| `godot` | Engine tag: `4.6.2` or `4.7.x`. |
| `production.dialect` | Per-secret pack magic + index layout. |
| `production.mangle_scripts` | Rename identifiers and strip debug statements. |
| `production.nameless_bytecode` | Omit stock `.gdc` debug name tables. |
| `production.sign_packs` | Ed25519 signature over the pack index. |
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
| `verify` | List packed paths; fail on leaked excludes, leftover debug tables, or bad signatures. |

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

Godot binary resolution for `export`: `FORTRESSGD_GODOT`, then `GODOT`, then `GODOT_BIN`, then `godot` / `godot4` on `PATH`.

---

## Editor plugin

`fortressgd init` copies `addons/fortressgd`. Enable it in **Project → Project Settings → Plugins**.

On presets tagged `fortressgd_production` the export plugin:

- Skips forced-exclude paths (unless allowlisted)
- Optionally mangles GDScript before bytecode remap
- Restores original scripts after export
- Writes `*.fortressgd.map.json` next to the artifact

It never compiles the engine and never writes the raw secret into `export_presets.cfg`. If you export from the editor without FortressGD templates, use `fortressgd export` (or build templates first) for encrypted / dialect packs.

---

## CI

Build templates once per `(godot version, patchset, secret hash, platform)` and cache them:

```yaml
- uses: ./actions/build-templates
  with:
    godot_version: "4.6.2"
    platforms: "linux,windows"
    secret: ${{ secrets.FORTRESSGD_SECRET }}

- run: fortressgd export --preset Linux
- run: fortressgd verify path/to/your_game.pck
```

Cache key: `fgd-templates-{godot}-{patchset}-{secret_hash}-{platform}`. The secret is passed at **run** time; it is not a Docker build-arg and must not land in image layers.

Optional unpacker regression (`FORTRESSGD_UNPACKER_TESTS=1`) runs pinned KeyDot/GDRE versions; those tools failing to recover the project is a pass. See [`docs/ci.md`](docs/ci.md).

---

## Repository layout

```text
DESIGN.md              source of truth for implementers
THREAT_MODEL.md        short threat model
plugin/addons/fortressgd editor plugin
cli/                   fortressgd CLI
core/                  shared library
generator/             dialect.gen.h (build artifact, not committed)
patches/<godot-tag>/   quilt applied to a pinned upstream tag
docker/                template build image
actions/               CI template factory
testdata/              sample project + unpacker fixtures
docs/                  getting-started, CI, agent rules
```

There is **no** Godot source tree in this repo. A tag without `patches/<tag>/series` is unsupported.

Tests: `python3 tests/run.py`.

---

## Comparison

| | Official encrypt | Godot-Secure | GDMaim | ChaosProtector | FortressGD |
|---|---|---|---|---|---|
| Stock KeyDot/GDRE | Usually succeed | Usually fail | Pack still opens | Claim fail (Windows) | Target: fail + CI proof |
| Editor | Official + custom templates | Patched editor | Official | Official | Official |
| Source leaks | Your problem | Your problem | Your problem | Your problem | `verify` fails the build |
| Script names | Intact | Intact | Mangled | Intact | Optional mangler |
| You compile Godot how? | By hand | By hand, in-place script | No | No | Docker / Action |
| License | MIT engine | MIT script | MIT | Paid | MIT |

---

## Docs

- [`docs/getting-started.md`](docs/getting-started.md) — leak checks with the official editor
- [`docs/ci.md`](docs/ci.md) — template factory, Docker, unpacker fixtures
- [`docs/secrets.md`](docs/secrets.md) — where to keep the secret, what `doctor` checks, rotation runbook
- [`docs/agent-rules.md`](docs/agent-rules.md) — Callables vs string `call`/`rpc`, no secrets under `res://`
- [`DESIGN.md`](DESIGN.md) — normative spec
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — in-scope vs out-of-scope attacks

When implementing or changing behavior: do not add packers, VMs, anti-debug, or license servers; do not vendor Godot source; fail export rather than ship a recoverable or broken build; update `DESIGN.md` in the same change if behavior shifts.

---

## License

MIT.

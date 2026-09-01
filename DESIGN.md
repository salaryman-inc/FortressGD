# FortressGD Design Spec

Status: draft for implementation  
License of the product: MIT  
Audience: implementation agents and maintainers  
Godot targets (initial): 4.6.2 and 4.7.x stable tags  

This document is the source of truth. If code and this spec disagree, change the code or update this spec in the same change. Do not invent features that are listed under Non-goals or Later.

---

## 1. Purpose

FortressGD is an open-source **release toolchain** for Godot 4. It produces production exports that stock, version-pinned unpackers (GDRE Tools, KeyDot, gdke, GodotPCKExplorer in documented versions) cannot one-click recover.

It is not a Godot fork, not DRM, and not an anti-cheat.

Promise to print in the README, unchanged:

> Export a Godot game that stock GDRE/KeyDot cannot one-click recover, without maintaining a fork. This raises the cost of automated recovery. It does not make a local client unextractable.

### 1.1 Goals

- Designers keep the official Godot editor.
- Engine changes are **pinned-tag patches + a generator**, not a living fork.
- First-time template builds happen in Docker or CI, not on a developer laptop with a hand-installed SCons toolchain.
- Release exports never ship GDScript text, C# source, source maps, or raw DCC files unless the user allowlists them.
- Official PCK AES remains, but the runtime key is **derived**, not a 32-byte static blob next to a known error string.
- A `fortressgd verify` command fails CI if the packed artifact leaked source or debug name tables.
- Every user-facing surface (plugin, CLI, Action) shares one backend and one config file.

### 1.2 Non-goals

- A maintained `our-org/godot` fork.
- Code virtualization / VMProtect-class packers.
- Kernel anti-cheat, always-online license servers, store DRM.
- macOS / Android / iOS / Web template dialects in v1 (may export vanilla; must not claim protection).
- Claiming cryptographic secrecy for assets that the process must decrypt to run.
- Replacing GDScript with a new language.
- Automatic support for every Godot minor the day it ships.

### 1.3 Threat model (normative)

In scope:

- Static key extraction via string anchors and LEA/pattern scans (KeyDot-class).
- Full project recovery via GDRE Tools / gdsdecomp on stock PCK + stock bytecode.
- Casual unzip / PCK Explorer listing of original paths and plaintext scripts.
- Accidental shipping of `.cs`, `.gd` text, `.blend`, `.psd`, FortressGD source maps.

Out of scope (document, do not “fix”):

- Attaching a debugger and dumping the derived key or decrypted resources from memory.
- Rewriting a packer after reverse-engineering *this* game’s dialect.
- Asset ripping from GPU/memory.
- Server-authoritative cheat prevention.

If a change only helps out-of-scope attacks and increases maintenance, reject it.

---

## 2. Product surfaces

```
┌──────────────────────────────────────────────────┐
│  addons/fortressgd           official Godot UI   │
│  fortressgd CLI              local + CI          │
│  GitHub Action               template factory    │
└────────────────────────┬─────────────────────────┘
                         │
                         ▼
             fortressgd-core (library)
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
    generator       patch apply      pack verify
        │                │
        ▼                ▼
  dialect.gen.h     Docker scons → templates
```

### 2.1 Editor plugin

Path: `plugin/addons/fortressgd/`  
Godot: 4.6+ `EditorPlugin` + `EditorExportPlugin`.

Responsibilities:

- Read/write `.fortressgd.toml` (project root).
- Release-preset resource filters (see §6.3).
- “Production export” checkbox on each export preset.
- Call `fortressgd` CLI if present; if templates for `(godot, secret_hash, platform)` are missing, block export with an actionable error.
- Never compile the engine from the editor process.
- Never write the raw secret into `export_presets.cfg` or any committed file.

### 2.2 CLI

Single command: `fortressgd`.

```
fortressgd init
fortressgd templates build [--godot X.Y.Z] [--platform windows|linux] [--secret-file PATH]
fortressgd templates list
fortressgd export --preset NAME
fortressgd verify PATH.pck|PATH.exe
fortressgd secret generate | fortressgd secret status
fortressgd doctor
```

Exit codes: `0` ok, `1` user/config error, `2` verify/policy failure, `3` tool/engine build failure.

### 2.3 GitHub Action

`actions/build-templates/action.yml`

Inputs: `godot_version`, `platforms`, `secret` (from Actions secret).  
Outputs: template artifacts named per §7.  
Must cache by `godot_version + patchset_id + secret_hash + platform`.

---

## 3. Repository layout

```
fortressgd/
  DESIGN.md                    # this file
  README.md
  LICENSE
  THREAT_MODEL.md              # one-page restatement of §1.3
  .fortressgd.example.toml
  plugin/addons/fortressgd/
  cli/
  core/                        # shared library used by CLI
  generator/
    dialect.py
    opcode_map.py              # v2; stub only in v1
    key_shards.py
  patches/
    4.6.2/
      series                   # ordered list of patch files
      0001-key-derive.patch
      0002-pack-hooks.patch
      0003-nameless-bytecode.patch   # optional in v1.1
    4.7.2/
      series
      ...
  docker/
    Dockerfile.templates
    entrypoint.sh
  actions/build-templates/
  testdata/sample_project/
  testdata/fixtures/
    unpackers.lock.json        # pinned tool versions we regression-test
  docs/
    getting-started.md
    ci.md
    rebasing.md
    agent-rules.md
```

Rules:

- No Godot source tree in this repo.
- Patches are the only engine surface. A Godot tag without a `patches/<tag>/series` file is unsupported.
- `series` is a newline-separated list of patch filenames, applied in order with `git apply --check` then `git apply`.

---

## 4. Versioning and support

Product version: semver.  
Engine support: **current Godot stable + previous stable** listed in `SUPPORTED_GODOT` in the CLI.

When adding a Godot tag:

1. Copy the closest `patches/` folder.
2. `fortressgd doctor --godot NEW` must apply every patch with `--check`.
3. Docker build templates for `windows` and `linux`.
4. Export `testdata/sample_project` and run `fortressgd verify`.
5. Run unpacker fixtures in `testdata/fixtures/unpackers.lock.json`.

If a patch fails to apply, fail CI. Do not silently skip patches.

Patchset id = SHA256 of the concatenation of all applied patch bytes for that tag, hex truncated to 12 chars. Embed in template filenames.

---

## 5. Secret and derivation

### 5.1 Secret

- 32 bytes, CSPRNG (`openssl rand` or OS CSPRNG).
- Stored as 64 hex chars.
- Environment: `FORTRESSGD_SECRET`.
- File: `--secret-file` (mode 0600).
- Optional keychain via `fortressgd secret generate` on macOS/Windows/libsecret; v1 may implement env + file only.
- **Never** commit. Add `.fortressgd.secret` to the plugin’s suggested `.gitignore`.

`secret_hash` = first 16 hex chars of `SHA256("fortressgd-v1|" + secret_bytes)`.

Rotating the secret **must** rebuild templates. Old PCKs encrypted under the old secret will not load. Document this as intended.

### 5.2 Key derivation (templates)

Do not store the AES-256 key as a raw 32-byte array next to a recognizable error string.

Normative algorithm v1 (`FGD-KDF-1`):

```
input:  secret[32], dialect_salt[16]   # salt from generator, compiled in
ikm   = secret
okm   = HKDF-SHA256(ikm, salt=dialect_salt, info="fortressgd.pck.aes.v1", L=32)
aes_key = okm[0..32)
```

Runtime template:

- Compile `dialect_salt` and an **obfuscated encoding of `secret` shards**, not `aes_key`.
- Shard scheme v1: secret split into 4×8-byte pieces, XOR’d with compile-time random masks stored separately, reassembled in `fortressgd_derive_key()`.
- Wipe stack buffers after use.
- Replace or encrypt known anchor strings used by KeyDot (`Can't open encrypted pack directory.` and similar). Use format strings rebuilt at runtime or store encrypted.

Editor / packer side:

- The official editor encrypts with the **final AES key**.
- CLI computes `aes_key = FGD-KDF-1(secret, salt)` and either:
  - injects it into the export preset at export time in memory, or
  - passes `GODOT_SCRIPT_ENCRYPTION_KEY` / the export CLI equivalent for the duration of one export.
- Do not persist `aes_key` on disk.

If PR-style “patch key bytes into official template” lands upstream, FortressGD may use official templates **only** for the AES layer. Dialect and derived-key patches still require FortressGD templates.

---

## 6. Configuration

Project file: `.fortressgd.toml` at the Godot project root. Committed. No secrets.

```toml
schema = 1
godot = "4.6.2"

[production]
dialect = true
mangle_scripts = true
nameless_bytecode = false    # v1.1
sign_packs = false           # v2
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
# opt-in extras to pack
include = []

[platforms]
build = ["windows", "linux"]

[templates]
cache_dir = "~/.cache/fortressgd"
```

Unknown keys are errors (`fortressgd doctor` and plugin).  
`schema` bump is required when meaning changes.

### 6.3 Release filters (normative)

When production export is on, the export plugin **forces** these excludes unless the user put the same pattern in `[filters].include`:

- `*.cs`, `*.gd` (text scripts — bytecode only)
- DCC / work files listed above
- `addons/fortressgd/**` source maps
- files named `*.fortressgd.map.json`

If a C# project cannot run without `.cs` in the PCK on a given Godot version, `fortressgd doctor` must print that as a known limitation and refuse `exclude *.cs` rather than produce a broken game. Document the tested Godot versions where excluding `.cs` is safe.

---

## 7. Templates

### 7.1 Naming

```
godot-<ver>-template_release-<platform>-<arch>-fgd<patchset12>-<secrethash16>
```

Example:

```
godot-4.6.2-template_release-windows-x86_64-fgd3a1c0b9d2e4f-9f3c1a77b0e2d145
```

### 7.2 Build

Docker image `Dockerfile.templates`:

- Input: Godot tag, patch dir, `dialect.gen.h`, `FORTRESSGD_SECRET` (build-arg must **not** be stored in image layers; pass at run via secret mount).
- Steps: shallow clone tag → `git apply` series → copy generated headers → `scons target=template_release production=yes debug_symbols=no` per platform → `strip` where applicable → emit artifact + `manifest.json`.

`manifest.json`:

```json
{
  "godot": "4.6.2",
  "patchset_id": "3a1c0b9d2e4f",
  "secret_hash": "9f3c1a77b0e2d145",
  "kdf": "FGD-KDF-1",
  "dialect_id": "…",
  "platform": "windows",
  "arch": "x86_64"
}
```

Do not put the raw secret or `aes_key` in the manifest.

### 7.3 Cache

`~/.cache/fortressgd/templates/<filename>`.  
CI: restore cache key `fgd-templates-{godot}-{patchset}-{secret_hash}-{platform}`.

---

## 8. Generator and dialect

### 8.1 Inputs

- secret bytes
- godot tag
- optional user `dialect_seed` (default: `HKDF` info `"fortressgd.dialect.v1"`)

### 8.2 Outputs (v1)

File `dialect.gen.h` (committed nowhere; build artifact):

- `FGD_DIALECT_SALT[16]`
- `FGD_PACK_MAGIC` (u32, must not equal stock `0x43504447` / `GDPC` when `dialect = true`)
- `FGD_INDEX_PERM[N]` describing field order of the pack index record
- Shard masks for secret encoding

Deterministic: same secret + tag + generator version ⇒ identical header.

### 8.3 Pack hooks (patch)

Minimal hooks in `core/io/file_access_pack.cpp` (and editor packer counterpart):

- Read/write magic from `FGD_PACK_MAGIC` when compiled with `FORTRESSGD_DIALECT`.
- Index field order from `FGD_INDEX_PERM`.
- Stock official builds remain 100% compatible. Dialect exists only in FortressGD templates **and** in the packer used at export.

Export packer:

- Preferred: CLI drives a **FortressGD-built editor-headless binary** (`target=editor` with the same patches) only on the export machine. Designers do not use it.
- Alternative v1 acceptable: CLI writes the PCK itself by shelling to that headless binary with `--export-pack`.

Do not reimplement the full Godot packer in Python in v1.

### 8.4 Later (do not implement until version gate)

- Opcode permutation table for GDScript VM (`opcode_map.py`).
- Ed25519 signatures over the pack index.

---

## 9. Script mangling

v1 lives entirely in the `EditorExportPlugin` / CLI export path. No engine patch required.

Behavior:

- Process only files that would be packed as GDScript.
- Strip comments, `assert`, `print_debug`, `breakpoint` (release).
- Rename user identifiers with a PRNG seeded from `secret_hash`.
- Never rename: Godot lifecycle methods, engine APIs, `class_name` entries that scenes reference unless the scene rewrite table is updated in the same pass.
- Emit `*.fortressgd.map.json` next to the export (not packed) when mangling is on.
- If `call("name")` / `rpc("name")` / `set("prop")` string usage is detected and not marked with an explicit allow annotation, **fail export** with file:line. Do not silently ship a broken game.

Annotation (optional, v1):

```gdscript
## fortressgd:keep
func public_mod_hook():
    pass
```

Document in `docs/agent-rules.md` for AI coding agents:

- Use Callables, not string `call`/`rpc`.
- No secrets under `res://`.
- No string `set`/`get` for user properties.

v1.1: nameless bytecode patch so decompilers lose symbol tables even without mangling.

---

## 10. Verify

`fortressgd verify <artifact>`

Checks:

1. Parse pack with **FortressGD** dialect + derived key (must succeed).
2. Parse pack with **stock** GDPC parser and empty/no key (must fail if dialect or encrypt on).
3. File list contains no excluded patterns from §6.3.
4. No packed `*.fortressgd.map.json`.
5. If `nameless_bytecode`: fail if debug name tables present in `.gdc`.
6. Optional: run pinned KeyDot/GDRE binaries from `unpackers.lock.json` in a sandbox when `FORTRESSGD_UNPACKER_TESTS=1`. Failure of those tools to recover the project is a **pass**.

Do not vendor unpacker binaries in the default clone. Document how CI obtains them.

---

## 11. Plugin UX

Dock name: FortressGD.

Fields:

- Production export: on/off (per preset, stored in toml + preset feature tag `fortressgd_production`).
- Secret status: present / missing (never display the secret).
- Godot version detected vs `godot` in toml (mismatch = error).
- Template status: found / missing, with the exact `fortressgd templates build …` command to copy.

Export feature tag: `fortressgd_production`.  
Users can keep a debug preset without the tag.

---

## 12. Phased delivery

Implement in this order. Do not start a later phase before the previous phase’s tests exist.

### Phase 0 — Skeleton

- Repo layout, `DESIGN.md`, `THREAT_MODEL.md`, example toml.
- CLI: `init`, `doctor`, `secret generate`, `secret status`.
- Plugin installs and reads toml.
- `testdata/sample_project` is a tiny 2D project with one scene and one script.

### Phase 1 — Hygiene + verify

- Export plugin enforces filters.
- `fortressgd verify` without dialect (leak checks only).
- Docs: getting-started without custom templates.

### Phase 2 — Templates + FGD-KDF-1

- `patches/4.6.2/0001-key-derive.patch`
- Docker template build for windows-x86_64 and linux-x86_64.
- CLI export sets derived AES key for the official encrypt-PCK path.
- Verify: stock KeyDot fixture fails on the protected exe (when unpacker tests enabled).

### Phase 3 — Dialect

- Generator + `0002-pack-hooks.patch`
- Headless patched editor for `--export-pack`
- Verify: stock PCK parser cannot open the pack.

### Phase 4 — Mangler

- Identifier mangling + export failure on unsafe dynamic calls.
- Source maps.

### Phase 5 — v1.1 / v2 (explicit milestone)

- Nameless bytecode.
- Opcode map.
- Pack signatures.

Each phase ships behind feature flags in toml so a project can stop at Phase 2.

---

## 13. Testing requirements

Minimum CI:

- Unit tests for FGD-KDF-1, shard encode/decode, dialect determinism.
- Patch `--check` on every supported tag.
- Docker template build on Linux runner (linux templates required; windows cross-compile if the Dockerfile supports it, else documented manual job).
- Export sample project, `fortressgd verify`.
- Lint: no secret-looking 64-hex strings in the repo except fixtures marked `fake`.

Manual / nightly:

- Unpacker fixtures when tools are available.

---

## 14. Security and supply chain

- MIT license, no telemetry.
- Docker image built from this repo; pin base image digests.
- `fortressgd doctor` warns if plugin files differ from the CLI package version.
- Refuse to run `templates build` if `series` is empty or `git apply --check` fails.
- Treat `generator/` output as untrusted C to embed: headers only, no executable code snippets from the secret.

---

## 15. Implementation agent rules

When implementing from this spec:

1. Read this file and `THREAT_MODEL.md` before writing code.
2. Do not add packers, VMs, anti-debug, or network license checks.
3. Do not vendor a full Godot source tree.
4. Prefer small patches. If a hook needs more than ~150 lines in Godot C++, stop and split or redesign.
5. If Godot APIs differ between 4.6 and 4.7, keep two patch folders. Do not `#ifdef` a single patch into unreadability unless the difference is trivial.
6. User-visible errors must include the next command to run.
7. Update this spec in the same PR when behavior changes.
8. Default to failing export rather than shipping a recoverable or broken build.

---

## 16. Glossary

| Term | Meaning |
|---|---|
| Official editor | Unmodified Godot from godotengine.org |
| Template | `target=template_release` binary players run |
| Dialect | Per-secret pack magic + index layout |
| Patchset id | Hash of applied patches for a Godot tag |
| FGD-KDF-1 | HKDF-SHA256 key derivation in §5.2 |
| Production export | FortressGD-enabled release preset |

---

## 17. Acceptance for v1

A stranger can:

1. `fortressgd init` in a Godot 4.6.2 project.
2. Put a secret in `FORTRESSGD_SECRET`.
3. Run `fortressgd templates build --platform linux` via Docker.
4. Export with the plugin or `fortressgd export`.
5. Run `fortressgd verify` successfully.
6. Observe that a stock PCK listing tool does not show plaintext scripts, and documented KeyDot/GDRE versions do not fully recover the project.

If that path needs more than the commands above plus installing Docker and the plugin, v1 is not done.

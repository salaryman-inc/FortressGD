# FortressGD Design Spec

Status: draft for implementation  
License of the product: MIT  
Audience: implementation agents and maintainers  
Godot targets (initial): 4.6.2 and 4.7.2 stable tags (`4.7` / `4.7.x` are aliases for 4.7.2)  

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
- Recovering the project secret or the pack-signing seed from anything that ships. Neither is ever compiled into a template or written to a pack: a template holds only its own pack key, encoded by its generated code (§18.3), and public values.
- A FortressGD-aware tool that reads values without executing the build, reused on another build: one that reads the pack key, the pack layout or the opcode map from a fixed location, a fixed array shape or a fixed instruction pattern, or an extractor written for one project or one release line. The generated code differs per `(secret, tag, key_epoch)` (§18). §18.7's tests show that builds differ; they do not show that a static extractor for builds in general is impossible.

Out of scope (document, do not “fix”):

- Attaching a debugger and dumping the derived key or decrypted resources from memory.
- Anything that executes or emulates the build (hooking the AES routine, emulating the key routine), and analysis of one build by a person or with AI help. Either yields one build's pack key and dialect parameters. That exposes the packs of every build sharing that key (same secret, Godot version and `key_epoch`) until the epoch is bumped or the secret rotated. It does not expose the project secret, the signing seed, other projects' keys, or anything mangling and the release filters removed. Dialect, opcode map and nameless bytecode do not hold against it: nameless bytecode keeps runtime names in its `FGDN` block.
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

Path: `fortressgd/plugin/addons/fortressgd/` in this repo; `addons/fortressgd/` once `fortressgd init` copies it into a project.  
Godot: 4.6+ `EditorPlugin` + `EditorExportPlugin`.

Godot runs the export hook only when `project.godot` lists the plugin under `[editor_plugins] enabled`, and the §6.3 forced excludes live in that hook. So `fortressgd init` adds `res://addons/fortressgd/plugin.cfg` to that list, keeping any other enabled plugins. `fortressgd export` refuses to run while it is missing, and `fortressgd doctor` warns about it.

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
FortressGD/                    # repository root
  DESIGN.md                    # this file
  README.md
  LICENSE
  THREAT_MODEL.md              # one-page restatement of §1.3
  SECURITY.md                  # private vulnerability reporting
  CONTRIBUTING.md
  pyproject.toml
  bin/fortressgd               # run the CLI from a checkout without installing
  fortressgd/                  # the Python package; everything below ships in the wheel
    fortressgd.example.toml    # written by `fortressgd init`
    plugin/addons/fortressgd/  # editor plugin, copied by `fortressgd init`
    cli/
    core/                      # shared library used by CLI
    generator/
      dialect.py
      opcode_map.py
      key_shards.py
    patches/
      common/                  # sources the series patches add to the engine
      4.6.2/
        series                 # ordered list of patch files
        0001-key-derive.patch
        0002-pack-hooks.patch
        0003-nameless-bytecode.patch
        0004-opcode-map.patch
        0005-pack-signatures.patch
      4.7.2/
        series
        ...
    docker/
      Dockerfile.templates
      entrypoint.sh
  actions/build-templates/
  .github/workflows/           # CI (§13)
  testdata/sample_project/
  testdata/fixtures/
    unpackers.lock.json        # pinned tool versions we regression-test
  tests/
  docs/
    getting-started.md
    ci.md
    secrets.md
    agent-rules.md
```

The plugin, patches, Docker build context and example config live inside the
package so `pip install fortressgd` works without a checkout. Code finds them
through `fortressgd/core/paths.py`, never relative to the repository root.

Rules:

- No Godot source tree in this repo.
- Patches are the only engine surface. A Godot tag without a `fortressgd/patches/<tag>/series` file is unsupported.
- `series` is a newline-separated list of patch filenames, applied in order with `git apply --check` then `git apply`.

---

## 4. Versioning and support

Product version: semver.  
Engine support: **current Godot stable + previous stable** listed in `SUPPORTED_GODOT` in the CLI.

When adding a Godot tag:

1. Copy the closest `fortressgd/patches/<tag>/` folder.
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

- **Never compile in the project secret**, or anything it can be recovered from. Everything the secret derives that a template needs (pack key, magic, index permutation, opcode map, public key) is computed when `dialect.gen.h` is written. The pack-signing seed is derived from the secret, so a template that held the secret would let anyone who extracts it sign packs.
- The generator computes `aes_key = FGD-KDF-1(secret, salt)` and compiles it as masked shards: 4×8-byte pieces XOR’d with masks stored separately (`FGD_KEY_SHARDS`, `FGD_KEY_MASKS`). `fortressgd_derive_key()` only reassembles them; the salt does not ship. The key equals the one `fortressgd export` hands Godot, so packs are unchanged.
- The shard and mask arrays are `static const volatile`. With plain `static const` the optimizer folds the XOR at build time (GCC at `-O3`, which `production=yes` uses; clang at `-O2`) and the template stores the key unmasked. `templates build` refuses to cache a template holding the raw key or the secret.
- `tests/test_generator.py` holds this: no array or pair of arrays in the header encodes the secret or the signing seed; the reassembly compiled with every C++ compiler on `PATH` keeps the key out of the object; and the shipped `fortressgd_derive_key()`, compiled and run, returns FGD-KDF-1(secret, salt).
- The masking only stops pattern scanners that look for a raw 32-byte key. A tool that knows this layout reads the key directly (§1.3).
- **Key epochs.** `[production].key_epoch` (integer, default 0) feeds the FGD-KDF-1 salt: `salt = HKDF(secret, domain(tag, "salt"), ...)` for epoch 0 and `domain(tag, "salt|epoch=N")` otherwise. Only the pack key changes; magic, index permutation, opcode map, signing seed, mangle key and `secret_hash` do not. Templates for a non-zero epoch are named `-e<N>` and record `key_epoch` in their manifest; `export` and `verify` use the epoch from `.fortressgd.toml`. An extracted key then opens one release line, not every future build. Rotating the secret (`docs/secrets.md`) still changes everything.
- Wipe stack buffers after use.
- Replace or encrypt known anchor strings used by KeyDot (`Can't open encrypted pack directory.` and similar). Use format strings rebuilt at runtime or store encrypted.

Editor / packer side:

- The official editor encrypts with the **final AES key**.
- CLI computes `aes_key = FGD-KDF-1(secret, salt)` and either:
  - injects it into the export preset at export time in memory, or
  - passes `GODOT_SCRIPT_ENCRYPTION_KEY` / the export CLI equivalent for the duration of one export.
- The export also sets `encrypt_pck`, `encrypt_directory` and, when the preset's `encryption_include_filters` is empty, `encryption_include_filters="*"` for that run. Godot encrypts a body only when it matches that filter, and an empty filter encrypts none. A non-empty preset filter is kept.
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
key_epoch = 0                # bump per release line for a new pack key (§5.2)
mangle_scripts = true
nameless_bytecode = false    # opt-in; see §8.4
sign_packs = false           # opt-in; needs the -sig template (§8.4)
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
- `*.pdb` (.NET debug symbols); `verify` also fails on a `*.pdb` next to the artifact or under its `data_*` folder

Godot sorts export plugins by name and gives a file to the next plugin only while none has skipped or remapped it. Its GDScript plugin (`GDScript`) remaps every `*.gd` to bytecode, so FortressGD registers two instances. `FortressGD` sorts before it and skips every excluded path, except a script that only the `*.gd` rule matches, which goes on to become bytecode. `GDScript.FortressGD` sorts after it and skips any `*.gd` that is still text (Text export mode, or a script Godot could not tokenize).

Excluding `*.cs` only keeps the source text out. A .NET game still ships its managed assembly, which decompiles to near-original C#; FortressGD does not obfuscate it, and `doctor` / `export` warn about this on .NET projects.

If a C# project cannot run without `.cs` in the PCK on a given Godot version, `fortressgd doctor` must print that as a known limitation and refuse `exclude *.cs` rather than produce a broken game. Document the tested Godot versions where excluding `.cs` is safe.

---

## 7. Templates

### 7.1 Naming

```
godot-<ver>-template_release-<platform>-<arch>-fgd<patchset12>-<secrethash16>[-e<key_epoch>][-sig]
```

Example:

```
godot-4.6.2-template_release-windows-x86_64-fgd3a1c0b9d2e4f-9f3c1a77b0e2d145
godot-4.6.2-template_release-windows-x86_64-fgd3a1c0b9d2e4f-9f3c1a77b0e2d145-sig
```

The `-sig` variant is built when `[production].sign_packs = true` and refuses packs without a valid index signature (§8.4). The two variants never share a cache entry.

The shared export editor (§8.3) has no secret hash, epoch or `-sig` part, because it holds nothing project-specific:

```
godot-<ver>-editor-linux-<arch>-fgd<patchset12>-p<editorheader8>
```

`<editorheader8>` is the first 8 hex of the sha256 of `patches/common/fortressgd_editor_dialect.h`, which the patchset id does not cover.

### 7.2 Build

Docker image `Dockerfile.templates`:

- Input: Godot tag, patch dir, `dialect.gen.h`, and `FGD_SECRET_HASH` (the public 16-hex id for the template name). The project secret never enters the container, as a build-arg, an env var or a mount: the host writes `dialect.gen.h`, which holds only the masked pack key and public values (§5.2).
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
  "arch": "x86_64",
  "require_signature": false
}
```

Do not put the raw secret or `aes_key` in the manifest.

### 7.3 Cache

`~/.cache/fortressgd/templates/<filename>`.  
`~/.cache/fortressgd/editor-cache/<editor>-<key>/`: the shared export editor's own Godot cache (§18.5). It is safe to delete.  
CI: restore cache key `fgd-templates-{godot}-{patchset}-{secret_hash}-{platforms}-e{key_epoch}`, with `-sig` appended for the signature-required variant.

---

## 8. Generator and dialect

### 8.1 Inputs

- secret bytes
- godot tag
- optional user `dialect_seed` (default: `HKDF` info `"fortressgd.dialect.v1"`)

### 8.2 Outputs (v1)

File `dialect.gen.h` (committed nowhere; build artifact):

- `FGD_KEY_SHARDS[4][8]`, `FGD_KEY_MASKS[4][8]`: the pack AES key, masked (§5.2). Never the project secret or the salt.
- `FGD_PACK_MAGIC` (u32, must not equal stock `0x43504447` / `GDPC` when `dialect = true`)
- `FGD_INDEX_PERM[N]` describing field order of the pack index record
- `FGD_OPCODE_MAP` / `FGD_OPCODE_UNMAP`, `FGD_PACK_PUBKEY`, `FGD_REQUIRE_PACK_SIGNATURE`

Deterministic: same secret + tag + generator version ⇒ identical header.

### 8.3 Pack hooks (patch)

Minimal hooks in `core/io/file_access_pack.cpp` (and editor packer counterpart):

- Read/write magic from `FGD_PACK_MAGIC` when compiled with `FORTRESSGD_DIALECT`.
- Index field order from `FGD_INDEX_PERM`.
- Stock official builds remain 100% compatible. Dialect exists only in FortressGD templates **and** in the packer used at export.

Export packer: the CLI drives the **shared FortressGD export editor** with `--export-pack`, on the export machine only. Designers do not use it.

- `fortressgd templates build --editor` builds it in Docker once per Godot tag (`target=editor`, the same series, Linux only, no LTO). Instead of a generated header it gets the fixed `patches/common/fortressgd_editor_dialect.h`, and it is compiled with `FORTRESSGD_DIALECT` only: the editor writes packs, and never runs the game's bytecode or checks pack signatures.
- `fortressgd export` passes the project's magic and index permutation in `FORTRESSGD_PACK_PARAMS=1:<magic, 8 lowercase hex>:<permutation, 4 digits>` for that one process, and the AES key in `GODOT_SCRIPT_ENCRYPTION_KEY` as for a stock export (§18.5). Unset, the editor reads and writes stock packs. Malformed, it exits with status 2 at startup.
- The CLI looks for the editor in `FORTRESSGD_EDITOR`, then the cache (on Linux hosts), then the usual Godot lookup, which still finds a patched editor a user built for one project. It fails the export if the pack it gets back is not in the project's dialect, so an official editor cannot produce a stock pack for a dialect template.

Do not reimplement the full Godot packer in Python in v1.

### 8.4 Phase 5 (nameless bytecode, opcode map, pack signatures)

- Opcode permutation table for GDScript VM (`opcode_map.py`): data-only `FGD_OPCODE_MAP` / `FGD_OPCODE_UNMAP` in `dialect.gen.h`. Compiler emit and VM dispatch use the table when `FORTRESSGD_OPCODE_MAP` is compiled in.
- Ed25519 signatures over the pack index when `[production].sign_packs = true`. Public key is data-only (`FGD_PACK_PUBKEY`); the private seed is derived from the project secret, which never ships, so no template or pack yields it.
  - Signed message: `"fortressgd.pack.sig.v1"` + the on-disk directory bytes from the directory offset to the end of the directory. For an encrypted directory that is the plaintext `u32 file_count` plus the FileAccessEncrypted blob (`md5[16]`, `u64 length`, `iv[16]`, ciphertext padded to 16 bytes). The 64-byte signature sits in the reserved header area at offset 40 (V3/V4).
  - The template verifies the signature before it registers any index entry, for plaintext and encrypted directories alike.
  - **How a template learns signatures are required (decision, #11):** `templates build` with `sign_packs = true` passes `FGD_REQUIRE_SIGNATURE=1` into Docker; the generator writes `FGD_REQUIRE_PACK_SIGNATURE = 1` into `dialect.gen.h` (0 otherwise); `manifest.json` records `"require_signature"`; the filename gets `-sig` (§7.1). Such a template refuses a pack whose signature is missing, all-zero, or invalid. `FORTRESSGD_SIGN_PACKS` (passed as Godot's `cppdefines`) stays compiled into every template, so a template without the requirement still rejects an invalid non-zero signature. `fortressgd export` with `sign_packs = true` fails if only the non-`-sig` template is cached.
  - **Encrypted sparse bundles on 4.7.2 (decision, #11):** unsupported with `sign_packs`. Godot 4.7 stores the sparse-bundle directory salt at header offset 40, where the signature goes. The patched reader reads the salt there as upstream does and, when a signature is required, refuses to load such a pack; `fortressgd export` refuses to sign one. Windows and Linux exports are not sparse by default.
- Nameless bytecode (`0003-nameless-bytecode.patch`): omit stock GDSC identifier/line tables from packed `.gdc`; runtime names live in an `FGDN` trailer. `fortressgd verify` fails if those debug tables are still present when `[production].nameless_bytecode = true`.

---

## 9. Script mangling

v1 lives entirely in the `EditorExportPlugin` / CLI export path. No engine patch required.

Behavior:

- Process only files that would be packed as GDScript.
- Strip comments, `assert`, `print_debug`, `breakpoint` (release).
- Rename user identifiers: `"_f" + HMAC-SHA256(mangle_key, "fortressgd-mangle-v2|<name>|<attempt>")[:10]`, with `mangle_key = hex(HMAC-SHA256(secret, "fortressgd.mangle.key.v1"))`. The Python and GDScript manglers must agree; `tests/mangle_corpus` holds them to it. Never key the mangler with `secret_hash`: it is public (logs, cache keys, template names), and v1 did, so anyone with it could hash guessed names and reverse the renaming. The mangle key is secret material: `leakscan` and the Action's log masks cover it.
- Never rename: Godot lifecycle methods, engine APIs, `class_name` entries that scenes reference unless the scene rewrite table is updated in the same pass.
- Emit the source map to `<project>/.fortressgd/maps/<export path relative to the project>.fortressgd.map.json` when mangling is on (an export outside the project goes to `_external/<file>-<sha256(path)[:8]>`). Never next to the artifact: the map reverses all mangling and build folders are uploaded whole. `.fortressgd/` gets a `.gdignore`; `init` suggests git-ignoring it; `verify` fails on a map next to the artifact.
- If `call("name")` / `rpc("name")` / `set("prop")` string usage is detected and not marked with an explicit allow annotation, **fail export** with file:line. Do not silently ship a broken game.

`fortressgd mangle-report` runs the same analysis as export (`fortressgd/core/mangle_report.py`) and lists every declared name that stays readable, with the rule that kept it and the file that triggered it. It needs no secret: which names are renamed does not depend on the mangle key. A test holds the report to the export's rename map. Use it to see what a decompiler still shows and which rules are worth narrowing.

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

With `nameless_bytecode` on (§8.4), packed bytecode drops the stock symbol and line tables, so stock decompilers lose names even without mangling. The names the engine needs move to the `FGDN` block, so a FortressGD-aware decompiler still reads them; only mangling removes names.

---

## 10. Verify

`fortressgd verify <artifact>`

Checks:

1. Parse pack with **FortressGD** dialect + derived key (must succeed).
2. Parse pack with **stock** GDPC parser and empty/no key (must fail if dialect or encrypt on).
3. File list contains no excluded patterns from §6.3.
4. No packed `*.fortressgd.map.json`, and none next to the artifact.
5. If `nameless_bytecode`: fail if debug name tables present in `.gdc`.
5a. If the pack directory is encrypted: fail if no file body is encrypted, or if any script body (`.gdc`, `.gde`, `.gd`) is not. `[filters].include` exempts a path.
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

- `fortressgd/patches/4.6.2/0001-key-derive.patch`
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

### Phase 5 — Opt-in hardening (shipped in 0.1.0, off by default)

- Nameless bytecode.
- Opcode map.
- Pack signatures.

Each phase ships behind feature flags in toml so a project can stop at Phase 2.

---

## 13. Testing requirements

Minimum CI (implemented in `.github/workflows/ci.yml` and `e2e.yml`; see `docs/ci.md` for what each covers and what is not covered yet):

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
- Treat `fortressgd/generator/` output as untrusted C to embed: headers only, no executable code snippets from the secret. §18 replaces this rule for generator v2 (0.2), with the constraints in §18.3.

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

---

## 18. Per-project code (0.2)

Status: implemented (§18.8). §1.3 and `THREAT_MODEL.md` describe what it covers. §8.2 and the `dialect.gen.h` references in §2, §5, §7 and §8.4 describe generator v1, which 0.2 templates no longer use; the shared export editor still gets a fixed `dialect.gen.h` (§18.5).

### 18.1 Why

Generator v1 writes a data-only header (§8.2). Every template for one Godot tag and platform therefore has the same code and the same layout; only the bytes of the masked key, magic, index permutation, opcode map and public key differ. Diffing two projects' templates shows where those bytes are, and a tool that reads them works on every FortressGD game.

Separately, building a template from source takes 30–60 minutes per platform. Users should not compile Godot.

### 18.2 Goals

1. **Per-build code.** The code that stores and decodes the per-project values differs for every `(secret, tag, key_epoch)`. A static extractor that works on one build fails on a build with a different secret or epoch (§1.3, as amended for 0.2).
2. **No Godot compile for users.** `fortressgd templates build` compiles only generated files and relinks. Target: under 10 minutes per platform on a standard GitHub-hosted Linux runner, after the build image is pulled.
3. **One container for everyone.** A published build image per `(FortressGD version, Godot tag, platform)`. The project secret is only an input to the host-side CLI, for example a CI secret in `FORTRESSGD_SECRET`.
4. **Nothing in §5.2 weakens.** The secret, the salt and the signing seed still never reach a template, a pack, a log or a container.

Non-goals stay as in §1.2 and §15 rule 2: no packer, no VM for Godot code, no anti-debug, no network checks. Generated code is small straight-line routines that decode values. It does not virtualize or transform Godot's own code.

### 18.3 Generator v2

Inputs: as §8.1, plus `key_epoch`. A code seed is derived as `HKDF-SHA256(secret, info="fortressgd.codegen.v2|" + tag + "|epoch=" + N)`. It drives a deterministic stream (HKDF-SHA256 in counter mode, standard library only). Same secret, tag, epoch and generator version give byte-identical output.

Outputs, all build artifacts that are never committed:

- `fortressgd_gen.cpp` (one or more files): generated routines.
- `fortressgd_gen_api.h` is **not generated**. It is a fixed header in `fortressgd/patches/common/` that declares the only functions patched Godot code may call:
  - `fgd_derive_key(uint8_t out[32])`
  - `fgd_pack_magic()`
  - `fgd_index_perm(uint8_t out[N])`
  - `fgd_opcode_tables(...)`
  - `fgd_pack_pubkey(uint8_t out[32])`

  No Godot file includes generated content, so a new project's generated files never invalidate Godot's object files (§18.4).

What changes per build:

1. **Key routine.** The pack key FGD-KDF-1(secret, salt) is split into 3–8 pieces of random sizes. Each piece is stored after a random chain of invertible byte or word operations (XOR, add, rotate, byte permutation, a per-build substitution table). `fgd_derive_key` undoes them in a generated order. The pieces live in separately named arrays across several functions, among decoy arrays of the same sizes, which feed decoy computations into a volatile sink.
2. **Encoded parameters.** Magic, index permutation, opcode tables and public key are no longer plain arrays. Each one is stored encoded the same way and decoded by its own generated routine. The opcode tables are decoded once at startup into a heap table, so the VM dispatch cost is unchanged.
3. **Layout.** Function order, array order, sizes of padding and decoys, and the operation chain all come from the code seed.

Constraints that replace §14's "headers only" rule:

- Generated code never contains the secret, the salt, the signing seed or the code seed. It contains what the v1 header already does (the key, masked, and public values), encoded differently.
- Generated code is produced only by `fortressgd/generator/`, from a fixed grammar of operations. It has no loops driven by data, no system calls and no I/O.
- The inputs to every routine are `volatile` loads, so the optimizer cannot fold a routine back into the plain value. This applies with link-time optimization too.
- The Python generator also has an interpreter for its own output. Tests check that interpreter, the compiled C++ (every compiler on `PATH`) and FGD-KDF-1 agree, as §5.2 requires for v1.
- `templates build` still refuses to cache a template that holds the raw key, the secret or the signing seed.

The security switches stay compile-time flags, not generated values: `-sig` (`FGD_REQUIRE_PACK_SIGNATURE`), dialect on or off, and the opcode map on or off. In data, one flipped byte would turn signature checking off.

### 18.4 Build images and templates

Release CI publishes `ghcr.io/salaryman-inc/fortressgd-build:<fgd-version>-godot<tag>-<platform>`. Each image holds:

- the Godot source at the tag, with the patch series applied,
- a complete build tree compiled once with placeholder generated files: every Godot object file, plus the scons cache or build directory needed to relink,
- the toolchain from `Dockerfile.templates` and the tag's `build-deps.sh` results.

`fortressgd templates build`:

1. On the host, generates `fortressgd_gen*.cpp` from the secret. The secret stays in the host process, as in §7.2.
2. Runs the build image with the generated files mounted read-only. The container compiles those files only, relinks `template_release`, strips it and writes the manifest.
3. Scans the result as today, then caches it.

The project secret never enters the container. When the CLI itself runs inside a FortressGD container, the compile and link run as a separate unprivileged user that can read neither `.fortressgd.secret` nor the CLI's environment.

**Link-time optimization.** `production=yes` enables it, which makes the relink redo optimization across the whole program. The first implementation measures warm relink time per platform and picks the first option that meets goal 2:

1. Keep full LTO, if the relink fits.
2. Switch to ThinLTO with a link cache (clang on Linux, llvm-mingw on Windows), so a relink reoptimizes only what changed.
3. Turn LTO off for templates, documenting the measured size and speed cost.

**Result: full LTO stays (option 1).** Each warm relink recompiled one file, `core/fortressgd_gen.cpp`.

| Where | Platform | LTO | Warm relink | Template size |
|---|---|---|---|---|
| GitHub-hosted `ubuntu-latest` (e2e run 42823510068) | Linux, 4.6.2 | full | 552 s | |
| GitHub-hosted `ubuntu-latest` (e2e run 42823510068) | Linux, 4.7.2 | full | 560 s | |
| Local, 4 cores | Linux | full | 252 s | 71.8 MB |
| Local, 16 cores | Linux | full | 164–169 s | 71.8 MB |
| Local, 16 cores | Linux | thin, clang + lld + cache | 7–8 s | 79.2 MB |
| Local, 16 cores | Linux | none | 7–8 s | 83.7 MB |
| Local, 4 and 16 cores | Windows (MinGW-GCC) | full | 9 s | 99.8 MB |

- **Linux** meets goal 2 on a hosted runner with full LTO, but with only 40–50 s to spare. A full-LTO relink reoptimizes the whole program, so it gains little from more cores: 252 s on 4 local cores, about 165 s on 16. If runner variance pushes it over 600 s, switch to option 2: ThinLTO with an lld cache, which relinks in seconds at about 10% more size.
- **Windows** needs no change. Godot links MinGW-GCC with `-fno-use-linker-plugin -fwhole-program`, so LTO adds nothing to a relink. The e2e job does not build Windows; these times are local.
- **On CI, the first build compiles the image**: 1942 s (4.7.2) and 2040 s (4.6.2), including that build's own relink. The image is about 6.7 GB unpacked. Prebuilt images (step 4) remove this cost.

Images:

- Built only by a release workflow on protected `v*` tags. It pushes with `GITHUB_TOKEN` (`packages: write` for that job only) and attests provenance with `actions/attest-build-provenance`.
- Each CLI release pins the digests (`@sha256:`) of its images and refuses any other digest unless the user passes `--image` explicitly.
- Building the image from source with the same Dockerfile stays supported (`templates build --from-source`), for users who will not run prebuilt toolchains.

Naming and cache: template names and the CI cache key gain the generator version, `-g2`. A template from generator v2 never reuses a v1 cache entry, and the reverse also holds.

**Implementation (step 3).**

- `fortressgd/docker/Dockerfile.build` layers the build image on the template image. Its context is the tag's patches and `patches/common`; it runs the entrypoint with `FGD_MODE=prebuild` and defaults to `FGD_MODE=relink`.
- Prebuild compiles the tree against `common/fortressgd_gen_placeholder.cpp`, whose functions trap, so a template linked against it by mistake dies at startup. It records in `/work/godot/.fortressgd` what a relink must match (patchset, tag, platform, arch, defines, LTO mode, build-deps flags), then deletes the placeholder-linked binary.
- Relink refuses the placeholder and any file the generator did not write, and checks that state against the request. It installs the project's `fortressgd_gen.cpp`, replays the prebuild's exact SCons arguments with no network, and fails unless SCons recompiled `core/fortressgd_gen.cpp`.
- `sign_packs` reaches only `core/io/file_access_pack.cpp`, through `core/fortressgd_variant.h`, which the build writes per template. It is still a compile-time `#define`, but switching it recompiles that one file instead of the tree a global define would invalidate. Dialect on or off changes `file_access_pack.h`, which is included widely, so images are built with the dialect on and dialect-off templates are built from source.
- Until the release workflow publishes images (step 4), `templates build` builds the image locally the first time, tagged `fortressgd-build:godot<tag>-<platform>-<arch>-fgd<patchset>-<h8>`. `h8` hashes the template image, `Dockerfile.build`, the placeholder and the LTO mode, so a stale local image is never reused. `--from-source` keeps the full compile in a fresh container.
- The template patchset id also covers the fixed common files every template compiles (`fortressgd_gen_api.h`, `fortressgd_gen_shim.h`, `fortressgd_gen_shim.cpp`). The shared editor's id does not.

**Implementation (step 4).** See `docs/releasing.md`.

- `.github/workflows/release.yml` runs on `v*` tags. It checks that the tag matches `__version__` and `plugin.cfg`. Then one job per Godot tag and platform builds the image with `python -m fortressgd.release build-image`, which uses the same `Dockerfile.build` and inputs as a local build, and pushes it to `ghcr.io/<owner>/fortressgd-build`. Each image gets two tags: its content tag (the local tag's name) and `v<version>-godot<tag>-<platform>-<arch>`. Each job attests its image's digest and pushes the attestation to the registry. Only these jobs get `packages: write`.
- The last job writes `fortressgd/images.lock.json` with `write-lock`, which requires one entry per supported tag and platform. It builds the wheel and sdist with the lock inside and checks both carry it. It attests the wheel, the sdist and the lock, and creates a draft release with all three attached.
- The lock pins `<repository>@sha256:<digest>` together with the image's content tag. `templates build` checks that this tag matches the one it computes from the installed patches and Docker files, pulls the digest, and relinks in it, so Docker refuses any other content. The tags differ only in a modified install. That fails and names `--from-source`, and so does a failed pull.
- `--image REF` relinks in another image for one platform. The relink's state check still refuses an image built for another patchset, tag, platform or LTO mode. `--patches-dir` ignores the lock and builds locally. A source checkout has no lock, and builds locally as in step 3.
- A git checkout of the tag can't contain digests that exist only after the tag is built, so the lock ships in the wheel and as a release asset. The `build-templates` Action runs from the tag's checkout. At a release tag, or a commit SHA that one points at, it downloads the asset and checks it with `gh attestation verify`: signer workflow `release.yml`, source ref the tag, source digest the commit. Then it puts the lock where the CLI reads it.
- `doctor` reports, for a dialect project's build platforms, whether each pinned image is pulled.
- `.github/rulesets/release-tags.json` restricts creating, updating and deleting `v*` tags to repository admins. An admin applies it with `gh api`.

### 18.5 Export side

Status: implemented (§8.3), except that the editor is built by `templates build --editor` and cached; it moves into the build image with §18.4.

The machine that exports is trusted: it already holds the secret. So the export side does not need per-build code.

- The patched headless editor (§8.3) is built **once** per Godot tag, without generated code, and ships in the build image.
- At export, the CLI passes the per-project values to it in environment variables for the length of one export: `FORTRESSGD_PACK_PARAMS` (magic and index permutation) and `GODOT_SCRIPT_ENCRYPTION_KEY` (the AES key). They are never written to disk, never passed as arguments, and never logged.
- The editor needs no opcode tables. A pack carries GDScript as tokens, and the template compiles them to bytecode with its own table, so the editor's bytecode never reaches a pack.
- Pack signing stays in the CLI (`fortressgd/core/pack_sign.py`). The editor never sees the signing seed.
- The editor gets its own Godot cache directory: `fortressgd export` sets `XDG_CACHE_HOME` to `<cache_dir>/editor-cache/<editor file name>-<key>`, where the key hashes the binary's resolved path, size and mtime. This works around an upstream Godot 4.7 crash. Godot names its class-doc cache by minor version only (`editor_doc_cache-4.7.res`) but checks it against a hash of the exact build. When a different 4.7 build wrote it (the user's official editor, or 4.7.1 before an upgrade to 4.7.2), the editor rebuilds it through deferred calls that finish after a headless export has freed the editor. `EditorNode::is_cmdline_mode()` then returns false, the script-doc regeneration thread walks the freed file system, and the process dies with SIGABRT after writing the pack. Godot's crash handler prints nothing, because the OS singleton is already gone. Official binaries alone reproduce it: import with 4.7.1, then `--export-pack` with 4.7.2. 4.6 is not affected. With its own directory, only one build ever writes the shared editor's cache, and the editor no longer rewrites the cache of the user's own editor. The workaround needs no Godot patch.

That removes the per-project editor build, which the dialect path needed in 0.1.

### 18.6 Compatibility

- Generator v2 derives the same values as v1 (§5.2, §8.2). Only how a template stores and decodes them changes, so packs and the export side's values are unchanged. Values extracted from a v1 build of a project still apply to its v2 builds with the same secret, tag and epoch; bump `key_epoch` when moving a released game to v2.
- `key_epoch` now changes the code shape as well as the pack key. Bumping it also breaks an extractor tuned to the previous release line.
- `dialect_id` in the manifest covers the generated sources, so `verify` can tell a v1 template from a v2 one.

### 18.7 Acceptance

In addition to §13 and §17:

- **Cross-build test (e2e).** Build templates for two secrets, A and B, and for A at two epochs.
  - A reference extractor in `tests/` locates and decodes A's key, given A's generated sources.
  - It must fail on B, and on A at the other epoch.
  - The key-handling functions of A and B must share no machine-code sequence longer than a set threshold, measured after strip.
- **Stock fixtures.** Stock unpacker fixtures still fail on every build.
- **Equivalence.** The interpreter, the compiled routines and FGD-KDF-1 agree for many seeds, on every compiler.
- **Speed.** A warm `templates build` per platform meets goal 2 on a GitHub-hosted runner, and the time is recorded in `docs/ci.md`.

These tests show that builds differ. They cannot show that a static extractor for builds in general is impossible. The README and `THREAT_MODEL.md` must say exactly that much and no more.

**Implementation (step 5).** `tests/cross_build.py`, run by the 4.7.2 dialect job of `.github/workflows/e2e.yml` on Linux templates for A, B and A at epoch 1 (`docs/ci.md`):

- The reference extractor parses A's `fortressgd_gen.cpp`: each key piece's encoded array, its chain arrays and its operations. On A's template it takes as anchor the longest key array that occurs exactly once (usually a 256-byte substitution table) and records where every other array sits relative to it. An array that occurs once near the anchor is placed for certain. A piece can be one or two bytes long, and its short arrays also occur by chance, so they are looked for in the span the certain arrays cover plus 8 KiB, and the placement that decodes to A's key is kept, as the extractor's author would check it. On a target it finds the anchor, reads every array at the recorded offset and runs A's chain. It must return A's key on A, and must fail (anchor not found, or bytes that are not the key) on B and on A at epoch 1.
- The machine-code check finds, in each template, the instructions that address that build's certainly placed key arrays (located from the build's own source), and takes each run from the first such instruction to the last, merging hits less than 512 bytes apart. It disassembles with GNU `objdump` and normalizes each instruction, replacing RIP-relative displacements and branch and call targets. The threshold is 32 instructions. A compared with itself must exceed it, as a control. In e2e run 42951715331 (Linux 4.7.2, full LTO) A's key code was 494 instructions; B shared at most 4 with it and A at epoch 1 at most 12. Over 1,157 pairs from 580 random secrets at two epochs, compiled alone, the maximum was 26 and the 99th percentile 10–17. What builds share is one operation's loop: each kind of operation compiles to a fixed loop, so a key piece of the same length with the same leading operations gives the same instructions. That is the limit of per-build code a grammar-aware tool can use; varying the code emitted per operation would shrink it.
- Stock fixtures: GDRE Tools (latest) runs on both the derived-key and the dialect Linux builds (`.github/actions/gdre-check`), and the pinned KeyDot on the derived-key Windows build.
- Equivalence is step 2's `tests/test_generate_compiled.py` and `tests/test_opchain.py`. Speed: the warm relink times are in `docs/ci.md`.

### 18.8 Order of work

Each step is a separate PR with its own tests:

1. Shared headless editor reading values from the environment (§18.5). Done.
2. Generator v2, its interpreter, and patches switched to the generated header (§18.3), still built from source. Done.
3. Build images with a precompiled tree, plus the relink path and the LTO measurement (§18.4). Done.
4. Release workflow: tag ruleset, image publishing, provenance, and digest pinning in the CLI. Done; the ruleset is applied.
5. Cross-build e2e and docs: README, `THREAT_MODEL.md` (removing "planned"), `docs/ci.md`. Done.

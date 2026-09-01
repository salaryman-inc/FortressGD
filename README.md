# FortressGD

Open-source **release toolchain** for Godot 4. Not a fork. Not DRM. Not anti-cheat.

> Export a Godot game that stock GDRE/KeyDot cannot one-click recover, without maintaining a fork. This raises the cost of automated recovery. It does not make a local client unextractable.

Designers keep the official Godot editor. Custom **export templates** are built in Docker or CI from a pinned Godot tag plus a small patch quilt. Production exports refuse to ship source, and `fortressgd verify` fails CI if they did.

**Status:** spec and repo skeleton. Implementation follows [`DESIGN.md`](DESIGN.md) in phases. Commands below are the intended v1 interface; they are not all wired yet.

| Phase | What you get |
|---|---|
| 0 | `init`, `doctor`, secret helpers, plugin reads config |
| 1 | Release filters + `verify` leak checks |
| 2 | Custom templates + derived AES key (`FGD-KDF-1`) |
| 3 | Per-secret pack dialect |
| 4 | GDScript mangling on export |
| 5 | Nameless bytecode, signatures (later) |

Supported engine tags for v1: **Godot 4.6.2 and 4.7.x stable**. See `DESIGN.md` §4.

---

## Why this exists

Godot’s PCK is a simple container. Official AES encryption still stores a 32-byte key next to a known error string. Tools like KeyDot and GDRE Tools recover a near-source project in seconds.

Existing answers each cover one slice:

- Official encryption — key is extractable
- Godot-Secure — engine patch, no export hygiene or CI
- GDMaim — names only; pack still opens
- ChaosProtector — paid Windows packer; not auditable

FortressGD is the pipeline: filters + derived key + optional dialect + optional mangler + verify. Stock unpackers of **documented versions** should fail. A person with a debugger can still dump decrypted resources. That is accepted and written down in [`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## What it does / does not

**Does**

- Keep the official editor for day-to-day work
- Build `template_release` binaries in Docker from `patches/<godot-tag>/`
- Derive the PCK AES key (`FGD-KDF-1`, HKDF-SHA256) instead of embedding the raw blob
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

---

## Requirements

- Godot **4.6.2** or **4.7.x** (official editor)
- Docker (template builds)
- A 32-byte secret, 64 hex chars, **not in git**
- Optional: GitHub Actions for the template factory

You do not need SCons or a local Godot source tree on designer machines.

---

## Quick start (intended v1)

```bash
# in your Godot project root
fortressgd init
# writes .fortressgd.toml, suggests .gitignore entries, installs addons/fortressgd

fortressgd secret generate
export FORTRESSGD_SECRET="$(cat .fortressgd.secret)"   # or use your OS keychain / CI secret
# add .fortressgd.secret to .gitignore  — never commit this

fortressgd templates build --godot 4.6.2 --platform linux
# also: --platform windows

fortressgd export --preset Linux
fortressgd verify path/to/your_game.pck
```

In the editor: enable the FortressGD plugin, turn **Production export** on for the Release preset, export as usual. If templates for `(godot, secret_hash, platform)` are missing, export is blocked with the exact `templates build` command to run.

Rotating `FORTRESSGD_SECRET` requires rebuilding templates. Old packs will not load. That is intended.

---

## Configuration

`.fortressgd.toml` lives at the project root and **is committed**. It must not contain the secret.

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
```

Release exports also force-exclude GDScript **text** (bytecode only) unless you allowlist a path. Dynamic `call("name")` / `rpc("name")` / `set("prop")` fail the export when mangling is on — use Callables. See `docs/agent-rules.md` once that file exists.

Secret sources, in order: `--secret-file`, `FORTRESSGD_SECRET`, optional OS keychain.

---

## Commands

```text
fortressgd init
fortressgd doctor
fortressgd secret generate | fortressgd secret status
fortressgd templates build [--godot X.Y.Z] [--platform windows|linux]
fortressgd templates list
fortressgd export --preset NAME
fortressgd verify PATH.pck|PATH.exe
```

Exit codes: `0` ok, `1` config/user error, `2` verify/policy failure, `3` tool or engine build failure.

---

## CI

Build templates once per `(godot version, patchset, secret hash, platform)` and cache them. A GitHub Action is specified in `DESIGN.md` §2.3:

```yaml
# sketch — action lands with Phase 2
- uses: you/fortressgd/actions/build-templates@v1
  with:
    godot_version: "4.6.2"
    platforms: "linux,windows"
    secret: ${{ secrets.FORTRESSGD_SECRET }}
```

Then `fortressgd export` + `fortressgd verify` on the artifact. Optional `FORTRESSGD_UNPACKER_TESTS=1` runs pinned KeyDot/GDRE versions; those tools failing to recover the project is a pass.

---

## Repository layout

```text
DESIGN.md              source of truth for implementers
THREAT_MODEL.md        short threat model
plugin/addons/fortressgd editor plugin
cli/                   fortressgd CLI
core/                  shared library
generator/             dialect.gen.h
patches/<godot-tag>/   quilt applied to a pinned upstream tag
docker/                template build image
actions/               CI template factory
testdata/              sample project + unpacker fixtures
```

There is **no** Godot source tree in this repo. A tag without `patches/<tag>/series` is unsupported.

---

## For implementation agents

1. Read [`DESIGN.md`](DESIGN.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md) before writing code.
2. Do not add packers, VMs, anti-debug, or license servers.
3. Do not vendor Godot source.
4. Fail export rather than ship a recoverable or broken build.
5. Update `DESIGN.md` in the same change if behavior shifts.

---

## Comparison (short)

| | Official encrypt | Godot-Secure | GDMaim | ChaosProtector | FortressGD |
|---|---|---|---|---|---|
| Stock KeyDot/GDRE | Usually succeed | Usually fail | Pack still opens | Claim fail (Windows) | Target: fail + CI proof |
| Editor | Official + custom templates | Patched editor | Official | Official | Official |
| Source leaks | Your problem | Your problem | Your problem | Your problem | `verify` fails the build |
| Script names | Intact | Intact | Mangled | Intact | Optional mangler |
| You compile Godot how? | By hand | By hand, in-place script | No | No | Docker / Action |
| License | MIT engine | MIT script | MIT | Paid | MIT |

---

## License

MIT.

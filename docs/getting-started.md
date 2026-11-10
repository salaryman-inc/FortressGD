# Getting started

Phase 1 of FortressGD is **export hygiene**: keep source, work files, and plugin internals out of a Release pack, then prove it with `fortressgd verify`.

You do this with the **official Godot editor**. Custom export templates, Docker, and `fortressgd templates build` are **not required** for this workflow.

## 1. Install into a Godot 4.6.2 / 4.7.2 project

Install FortressGD (see the README's Install section), then:

```bash
cd /path/to/your/godot/project
fortressgd init
```

From a source checkout without installing, run `python3 /path/to/FortressGD/bin/fortressgd` in place of `fortressgd`.

This writes `.fortressgd.toml` (commit it; it has no secret), suggests `.gitignore` entries, copies `addons/fortressgd`, and enables the **FortressGD** plugin in `project.godot`.

Keep the plugin enabled: Godot applies FortressGD's release filters only through it. If it is turned off in **Project → Project Settings → Plugins**, `fortressgd export` refuses to run and `fortressgd doctor` warns until you run `fortressgd init` again or re-enable it.

## 2. Mark a production export preset

In **Project → Export**, open the preset you use for Release (not your debug preset):

1. Set **GDScript Export Mode** to **Binary tokens** or **Compressed binary tokens** (Godot’s default). That packs bytecode (`.gdc`) instead of GDScript text.
2. Add the custom feature tag `fortressgd_production` (Resources / features field on the preset).

Presets **without** that tag are not force-filtered. Keep a debug preset without it.

When the tag is on, the export plugin **skips** these paths unless the same pattern is listed in `[filters].include` in `.fortressgd.toml`:

- `*.gd` (text scripts — bytecode only), `*.cs`
- DCC / work files: `*.sln` `*.csproj` `*.blend` `*.psd` `*.kra` `*.tmp`
- `addons/fortressgd/**`
- `*.fortressgd.map.json`

## 3. Export as usual

Export PCK/ZIP or a full project from the official editor. You do not need FortressGD templates for leak checks.

## 4. Verify the artifact

```bash
fortressgd verify path/to/game.pck
# also:  fortressgd verify path/to/game.exe
```

`verify` lists packed paths with a **stock GDPC** parser (no FortressGD dialect, no encryption key) and fails if any packed path matches the excludes above.

| Exit | Meaning |
|---|---|
| 0 | leak-free listing |
| 2 | policy failure (leaks); stderr includes `error:` and `Run:` |
| 1 | missing/unreadable artifact or bad config |

Allowlist example — pack a specific text script that would otherwise fail:

```toml
[filters]
include = ["mods/hook.gd"]
```

Re-export, then run `fortressgd verify` again.

## What this does not require

Custom export templates, Docker, and `fortressgd templates build` are **not required** for the leak-check workflow above.

## 5. Optional: derived-key templates (Phase 2)

When you are ready to encrypt a Release PCK so stock KeyDot cannot one-click extract a 32-byte key:

```bash
export FORTRESSGD_SECRET="$(cat .fortressgd.secret)"
fortressgd templates build --godot 4.6.2 --platform linux
fortressgd export --preset Linux
```

That builds `template_release` in Docker (see `docs/ci.md`) and runs one official Godot export with `GODOT_SCRIPT_ENCRYPTION_KEY` set to FGD-KDF-1(secret, salt) for that process only. If the preset's Encryption Include Filters is empty, `export` sets it to `*` for that run, because Godot otherwise encrypts only the file list and none of the file contents. Missing templates print the exact `fortressgd templates build …` command to run.

Set `[production].dialect = false` to stay on that Phase 2 path.

## 6. Optional: pack dialect (Phase 3)

With `[production].dialect = true` (the example default), `fortressgd export` drives a **FortressGD-patched headless editor** (`target=editor`, same patches as the templates) with `--export-pack`. Point `FORTRESSGD_GODOT` at that binary. Designers keep using the official editor day-to-day.

`fortressgd verify` then parses the artifact with the dialect magic + index permutation and the derived AES key. A stock GDPC listing of that pack must fail.

With `[production].mangle_scripts = true`, `fortressgd export` (and the editor plugin) strip comments / `assert` / `print_debug` / `breakpoint` and rename user identifiers. Unmarked `call("name")` / `rpc("name")` / `set("prop")` fail the export. The source map (`*.fortressgd.map.json`) is written to `.fortressgd/maps/` in the project, never packed and never next to the artifact; keep it out of git and out of anything you publish. See `docs/agent-rules.md`.

A debugger can still dump decrypted resources from a running client; see `THREAT_MODEL.md`.

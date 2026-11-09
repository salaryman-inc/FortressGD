# Security policy

FortressGD protects other people's games, so a bug here can quietly weaken every build made with it. Please report security problems privately.

## Reporting

Use GitHub's private vulnerability reporting: **[Report a vulnerability](https://github.com/salaryman-inc/FortressGD/security/advisories/new)** (Security tab → "Report a vulnerability").

Do not open a public issue, pull request or discussion for a security problem. Include:

- the FortressGD version (`fortressgd --version`) and Godot tag,
- the relevant `.fortressgd.toml` (it holds no secret; never send `.fortressgd.secret` or `FORTRESSGD_SECRET`),
- steps or a minimal project that reproduce the problem.

We aim to acknowledge a report within a week and will keep you updated while we fix it. Once a fix ships we publish an advisory and credit you unless you ask us not to.

## Supported versions

FortressGD is pre-1.0. Only the latest release gets security fixes.

## In scope

Anything that breaks a promise in [`THREAT_MODEL.md`](THREAT_MODEL.md), for example:

- The project secret or the pack-signing seed reaching anything that ships (a template, a pack, a source map) or a log, the template cache, `export_presets.cfg`, or a Docker image layer.
- The derived PCK key reaching any of those unmasked. A template holds it only as masked shards (DESIGN.md §5.2).
- `fortressgd verify` passing an artifact that still contains an excluded file (`.gd` text, `.cs`, `.pdb`, DCC files, source maps) or a stock debug table it is meant to reject.
- A stock tool (KeyDot, GDRE Tools / gdsdecomp, gdke, GodotPCKExplorer) recovering the key or the project from a FortressGD-protected build in one step.
- A `-sig` template loading a pack whose index signature is missing, zeroed or invalid.
- Supply-chain problems in the patches, the Docker build, or the GitHub Action, such as unpinned inputs or a way for a pull request to read the secret.

## Out of scope

The threat model accepts these on purpose. Report them as normal issues if you think the docs are wrong:

- Dumping the derived key or decrypted resources from a running game with a debugger.
- Reading one build's pack key out of its template with a tool that knows FortressGD's layout. The source is public; the masking only defeats tools that don't know it.
- Writing a dedicated unpacker for one game's pack dialect.
- Ripping textures or audio after decryption.
- Decompiling a .NET assembly.
- Gameplay cheats.

## If your project secret leaked

That is not a FortressGD vulnerability, but it does need action: follow the rotation runbook in [`docs/secrets.md`](docs/secrets.md).

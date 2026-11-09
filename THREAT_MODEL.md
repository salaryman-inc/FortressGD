# FortressGD threat model

See `DESIGN.md` §1.3 for the normative text. This page is the short form for README and agents.

## We try to stop

- One-click key extraction from a stock Godot binary (string + pattern scanners).
- One-click full project recovery (GDRE Tools / gdsdecomp on a stock PCK).
- Shipping the repo by accident (`.gd` text, `.cs` source, DCC files, source maps).
- Anyone recovering the project secret or the pack-signing seed from what ships. Neither is ever in a template or a pack.

## We do not try to stop

- A person with a debugger dumping the derived key or decrypted resources.
- A tool written for FortressGD. The source is public, so a tool that knows the template layout can read one build's pack key and dialect parameters straight from the binary. That costs about as much as the debugger attack above.
- A person who reverse-engineers this game’s pack dialect and writes a dedicated unpacker.
- Texture/audio ripping from memory or disk after decrypt.
- Gameplay cheats that need a server to prevent.
- Decompiling a .NET game's managed assembly. Excluding `.cs` only keeps the source *text* out of the pack; the compiled C# still ships and tools such as ILSpy or dnSpy turn it back into near-original source in one click. FortressGD does not obfuscate .NET assemblies. It does refuse to ship `.pdb` debug symbols, which would also restore names and line numbers. Use a .NET obfuscator if your C# needs protection.

## What holds after a build's key is extracted

Assume every value in a shipped binary is public. Someone who extracts one build's pack key, by debugger or by a FortressGD-aware tool, can decrypt that build's packs. The key depends only on the project secret, the Godot version and `[production].key_epoch`, so it also opens every other build of the project with the same three, on any platform, until you bump the epoch or rotate the secret. They still cannot:

- get the project secret, so the key stops working for builds made after you rotate it, and does not open builds for another Godot version;
- sign packs, so a `sign_packs` template still refuses a modified pack;
- get back what was never shipped: script source text, comments, `assert`/`print_debug` lines, original identifiers renamed by the mangler, or files the release filters excluded. Mangled names are keyed by the project secret, so they cannot be reversed by hashing guessed names. Only the source map reverses them, and it stays in `.fortressgd/maps/`, out of the build folder and out of git.

Protection that must survive a determined attacker comes from that last list, not from the encryption. The pack dialect, the opcode map and nameless bytecode only defeat tools that don't know FortressGD: nameless bytecode moves identifier names into an `FGDN` block the engine reads, so a FortressGD-aware decompiler gets every name back. Only the mangler removes names.

## Consequence

FortressGD is a release toolchain. Treat “stock tools fail on this build” as success. Treat “nobody can ever extract assets” as out of scope. Do not add features that only address the second sentence.

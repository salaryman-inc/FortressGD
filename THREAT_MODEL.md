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

## Planned for 0.2: per-project code (not implemented)

Everything above describes 0.1, which is what ships today. This section is the goal for 0.2. Do not claim it for a build until `DESIGN.md` §18 is implemented and its acceptance tests pass.

In 0.1 every template for a Godot version and platform has the same code and the same layout. Only the bytes of the masked key, magic, index permutation, opcode map and public key differ. A FortressGD-aware tool written once can therefore read those values out of every FortressGD game. The source being public is enough to write it.

0.2 makes the code that holds and decodes those values different for every project, and for every `key_epoch` of a project. The goal:

> No static tool recovers the pack key, the pack layout or the opcode map from FortressGD builds in general. A tool that reads one build's values without running it does not work on a build with a different secret or epoch. Each build needs its own analysis, by a person or with AI help, or a runtime attack.

Moves into scope in 0.2:

- A FortressGD-aware tool that reads values from a fixed location, a fixed array shape, or a fixed instruction pattern.
- Reusing an extractor written for one project, or one release line, on another.

Stays out of scope in 0.2:

- Anything that executes or emulates the build: a debugger, hooking the AES routine, emulating the key routine, or dumping decrypted resources from memory. A game has to decrypt its own packs, so a runtime tool that works on every FortressGD game can still be written. 0.2 moves the points such a tool must find, but promises nothing against it.
- Everything else under "We do not try to stop".

What holds after a key is extracted does not change.

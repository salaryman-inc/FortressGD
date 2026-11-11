# FortressGD threat model

See `DESIGN.md` §1.3 for the normative text. This page is the short form for README and agents.

## We try to stop

- One-click key extraction from a stock Godot binary (string + pattern scanners).
- One-click full project recovery (GDRE Tools / gdsdecomp on a stock PCK).
- Shipping the repo by accident (`.gd` text, `.cs` source, DCC files, source maps).
- Anyone recovering the project secret or the pack-signing seed from what ships. Neither is ever in a template or a pack.
- A FortressGD-aware tool that reads one build's values without running it, then works on another build. Since 0.2 the code that stores and decodes the pack key, the pack layout, the opcode map and the public key is generated per project secret, Godot version and `key_epoch` (`DESIGN.md` §18). A tool that reads those values from a fixed location, a fixed array shape or a fixed instruction pattern, or an extractor written for one project or one release line, must fail on a build with another secret or epoch.

## We do not try to stop

- A person with a debugger dumping the derived key or decrypted resources.
- Anything that executes or emulates the build: hooking the AES routine, emulating the key routine, or dumping decrypted resources from memory. A game has to decrypt its own packs, so a runtime tool that works on every FortressGD game can still be written. Per-build code moves the points such a tool must find, but promises nothing against it.
- Analysis of one build, by a person or with AI help. The source is public, so someone who studies one build's generated code can read that build's pack key and dialect parameters. Per-build code means the work has to be redone for each project and each `key_epoch`.
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

## What the tests show about per-build code

The e2e workflow builds the sample project with two secrets, and one of them at two key epochs. A reference extractor written from one build's generated source recovers that build's key, and fails on the other two. The key-handling machine code of two builds shares no run of more than 32 instructions once addresses are masked; what they do share is the loop for one kind of operation. Stock GDRE Tools and KeyDot still fail on the protected builds. Details are in `docs/ci.md`.

That shows that builds differ. It does not show that a static extractor for FortressGD builds in general is impossible. The generator uses a fixed, public grammar of operations, so a tool that recognizes that grammar, rather than one build's bytes, is not ruled out. Treat per-build code as raising the cost of reusing an extractor, not as a guarantee.

Builds made before 0.2 (generator v1) have the same code and layout for every project. Their values can be read by a tool written once, and the values extracted from a v1 build also apply to v2 builds with the same secret, Godot version and `key_epoch`. Bump `key_epoch` when you move a released game to 0.2.

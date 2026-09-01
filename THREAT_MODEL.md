# Forgekit threat model

See `DESIGN.md` §1.3 for the normative text. This page is the short form for README and agents.

## We try to stop

- One-click key extraction from a stock Godot binary (string + pattern scanners).
- One-click full project recovery (GDRE Tools / gdsdecomp on a stock PCK).
- Shipping the repo by accident (`.gd` text, `.cs` source, DCC files, source maps).

## We do not try to stop

- A person with a debugger dumping the derived key or decrypted resources.
- A person who reverse-engineers this game’s pack dialect and writes a dedicated unpacker.
- Texture/audio ripping from memory or disk after decrypt.
- Gameplay cheats that need a server to prevent.

## Consequence

Forgekit is a release toolchain. Treat “stock tools fail on this build” as success. Treat “nobody can ever extract assets” as out of scope. Do not add features that only address the second sentence.

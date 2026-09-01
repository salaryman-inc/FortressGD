"""Generator for dialect.gen.h (salt, shards, pack magic, index perm, opcode map, pack pubkey)."""

from generator.dialect import GENERATOR_VERSION, render_dialect_header, write_dialect_header

__all__ = ["GENERATOR_VERSION", "render_dialect_header", "write_dialect_header"]

"""Opcode permutation table for the GDScript VM (DESIGN.md §8.4 / Phase 5)."""

from __future__ import annotations

from core.kdf import hkdf_sha256
from core.secret import SECRET_BYTES

# GDScriptFunction::Opcode count: OPCODE_OPERATOR .. OPCODE_END inclusive.
# Godot 4.6.2 and 4.7.2 both enumerate 158 opcodes (static_assert vs jump table).
FGD_OPCODE_COUNT = 158

_OPCODE_INFO = b"fortressgd.opcode.v1"


def opcode_count(_godot_tag: str | None = None) -> int:
    return FGD_OPCODE_COUNT


def _entropy(secret: bytes, godot_tag: str, dialect_seed: bytes | None) -> bytes:
    if len(secret) != SECRET_BYTES:
        raise ValueError("secret must be {0} bytes".format(SECRET_BYTES))
    from generator.dialect import _domain_salt, _info

    n = FGD_OPCODE_COUNT
    return hkdf_sha256(
        secret,
        _domain_salt(godot_tag, "opcodes"),
        _info(dialect_seed) + b"|" + _OPCODE_INFO,
        n * 2,
    )


def _fisher_yates(n: int, entropy: bytes) -> list[int]:
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = int.from_bytes(entropy[2 * i : 2 * i + 2], "little") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    if perm == list(range(n)):
        perm[0], perm[1] = perm[1], perm[0]
    return perm


def opcode_perm(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> tuple[int, ...]:
    """Bijection as a tuple: stored_opcode = perm[original]. Not the identity."""
    perm = _fisher_yates(FGD_OPCODE_COUNT, _entropy(secret, godot_tag, dialect_seed))
    return tuple(perm)


def opcode_map(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> dict[int, int]:
    """
    Deterministic bijection of GDScript VM opcode integers.

    Same secret + Godot tag + generator version => same map.
    Different secret => different map. Never the identity.
    """
    perm = opcode_perm(secret, godot_tag, dialect_seed)
    return {i: perm[i] for i in range(FGD_OPCODE_COUNT)}


def opcode_unmap(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> tuple[int, ...]:
    """Inverse of opcode_perm: original = unmap[stored]."""
    perm = opcode_perm(secret, godot_tag, dialect_seed)
    inv = [0] * FGD_OPCODE_COUNT
    for src, dst in enumerate(perm):
        inv[dst] = src
    return tuple(inv)


def _c_u16_array(name: str, values: tuple[int, ...], indent: str = "\t") -> str:
    inner = ", ".join(str(int(v)) for v in values)
    return "{0}static const uint16_t {1}[{2}] = {{ {3} }};".format(
        indent, name, len(values), inner
    )


def render_opcode_arrays(
    secret: bytes,
    godot_tag: str,
    dialect_seed: bytes | None = None,
) -> list[str]:
    """Data-only C arrays. No executable snippets derived from the secret."""
    perm = opcode_perm(secret, godot_tag, dialect_seed)
    inv = opcode_unmap(secret, godot_tag, dialect_seed)
    return [
        "{0}static const uint16_t FGD_OPCODE_COUNT = {1};".format("\t", FGD_OPCODE_COUNT),
        _c_u16_array("FGD_OPCODE_MAP", perm),
        _c_u16_array("FGD_OPCODE_UNMAP", inv),
    ]

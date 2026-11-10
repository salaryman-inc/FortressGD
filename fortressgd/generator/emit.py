"""Emit C++ for generator v2 op chains (DESIGN.md §18.3).

Each value is embedded as its encoded bytes plus the chain parameters, and a
generated function runs the chain forward at runtime to recover the plaintext —
the exact mirror of opchain.decode_value. Inputs are read through volatile loads
so the optimizer cannot fold a routine back into the plaintext, including under
link-time optimization.

This file only formats C++ text from a chain; the chain and the values come from
the caller. The tests compile the output with every C++ compiler on PATH and
check it against the Python interpreter and FGD-KDF-1.
"""

from __future__ import annotations

from fortressgd.generator.opchain import AddKey, Op, PermPos, Rotate, Sbox, XorKey, encode_value


def _c_bytes(data: bytes) -> str:
    return ", ".join("0x{0:02x}".format(b) for b in data)


def _vol_array(name: str, data: bytes) -> str:
    return "\tstatic const volatile uint8_t {0}[{1}] = {{ {2} }};".format(name, len(data), _c_bytes(data))


def _emit_op(op: Op, idx: int, length: int) -> list[str]:
    """C++ statements applying one op (decode direction) to buffer ``b[length]``."""
    lines: list[str] = []
    if isinstance(op, XorKey):
        lines.append(_vol_array("k{0}".format(idx), op.key))
        lines.append("\tfor (int i = 0; i < {0}; i++) b[i] = (uint8_t)(b[i] ^ k{1}[i]);".format(length, idx))
    elif isinstance(op, AddKey):
        lines.append(_vol_array("k{0}".format(idx), op.key))
        lines.append("\tfor (int i = 0; i < {0}; i++) b[i] = (uint8_t)(b[i] + k{1}[i]);".format(length, idx))
    elif isinstance(op, Rotate):
        r = op.bits
        lines.append(
            "\tfor (int i = 0; i < {0}; i++) b[i] = (uint8_t)((b[i] << {1}) | (b[i] >> {2}));".format(
                length, r, 8 - r
            )
        )
    elif isinstance(op, PermPos):
        lines.append(_vol_array("p{0}".format(idx), bytes(op.perm)))
        lines.append("\t{")
        lines.append("\t\tuint8_t t[{0}];".format(length))
        lines.append("\t\tfor (int i = 0; i < {0}; i++) t[i] = b[p{1}[i]];".format(length, idx))
        lines.append("\t\tfor (int i = 0; i < {0}; i++) b[i] = t[i];".format(length))
        lines.append("\t}")
    elif isinstance(op, Sbox):
        lines.append(_vol_array("s{0}".format(idx), op.table))
        lines.append("\tfor (int i = 0; i < {0}; i++) b[i] = s{1}[b[i]];".format(length, idx))
    else:  # pragma: no cover - guarded by OP_KINDS
        raise TypeError("unknown op {0!r}".format(op))
    return lines


def emit_decode_fn(name: str, plain: bytes, chain: list[Op]) -> str:
    """An inline C++ function ``void <name>(uint8_t out[L])`` that yields ``plain``.

    The embedded bytes are the encoded form; the body runs the chain to decode.
    inline so the generated header can be included by many translation units with
    one merged definition; the volatile locals still defeat constant folding.
    """
    length = len(plain)
    stored = encode_value(plain, chain)
    out: list[str] = []
    out.append("inline void {0}(uint8_t out[{1}]) {{".format(name, length))
    out.append(_vol_array("enc", stored))
    out.append("\tuint8_t b[{0}];".format(length))
    out.append("\tfor (int i = 0; i < {0}; i++) b[i] = enc[i];".format(length))
    for idx, op in enumerate(chain):
        out.extend(_emit_op(op, idx, length))
    out.append("\tfor (int i = 0; i < {0}; i++) out[i] = b[i];".format(length))
    out.append("}")
    return "\n".join(out)

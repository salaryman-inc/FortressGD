"""Emit C++ for generator v2 op chains (DESIGN.md §18.3).

Each value is embedded as its encoded bytes plus the chain parameters, and a
generated function runs the chain forward at runtime to recover the plaintext —
the exact mirror of opchain.decode_value. Inputs are read through volatile loads
so the optimizer cannot fold a routine back into the plaintext, including under
link-time optimization.

Every operation is emitted in one of several equivalent forms, chosen per op by
``op.form`` (drawn from the code stream in opchain.build_chain). A form changes
only the C++ text — the loop direction, an equal arithmetic expression, a little
unrolling — never what the op computes, so the same operation on the same length
compiles to different instructions across builds. For each kind there are exactly
``opchain.OP_FORM_COUNTS[kind]`` forms; ``_FORMS`` below lists them, and a test
asserts the two agree. The copy that loads the encoded bytes is itself emitted in
a seed-chosen shape, so builds do not share that loop either.

This file only formats C++ text from a chain; the chain and the values come from
the caller. The tests compile the output with every C++ compiler on PATH and
check it against the Python interpreter and FGD-KDF-1.
"""

from __future__ import annotations

from fortressgd.generator.opchain import (
    AddKey,
    Op,
    OP_FORM_COUNTS,
    PermPos,
    Rotate,
    Sbox,
    XorKey,
    encode_value,
)


def _c_bytes(data: bytes) -> str:
    return ", ".join("0x{0:02x}".format(b) for b in data)


def _vol_array(name: str, data: bytes) -> str:
    return "\tstatic const volatile uint8_t {0}[{1}] = {{ {2} }};".format(name, len(data), _c_bytes(data))


# ---------------------------------------------------------------- loop shapes
#
# A "body" is a function ix -> a full C++ statement that transforms element ``ix``
# of ``b`` in place. A loop shape wraps a body in an equal iteration over the
# ``length`` elements. Trip counts are compile-time constants (no data-driven
# loops, DESIGN.md §18.3); only the shape of the iteration differs.


def _loop_fwd(length: int, body, indent: str = "\t") -> list[str]:
    return ["{0}for (int i = 0; i < {1}; i++) {2}".format(indent, length, body("i"))]


def _loop_bwd(length: int, body, indent: str = "\t") -> list[str]:
    return ["{0}for (int i = {1} - 1; i >= 0; i--) {2}".format(indent, length, body("i"))]


def _loop_unroll2(length: int, body, indent: str = "\t") -> list[str]:
    # Two elements per turn, with a one-element tail when ``length`` is odd.
    return [
        "{0}for (int i = 0; i + 1 < {1}; i += 2) {{".format(indent, length),
        "{0}\t{1}".format(indent, body("i")),
        "{0}\t{1}".format(indent, body("i + 1")),
        "{0}}}".format(indent),
        "{0}for (int i = {1} - ({1} % 2); i < {1}; i++) {2}".format(indent, length, body("i")),
    ]


_ELEMENTWISE_SHAPES = (_loop_fwd, _loop_bwd, _loop_unroll2)


# ---------------------------------------------------------------- op bodies


def _body_xor(idx: int, variant: int):
    k = "k{0}".format(idx)
    if variant == 0:
        return lambda ix: "b[{0}] = (uint8_t)(b[{0}] ^ {1}[{0}]);".format(ix, k)
    # a ^ k == (a | k) - (a & k), always in range for bytes (a|k >= a&k).
    return lambda ix: "b[{0}] = (uint8_t)((b[{0}] | {1}[{0}]) - (b[{0}] & {1}[{0}]));".format(ix, k)


def _body_add(idx: int, variant: int):
    k = "k{0}".format(idx)
    if variant == 0:
        return lambda ix: "b[{0}] = (uint8_t)(b[{0}] + {1}[{0}]);".format(ix, k)
    # a + k == a - (uint8_t)(-k) mod 256.
    return lambda ix: "b[{0}] = (uint8_t)(b[{0}] - (uint8_t)(-{1}[{0}]));".format(ix, k)


def _body_sbox(idx: int, variant: int):
    s = "s{0}".format(idx)
    return lambda ix: "b[{0}] = {1}[b[{0}]];".format(ix, s)


def _body_rot(bits: int, order: int):
    r, l = bits, 8 - bits
    if order == 0:
        return lambda ix: "b[{0}] = (uint8_t)((b[{0}] << {1}) | (b[{0}] >> {2}));".format(ix, r, l)
    return lambda ix: "b[{0}] = (uint8_t)((b[{0}] >> {2}) | (b[{0}] << {1}));".format(ix, r, l)


# ---------------------------------------------------------------- per-op emit
#
# Each entry of ``_FORMS[kind]`` is a function (op, idx, length) -> C++ lines for
# one form. The lists are indexed by ``op.form``; their lengths must match
# ``OP_FORM_COUNTS`` (checked below and by a test).


def _elementwise_forms(decl_name, body_factory, n_variants):
    """Forms for an op whose body is applied element by element.

    One form per (loop shape, arithmetic variant); ``decl_name`` is the key/sbox
    array the body reads, or ``None`` for rotate, which reads no array.
    """
    forms = []
    for variant in range(n_variants):
        for shape in _ELEMENTWISE_SHAPES:
            def emit(op, idx, length, _shape=shape, _variant=variant):
                lines: list[str] = []
                if decl_name is not None:
                    lines.append(_vol_array(decl_name.format(idx), _op_array(op, idx)))
                lines.extend(_shape(length, body_factory(op, idx, _variant)))
                return lines
            forms.append(emit)
    return forms


def _op_array(op: Op, idx: int) -> bytes:
    if isinstance(op, (XorKey, AddKey)):
        return op.key
    if isinstance(op, Sbox):
        return op.table
    if isinstance(op, PermPos):
        return bytes(op.perm)
    raise TypeError("op {0!r} has no array".format(op))


def _xor_forms() -> list:
    return _elementwise_forms("k{0}", lambda op, idx, v: _body_xor(idx, v), 2)


def _add_forms() -> list:
    return _elementwise_forms("k{0}", lambda op, idx, v: _body_add(idx, v), 2)


def _sbox_forms() -> list:
    return _elementwise_forms("s{0}", lambda op, idx, v: _body_sbox(idx, v), 1)


def _rot_forms() -> list:
    forms = []
    for order in (0, 1):
        for shape in (_loop_fwd, _loop_bwd):
            def emit(op, idx, length, _shape=shape, _order=order):
                return _shape(length, _body_rot(op.bits, _order))
            forms.append(emit)
    return forms


def _emit_perm(op: PermPos, idx: int, length: int, *, backward: bool) -> list[str]:
    p = "p{0}".format(idx)
    fill = (
        "\t\tfor (int i = {0} - 1; i >= 0; i--) t[i] = b[{1}[i]];".format(length, p)
        if backward
        else "\t\tfor (int i = 0; i < {0}; i++) t[i] = b[{1}[i]];".format(length, p)
    )
    return [
        _vol_array(p, bytes(op.perm)),
        "\t{",
        "\t\tuint8_t t[{0}];".format(length),
        fill,
        "\t\tfor (int i = 0; i < {0}; i++) b[i] = t[i];".format(length),
        "\t}",
    ]


def _perm_forms() -> list:
    return [
        lambda op, idx, length: _emit_perm(op, idx, length, backward=False),
        lambda op, idx, length: _emit_perm(op, idx, length, backward=True),
    ]


_FORMS = {
    "xor": _xor_forms(),
    "add": _add_forms(),
    "rot": _rot_forms(),
    "perm": _perm_forms(),
    "sbox": _sbox_forms(),
}

# The grammar in opchain and the realisations here must agree.
for _kind, _n in OP_FORM_COUNTS.items():
    if len(_FORMS[_kind]) != _n:  # pragma: no cover - guarded by test_emit_forms
        raise AssertionError(
            "emit has {0} forms for {1}, opchain expects {2}".format(len(_FORMS[_kind]), _kind, _n)
        )


def _kind_of(op: Op) -> str:
    return {XorKey: "xor", AddKey: "add", Rotate: "rot", PermPos: "perm", Sbox: "sbox"}[type(op)]


def _emit_op(op: Op, idx: int, length: int) -> list[str]:
    """C++ statements applying one op (decode direction) to buffer ``b[length]``."""
    kind = _kind_of(op)
    forms = _FORMS[kind]
    return forms[op.form % len(forms)](op, idx, length)


def emit_decode_fn(name: str, plain: bytes, chain: list[Op], load_form: int = 0) -> str:
    """A static C++ function ``void <name>(uint8_t out[L])`` that yields ``plain``.

    The embedded bytes are the encoded form; the body runs the chain to decode.
    ``load_form`` picks the shape of the copy that loads the encoded bytes into the
    working buffer, so two builds do not share that loop either.
    """
    length = len(plain)
    stored = encode_value(plain, chain)
    out: list[str] = []
    out.append("static void {0}(uint8_t out[{1}]) {{".format(name, length))
    out.append(_vol_array("enc", stored))
    out.append("\tuint8_t b[{0}];".format(length))
    load = _ELEMENTWISE_SHAPES[load_form % len(_ELEMENTWISE_SHAPES)]
    out.extend(load(length, lambda ix: "b[{0}] = enc[{0}];".format(ix)))
    for idx, op in enumerate(chain):
        out.extend(_emit_op(op, idx, length))
    out.append("\tfor (int i = 0; i < {0}; i++) out[i] = b[i];".format(length))
    out.append("}")
    return "\n".join(out)

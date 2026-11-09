#!/bin/sh
# Clone a pinned Godot tag, apply the FortressGD series, copy dialect.gen.h, build templates.
# The project secret never enters this container. The host passes the generated
# dialect.gen.h (masked pack key and public values only) and FGD_SECRET_HASH, the
# public 16-hex id used in the template name.
set -eu

err() {
    echo "error: $1" >&2
    echo "Run: fortressgd templates build" >&2
    exit 3
}

GODOT_VERSION="${GODOT_VERSION:-4.6.2-stable}"
FGD_GODOT="${FGD_GODOT:-4.6.2}"
FGD_PLATFORM="${FGD_PLATFORM:-linux}"
FGD_ARCH="${FGD_ARCH:-x86_64}"
SECRET_HASH="${FGD_SECRET_HASH:-}"
PATCHES_DIR="${PATCHES_DIR:-/patches}"
HEADER_SRC="${DIALECT_HEADER:-/src/dialect.gen.h}"
OUT_DIR="${OUT_DIR:-/out}"
SKIP_SCONS="${FORTRESSGD_SKIP_SCONS:-0}"
GODOT_SRC="${GODOT_SRC:-/work/godot}"
FGD_DIALECT="${FGD_DIALECT:-1}"
# 1 when [production].sign_packs is true: dialect.gen.h sets FGD_REQUIRE_PACK_SIGNATURE,
# the template refuses unsigned packs, and its name gets the -sig suffix.
FGD_REQUIRE_SIGNATURE="${FGD_REQUIRE_SIGNATURE:-0}"
FGD_CCFLAGS="-DFORTRESSGD_OPCODE_MAP -DFORTRESSGD_NAMELESS -DFORTRESSGD_SIGN_PACKS"
if [ "$FGD_DIALECT" = "1" ]; then
    FGD_CCFLAGS="$FGD_CCFLAGS -DFORTRESSGD_DIALECT"
fi

printf '%s\n' "$SECRET_HASH" | grep -Eq '^[0-9a-f]{16}$' || err "FGD_SECRET_HASH must be the 16-hex secret_hash"
[ -d "$PATCHES_DIR" ] || err "patches directory missing at $PATCHES_DIR"
[ -f "$HEADER_SRC" ] || err "dialect.gen.h missing at $HEADER_SRC"
mkdir -p "$OUT_DIR"

SERIES_FILES="$(grep -v '^[[:space:]]*#' "$PATCHES_DIR/series" 2>/dev/null | grep -v '^[[:space:]]*$' || true)"
[ -n "$SERIES_FILES" ] || err "patches series is empty ($PATCHES_DIR/series)"

# shellcheck disable=SC2086
set -- $SERIES_FILES
for patch in "$@"; do
    [ -f "$PATCHES_DIR/$patch" ] || err "series lists missing patch file: $patch"
done

# Patchset id from the mounted patches; the host's value is cross-checked below.
PATCHSET_ID="$(python3 - "$PATCHES_DIR" <<'PY'
import hashlib, pathlib, sys
patches = pathlib.Path(sys.argv[1])
names = []
for line in (patches / "series").read_text(encoding="utf-8").splitlines():
    name = line.split("#", 1)[0].strip()
    if name:
        names.append(name)
blob = b"".join((patches / n).read_bytes() for n in names)
print(hashlib.sha256(blob).hexdigest()[:12])
PY
)"
[ -n "$PATCHSET_ID" ] || err "failed to compute patchset_id"

if [ -n "${FGD_PATCHSET:-}" ] && [ "$FGD_PATCHSET" != "$PATCHSET_ID" ]; then
    err "patchset_id mismatch (host $FGD_PATCHSET vs computed $PATCHSET_ID)"
fi

NAME="godot-${FGD_GODOT}-template_release-${FGD_PLATFORM}-${FGD_ARCH}-fgd${PATCHSET_ID}-${SECRET_HASH}"
if [ "$FGD_REQUIRE_SIGNATURE" = "1" ]; then
    NAME="${NAME}-sig"
    grep -q "FGD_REQUIRE_PACK_SIGNATURE = 1;" "$HEADER_SRC" || err "FGD_REQUIRE_SIGNATURE=1 but dialect.gen.h does not require signatures"
fi
DIALECT_ID="${FGD_DIALECT_ID:-}"

clone_godot() {
    if [ -d "$GODOT_SRC/.git" ]; then
        return 0
    fi
    git clone --depth 1 --branch "$GODOT_VERSION" https://github.com/godotengine/godot.git "$GODOT_SRC" \
        || err "git clone of Godot $GODOT_VERSION failed"
}

apply_series() {
    cd "$GODOT_SRC"
    for patch in "$@"; do
        git apply --check "$PATCHES_DIR/$patch" || err "git apply --check failed for $patch"
        git apply "$PATCHES_DIR/$patch" || err "git apply failed for $patch"
    done
    cp "$HEADER_SRC" "$GODOT_SRC/core/dialect.gen.h"
    [ -f "$GODOT_SRC/core/fortressgd_kdf.cpp" ] || err "patched sources missing fortressgd_kdf.cpp"
    [ -f "$GODOT_SRC/core/dialect.gen.h" ] || err "dialect.gen.h was not installed"
}

write_manifest() {
    python3 - "$OUT_DIR/$NAME.manifest.json" "$FGD_GODOT" "$PATCHSET_ID" "$SECRET_HASH" "$FGD_PLATFORM" "$FGD_ARCH" "$DIALECT_ID" "$SKIP_SCONS" "$FGD_REQUIRE_SIGNATURE" <<'PY'
import json, sys
path, godot, patchset, secrethash, platform, arch, dialect, skip, require_sig = sys.argv[1:10]
data = {
    "godot": godot,
    "patchset_id": patchset,
    "secret_hash": secrethash,
    "kdf": "FGD-KDF-1",
    "dialect_id": dialect,
    "platform": platform,
    "arch": arch,
    "require_signature": require_sig == "1",
}
if skip == "1":
    data["skip_scons"] = "1"
text = json.dumps(data, indent=2, sort_keys=True) + "\n"
lower = text.lower()
if '"aes_key"' in lower or '"secret"' in lower:
    raise SystemExit("refusing to write secret or aes_key into manifest.json")
open(path, "w", encoding="utf-8").write(text)
PY
    cp "$OUT_DIR/$NAME.manifest.json" "$OUT_DIR/manifest.json"
}

clone_godot
# shellcheck disable=SC2086
set -- $SERIES_FILES
apply_series "$@"

if [ "$SKIP_SCONS" = "1" ]; then
    : > "$OUT_DIR/$NAME"
    write_manifest
    echo "ok: skip-scons $NAME"
    exit 0
fi

cd "$GODOT_SRC"
JOBS="$(nproc 2>/dev/null || echo 2)"
# Do not set SCRIPT_AES256_ENCRYPTION_KEY — that would bake a KeyDot-extractable blob.
if [ "$FGD_PLATFORM" = "linux" ]; then
    scons platform=linuxbsd target=template_release production=yes debug_symbols=no arch="$FGD_ARCH" \
        CCFLAGS="$FGD_CCFLAGS" -j"$JOBS" \
        || err "scons linuxbsd template_release failed"
    BIN="$(ls -1 bin/godot.linuxbsd.template_release* 2>/dev/null | head -n 1 || true)"
elif [ "$FGD_PLATFORM" = "windows" ]; then
    scons platform=windows target=template_release production=yes debug_symbols=no arch="$FGD_ARCH" use_mingw=yes \
        CCFLAGS="$FGD_CCFLAGS" -j"$JOBS" \
        || err "scons windows template_release (mingw) failed. See docs/ci.md for the manual Windows job."
    BIN="$(ls -1 bin/godot.windows.template_release* 2>/dev/null | head -n 1 || true)"
else
    err "unsupported platform $FGD_PLATFORM"
fi
[ -n "${BIN:-}" ] && [ -f "$BIN" ] || err "scons did not emit a template_release binary"

if command -v strip >/dev/null 2>&1 && [ "$FGD_PLATFORM" = "linux" ]; then
    strip --strip-unneeded "$BIN" || true
fi
cp "$BIN" "$OUT_DIR/$NAME"
write_manifest
echo "ok: $NAME"

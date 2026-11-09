#!/bin/sh
# Third-party libraries Godot 4.6.2's own CI links into its release templates
# (.github/workflows/windows_builds.yml and linux_builds.yml at 4.6.2-stable),
# so FortressGD templates support the same features as the official ones:
#   all platforms: AccessKit (screen readers), statically linked
#   windows:       Direct3D 12 (Mesa NIR, Agility SDK) and ANGLE (OpenGL on D3D11)
# Usage, from the Godot source tree: sh build-deps.sh <linux|windows>
# Prints the extra SCons arguments on stdout; progress goes to stderr. Any failed
# download fails the build: a template silently missing a renderer is worse
# than no template. This file is part of the patchset id, so changing it
# rebuilds templates.
set -eu
platform="$1"
deps="$PWD/bin/build_deps"
mkdir -p "$deps"

# fetch URL sha256:DIGEST DEST: download with retries and refuse a wrong digest.
fetch() {
    python3 - "$1" "$2" "$3" <<'PY'
import hashlib, sys, time, urllib.request
url, want, dest = sys.argv[1:4]
want = want.split("sha256:", 1)[-1]
for attempt in range(6):
    try:
        with urllib.request.urlopen(url, timeout=300) as resp:
            data = resp.read()
        break
    except Exception as exc:  # 5xx from GitHub Releases happens; back off and retry
        if attempt == 5:
            sys.exit("download failed: {0}: {1}".format(url, exc))
        time.sleep(2 ** attempt)
got = hashlib.sha256(data).hexdigest()
if got != want:
    sys.exit("sha256 mismatch for {0}: got {1}, want {2}".format(url, got, want))
open(dest, "wb").write(data)
PY
}

fetch "https://github.com/godotengine/godot-accesskit-c-static/releases/download/0.21.2/accesskit-c-0.21.2.zip" \
    sha256:02a08691b78fc6f8f88f6546e997b9f90b4ecbedf5ca5c621dbab144a4b18964 "$deps/accesskit_c.zip"
unzip -oq "$deps/accesskit_c.zip" -d "$deps"
flags="accesskit_sdk_path=$deps/accesskit-c-0.21.2/"

if [ "$platform" = "windows" ]; then
    # Godot's own script; it pins Mesa NIR, the Agility SDK and PIX for this tag
    # and installs them under bin/build_deps, where detect.py looks.
    python3 misc/scripts/install_d3d12_sdk_windows.py >&2
    fetch "https://github.com/godotengine/godot-angle-static/releases/download/chromium%2F6601.2/godot-angle-static-x86_64-gcc-release.zip" \
        sha256:bbf158906d8234615bfb1350dfd7d49a28f46daf0483fca89ff7981b0408333b "$deps/angle.zip"
    unzip -oq "$deps/angle.zip" -d "$deps/angle"
    flags="$flags d3d12=yes angle_libs=$deps/angle/"
fi
printf '%s\n' "$flags"

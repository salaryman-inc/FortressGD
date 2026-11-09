#!/bin/sh
# Third-party libraries Godot 4.7.2's own CI links into its release templates
# (.github/workflows/windows_builds.yml and linux_builds.yml at 4.7.2-stable),
# so FortressGD templates support the same features as the official ones:
#   all platforms: AccessKit (screen readers), statically linked
#   windows:       Direct3D 12, ANGLE (OpenGL on D3D11) and WinRT (OneCore TTS)
# Godot 4.7.2 ships an install script for each; they pin the versions for this
# tag and install under bin/build_deps, where detect.py looks by default.
# Usage, from the Godot source tree: sh build-deps.sh <linux|windows>
# Prints the extra SCons arguments on stdout; progress goes to stderr. A failed
# install fails the build: a template silently missing a renderer is worse than
# no template. This file is part of the patchset id.
set -eu
platform="$1"

python3 misc/scripts/install_accesskit.py >&2
flags="accesskit=yes"
if [ "$platform" = "windows" ]; then
    python3 misc/scripts/install_d3d12_sdk_windows.py >&2
    python3 misc/scripts/install_angle.py >&2
    python3 misc/scripts/install_winrt.py >&2
    flags="$flags d3d12=yes angle=yes winrt=yes"
fi
printf '%s\n' "$flags"

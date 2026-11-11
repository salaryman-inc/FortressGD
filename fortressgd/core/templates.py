"""Template naming, cache, Docker build (DESIGN.md §7)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from fortressgd.core.errors import NEXT_TEMPLATES, ToolError, UserError
from fortressgd.core.kdf import secret_hash
from fortressgd.core.patches import (
    patch_dir_for_tag,
    patchset_id,
    patchset_inputs,
    require_series,
    template_patchset_inputs,
)
from fortressgd.core.leakscan import format_leaks, redact, scan_paths, secret_needles
from fortressgd.core.paths import default_cache_dir, docker_dir, images_lock_path, patches_root
from fortressgd.core.secret import load_secret_hex, secret_bytes_from_hex
from fortressgd.core.version import concrete_godot_tag  # noqa: F401  (re-exported)
from fortressgd.generator.codeseed import CODEGEN_VERSION
from fortressgd.generator.dialect import dialect_material
from fortressgd.generator.generate import render_gen_cpp

KDF_NAME = "FGD-KDF-1"
SUPPORTED_PLATFORMS = ("linux", "windows")
DEFAULT_ARCH = "x86_64"
DOCKER_IMAGE_REPO = "fortressgd-templates"
# Files baked into the image. The tag is their hash, so an upgraded FortressGD
# never reuses an image built with an older entrypoint.
DOCKER_CONTEXT_FILES = ("Dockerfile.templates", "entrypoint.sh")


def docker_image() -> str:
    """fortressgd-templates:<sha256 of the Dockerfile and entrypoint, 12 hex>."""
    digest = hashlib.sha256()
    for name in DOCKER_CONTEXT_FILES:
        data = (docker_dir() / name).read_bytes()
        digest.update(name.encode("utf-8") + b"\0" + len(data).to_bytes(8, "big") + data)
    return "{0}:{1}".format(DOCKER_IMAGE_REPO, digest.hexdigest()[:12])
GODOT_STABLE_SUFFIX = "-stable"


def templates_cache_dir(cache_dir: str | Path | None = None) -> Path:
    """`{cache_dir}/templates` with cache_dir defaulting to ~/.cache/fortressgd."""
    base = Path(cache_dir).expanduser() if cache_dir else default_cache_dir()
    return base / "templates"


def editor_cache_home(binary: str | Path, cache_dir: str | Path | None = None) -> Path:
    """
    `{cache_dir}/editor-cache/<editor name>-<key>`: XDG_CACHE_HOME for one export editor.

    Godot names its class-doc cache by minor version only (editor_doc_cache-4.7.res)
    but checks it against a hash of the exact build. When two 4.7 builds share the
    cache, each rebuilds it on its next run, and on 4.7 that rebuild ends after a
    headless export has freed the editor, which then dies with SIGABRT (DESIGN.md
    §18.5). Each editor binary gets its own directory, so only one build ever writes
    it, and the user's own editor cache is left alone.

    The key covers the resolved path, size and mtime, so a binary rebuilt in place
    gets a fresh directory too.
    """
    path = Path(binary).expanduser()
    try:
        resolved = path.resolve()
        st = resolved.stat()
        identity = "{0}\0{1}\0{2}".format(resolved, st.st_size, st.st_mtime_ns)
    except OSError:
        identity = str(path)
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    base = Path(cache_dir).expanduser() if cache_dir else default_cache_dir()
    return base / "editor-cache" / "{0}-{1}".format(path.name, key)


SIGNATURE_SUFFIX = "-sig"
# Generator version in template names and the CI cache key (DESIGN.md §18.4): a
# template from one generator never reuses another generator's cache entry.
GENERATOR_SUFFIX = "-g{0}".format(CODEGEN_VERSION)


def template_filename(
    godot: str,
    platform: str,
    arch: str,
    patchset: str,
    secrethash: str,
    *,
    require_signature: bool = False,
    key_epoch: int = 0,
) -> str:
    """godot-<ver>-template_release-<platform>-<arch>-fgd<patchset12>-<secrethash16>-g<G>[-e<N>][-sig]

    -g<G> is the generator version (CODEGEN_VERSION), so templates from different
    generators never share a name or a cache entry.

    -e<N> marks a template whose pack key comes from [production].key_epoch N
    (absent for epoch 0). The -sig variant refuses packs without a valid index
    signature (sign_packs).
    """
    return "godot-{0}-template_release-{1}-{2}-fgd{3}-{4}{5}{6}{7}".format(
        godot,
        platform,
        arch,
        patchset,
        secrethash,
        GENERATOR_SUFFIX,
        "-e{0}".format(key_epoch) if key_epoch else "",
        SIGNATURE_SUFFIX if require_signature else "",
    )


EDITOR_PLATFORM = "linux"
EDITOR_HEADER_NAME = "fortressgd_editor_dialect.h"


def editor_header_path(patches_dir: Path | None = None) -> Path:
    """The fixed dialect.gen.h of the shared export editor (DESIGN.md §18.5)."""
    root = patches_root() if patches_dir is None else Path(patches_dir)
    return root / "common" / EDITOR_HEADER_NAME


def editor_header_id(patches_dir: Path | None = None) -> str:
    """8 hex of the editor header's sha256; entrypoint.sh computes the same."""
    return hashlib.sha256(editor_header_path(patches_dir).read_bytes()).hexdigest()[:8]


def editor_filename(godot: str, arch: str, patchset: str, header_id: str) -> str:
    """godot-<ver>-editor-linux-<arch>-fgd<patchset12>-p<header8>

    The shared FortressGD export editor for one Godot tag. It holds nothing
    project-specific: `fortressgd export` passes the dialect in
    FORTRESSGD_PACK_PARAMS. It runs on the export machine only and is never
    shipped. The header id is in the name because the patchset id does not cover
    the editor header.
    """
    return "godot-{0}-editor-{1}-{2}-fgd{3}-p{4}".format(godot, EDITOR_PLATFORM, arch, patchset, header_id)


def editor_build_command(godot: str) -> str:
    return "fortressgd templates build --editor --godot {0}".format(godot)


def find_cached_editor(
    *,
    godot: str,
    arch: str = DEFAULT_ARCH,
    cache_dir: str | Path | None = None,
    patches_dir: Path | None = None,
) -> Path | None:
    """The cached shared editor for this tag and FortressGD version, if built."""
    tag = concrete_godot_tag(godot)
    name = editor_filename(tag, arch, editor_patchset_for_tag(tag, patches_dir), editor_header_id(patches_dir))
    path = templates_cache_dir(cache_dir) / name
    return path if path.is_file() else None


def read_manifest(binary: Path) -> dict[str, Any]:
    """The manifest cached next to a template or editor binary, or {} when missing."""
    path = Path(str(binary) + ".manifest.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def require_dialect_match(binary: Path, dialect: bool, godot: str, platform: str) -> None:
    """Refuse a cached template or editor built for the other [production].dialect.

    A dialect template cannot open a stock pack and a stock template cannot open a
    dialect pack, and the template name does not say which it is: the manifest does.
    """
    recorded = read_manifest(binary).get("dialect_enabled")
    if recorded is None or bool(recorded) != bool(dialect):
        raise UserError(
            "{0} was built with dialect = {1}, but .fortressgd.toml has dialect = {2}; "
            "the game could not open its own pack".format(
                Path(binary).name,
                "unknown" if recorded is None else str(bool(recorded)).lower(),
                str(bool(dialect)).lower(),
            ),
            templates_build_command(godot, platform) + " --force",
        )


def templates_build_command(godot: str, platform: str) -> str:
    # key_epoch and sign_packs come from .fortressgd.toml, so the plain command
    # builds the variant the project needs.
    return "fortressgd templates build --godot {0} --platform {1}".format(godot, platform)


def missing_template_error(godot: str, secrethash: str, platform: str, key_epoch: int = 0) -> UserError:
    return UserError(
        "missing templates for godot={0} secret_hash={1} platform={2}{3}".format(
            godot, secrethash, platform, " key_epoch={0}".format(key_epoch) if key_epoch else ""
        ),
        templates_build_command(godot, platform),
    )


def find_cached_template(
    *,
    godot: str,
    platform: str,
    arch: str = DEFAULT_ARCH,
    patchset: str,
    secrethash: str,
    cache_dir: str | Path | None = None,
    require_signature: bool = False,
    key_epoch: int = 0,
) -> Path | None:
    name = template_filename(
        godot, platform, arch, patchset, secrethash, require_signature=require_signature, key_epoch=key_epoch
    )
    path = templates_cache_dir(cache_dir) / name
    if path.is_file():
        return path
    return None


def list_cached_templates(cache_dir: str | Path | None = None) -> list[str]:
    directory = templates_cache_dir(cache_dir)
    if not directory.is_dir():
        return []
    names = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name.startswith("godot-") and ".manifest." not in path.name:
            names.append(path.name)
    return names


def manifest_dict(
    *,
    godot: str,
    patchset: str,
    secrethash: str,
    dialect: str,
    platform: str,
    arch: str = DEFAULT_ARCH,
    require_signature: bool = False,
    key_epoch: int = 0,
    dialect_enabled: bool = True,
    target: str = "template_release",
) -> dict[str, Any]:
    return {
        "godot": godot,
        "patchset_id": patchset,
        "secret_hash": secrethash,
        "kdf": KDF_NAME,
        "dialect_id": dialect,
        "platform": platform,
        "arch": arch,
        "generator_version": str(CODEGEN_VERSION),
        "require_signature": bool(require_signature),
        "key_epoch": int(key_epoch),
        "dialect_enabled": bool(dialect_enabled),
        "target": target,
    }


def write_manifest(path: Path, data: dict[str, Any]) -> None:
    if "secret" in {k.lower() for k in data} or "aes_key" in {k.lower() for k in data}:
        raise ToolError("refusing to write secret or aes_key into manifest.json", NEXT_TEMPLATES)
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    lower = text.lower()
    if '"aes_key"' in lower or '"secret"' in lower:
        raise ToolError("refusing to write secret or aes_key into manifest.json", NEXT_TEMPLATES)
    path.write_text(text, encoding="utf-8")


def normalize_platform(platform: str) -> str:
    value = platform.strip().lower()
    if value in SUPPORTED_PLATFORMS:
        return value
    raise UserError(
        "unsupported template platform {0} (supported: {1})".format(
            platform, ", ".join(SUPPORTED_PLATFORMS)
        ),
        NEXT_TEMPLATES,
    )


def patchset_for_tag(godot: str, patches_dir: Path | None = None) -> str:
    """The patchset id in template names: series patches, build-deps.sh and the
    template's fixed common files."""
    tag = concrete_godot_tag(godot)
    root = patches_root() if patches_dir is None else Path(patches_dir)
    return patchset_id(template_patchset_inputs(patch_dir_for_tag(tag, root)))


def editor_patchset_for_tag(godot: str, patches_dir: Path | None = None) -> str:
    """The patchset id in the shared editor's name: series patches and build-deps.sh."""
    tag = concrete_godot_tag(godot)
    root = patches_root() if patches_dir is None else Path(patches_dir)
    return patchset_id(patchset_inputs(patch_dir_for_tag(tag, root)))


def godot_git_tag(version: str) -> str:
    tag = concrete_godot_tag(version)
    if tag.endswith("-stable"):
        return tag
    return tag + GODOT_STABLE_SUFFIX


def resolve_cache_dir_from_config(cfg: dict[str, Any] | None) -> Path:
    if cfg:
        templates = cfg.get("templates") or {}
        raw = templates.get("cache_dir")
        if isinstance(raw, str) and raw.strip():
            return Path(raw).expanduser()
    return default_cache_dir()


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def ensure_docker_image() -> None:
    dockerfile = docker_dir() / "Dockerfile.templates"
    if not dockerfile.is_file():
        raise ToolError("missing {0}".format(dockerfile.as_posix()), NEXT_TEMPLATES)
    if not _docker_available():
        raise ToolError(
            "docker is required to build templates",
            "install Docker, then: fortressgd templates build",
        )
    inspect = subprocess.run(
        ["docker", "image", "inspect", docker_image()],
        capture_output=True,
        text=True,
    )
    if inspect.returncode == 0:
        return
    # Stream the build (stdout to our stderr) so a slow package mirror shows in
    # the log instead of as minutes of silence.
    print("fortressgd: building {0} (the build toolchain)".format(docker_image()), file=sys.stderr, flush=True)
    built = subprocess.run(
        ["docker", "build", "--progress=plain", "-f", str(dockerfile), "-t", docker_image(), str(docker_dir())],
        stdout=2,
    )
    if built.returncode != 0:
        raise ToolError("docker build of {0} failed (log above)".format(docker_image()), NEXT_TEMPLATES)


BUILD_IMAGE_REPO = "fortressgd-build"
# SCons lto= for build images and their relinks (DESIGN.md §18.4). "" keeps Godot's
# production default: full LTO with GCC and MinGW.
TEMPLATE_LTO = ""


def build_image_tag(
    tag: str,
    platform: str,
    arch: str,
    patchset: str,
    *,
    lto: str = TEMPLATE_LTO,
    patches_dir: Path | None = None,
) -> str:
    """fortressgd-build:godot<tag>-<platform>-<arch>-fgd<patchset>-<inputs8>.

    inputs8 hashes what the image holds besides the patched source: the template
    image (Dockerfile.templates and the entrypoint), Dockerfile.build, the placeholder
    the tree is compiled against, and the LTO mode. A locally built image whose
    inputs changed gets a new tag instead of being reused.
    """
    root = patches_root() if patches_dir is None else Path(patches_dir)
    digest = hashlib.sha256()
    for part in (
        docker_image().encode("utf-8"),
        (docker_dir() / "Dockerfile.build").read_bytes(),
        (root / "common" / "fortressgd_gen_placeholder.cpp").read_bytes(),
        lto.encode("utf-8"),
    ):
        digest.update(len(part).to_bytes(8, "big") + part)
    return "{0}:godot{1}-{2}-{3}-fgd{4}-{5}".format(
        BUILD_IMAGE_REPO, tag, platform, arch, patchset, digest.hexdigest()[:8]
    )


def _build_image_inputs(
    tag: str, platform: str, arch: str, root: Path, lto: str
) -> tuple[Path, str, str]:
    """(tag dir, template patchset id, local build image tag) for these inputs."""
    tag_dir = patch_dir_for_tag(tag, root)
    require_series(tag_dir)
    pset = patchset_id(template_patchset_inputs(tag_dir))
    return tag_dir, pset, build_image_tag(tag, platform, arch, pset, lto=lto, patches_dir=root)


def build_build_image(
    tag: str,
    platform: str,
    *,
    arch: str = DEFAULT_ARCH,
    patches_dir: Path | None = None,
    lto: str = TEMPLATE_LTO,
    extra_tags: tuple[str, ...] = (),
    labels: dict[str, str] | None = None,
) -> str:
    """docker build the build image (DESIGN.md §18.4); returns its local tag.

    The release workflow adds its registry tags and OCI labels through extra_tags
    and labels; `templates build` uses neither.
    """
    root = patches_root() if patches_dir is None else Path(patches_dir)
    tag_dir, pset, image = _build_image_inputs(tag, platform, arch, root, lto)
    ensure_docker_image()
    print(
        "fortressgd: building {0}; this compiles Godot once, later template builds relink".format(image),
        file=sys.stderr,
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="fortressgd-build-image-") as tmp:
        ctx = Path(tmp)
        shutil.copy2(docker_dir() / "Dockerfile.build", ctx / "Dockerfile.build")
        shutil.copytree(tag_dir, ctx / "patches")
        shutil.copytree(root / "common", ctx / "common")
        args = {
            "BASE_IMAGE": docker_image(),
            "GODOT_VERSION": godot_git_tag(tag),
            "FGD_GODOT": tag,
            "FGD_PLATFORM": platform,
            "FGD_ARCH": arch,
            "FGD_LTO": lto,
            "FGD_PATCHSET": pset,
        }
        cmd = ["docker", "build", "--progress=plain", "-f", str(ctx / "Dockerfile.build"), "-t", image]
        for extra in extra_tags:
            cmd += ["-t", extra]
        for key, value in args.items():
            cmd += ["--build-arg", "{0}={1}".format(key, value)]
        for key, value in sorted((labels or {}).items()):
            cmd += ["--label", "{0}={1}".format(key, value)]
        cmd.append(str(ctx))
        # The compile takes a while; stream it (stdout to our stderr) rather than
        # sit silent.
        built = subprocess.run(cmd, stdout=2)
    if built.returncode != 0:
        raise ToolError(
            "building the {0} build image failed (log above)".format(image),
            templates_build_command(tag, platform),
        )
    return image


def ensure_build_image(
    tag: str,
    platform: str,
    *,
    arch: str = DEFAULT_ARCH,
    patches_dir: Path | None = None,
    lto: str = TEMPLATE_LTO,
) -> str:
    """The locally built build image for this tag, platform and arch, built if Docker lacks it.

    Building it compiles Godot once (DESIGN.md §18.4); later template builds for any
    project relink against it. The image holds no secret: the tree is compiled
    against the trapping placeholder fortressgd_gen.cpp.
    """
    root = patches_root() if patches_dir is None else Path(patches_dir)
    _tag_dir, _pset, image = _build_image_inputs(tag, platform, arch, root, lto)
    inspect = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    if inspect.returncode == 0:
        return image
    return build_build_image(tag, platform, arch=arch, patches_dir=root, lto=lto)


# images.lock.json (DESIGN.md §18.4): the release workflow writes it into the
# wheel and sdist of each release. A source checkout has none.
IMAGE_LOCK_SCHEMA = 1
_DIGEST_REF = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")


def load_image_pins(path: Path | None = None) -> list[dict[str, str]]:
    """The pinned build images this CLI release ships with; [] when it has none."""
    lock = images_lock_path() if path is None else Path(path)
    if not lock.is_file():
        return []
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ToolError(
            "{0} is unreadable: {1}".format(lock.name, exc),
            "reinstall FortressGD from its release, then: fortressgd doctor",
        )
    images = data.get("images") if isinstance(data, dict) else None
    if not isinstance(data, dict) or data.get("schema") != IMAGE_LOCK_SCHEMA or not isinstance(images, list):
        raise ToolError(
            "{0} is not a schema {1} image lock".format(lock.name, IMAGE_LOCK_SCHEMA),
            "reinstall FortressGD from its release, then: fortressgd doctor",
        )
    pins = []
    for entry in images:
        fields = ("godot", "platform", "arch", "tag", "ref")
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in fields):
            raise ToolError(
                "{0} has a malformed entry".format(lock.name),
                "reinstall FortressGD from its release, then: fortressgd doctor",
            )
        if not _DIGEST_REF.match(entry["ref"]):
            raise ToolError(
                "{0} pins {1}, which is not a <repository>@sha256:<digest> reference".format(lock.name, entry["ref"]),
                "reinstall FortressGD from its release, then: fortressgd doctor",
            )
        pins.append({k: entry[k] for k in fields})
    return pins


def pinned_build_image(tag: str, platform: str, arch: str = DEFAULT_ARCH, pins: list[dict[str, str]] | None = None) -> dict[str, str] | None:
    for pin in load_image_pins() if pins is None else pins:
        if (pin["godot"], pin["platform"], pin["arch"]) == (tag, platform, arch):
            return pin
    return None


def _image_present(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True, text=True).returncode == 0


def _pull_image(ref: str, tag: str, platform: str) -> None:
    print("fortressgd: pulling {0}".format(ref), file=sys.stderr, flush=True)
    pulled = subprocess.run(["docker", "pull", ref], stdout=2)
    if pulled.returncode != 0:
        raise ToolError(
            "could not pull {0} (log above)".format(ref),
            "check your network and registry access, or compile it here: "
            + templates_build_command(tag, platform) + " --from-source",
        )


def resolve_build_image(
    tag: str,
    platform: str,
    *,
    arch: str = DEFAULT_ARCH,
    patches_dir: Path | None = None,
    lto: str = TEMPLATE_LTO,
    image: str | None = None,
) -> str:
    """The build image a relink runs in (DESIGN.md §18.4).

    1. image (--image): used as given, pulled if Docker lacks it. The relink still
       checks the image's recorded patchset, tag, platform and LTO mode.
    2. The image pinned by digest in this release's images.lock.json, pulled by
       that digest. Docker verifies the content against it, so no other image
       can stand in for it.
    3. No pin (a source checkout, or --patches-dir): built locally.
    """
    if image:
        if not _image_present(image):
            _pull_image(image, tag, platform)
        print("fortressgd: using --image {0} instead of a pinned build image".format(image), file=sys.stderr)
        return image
    if patches_dir is not None:
        return ensure_build_image(tag, platform, arch=arch, patches_dir=patches_dir, lto=lto)
    pin = pinned_build_image(tag, platform, arch)
    if pin is None:
        return ensure_build_image(tag, platform, arch=arch, lto=lto)
    _tag_dir, _pset, expected = _build_image_inputs(tag, platform, arch, patches_root(), lto)
    if pin["tag"] != expected:
        raise ToolError(
            "the pinned {0} {1} build image was built from other inputs ({2}) than this "
            "install's patches and Docker files ({3})".format(tag, platform, pin["tag"], expected),
            "reinstall FortressGD from its release, or compile it here: "
            + templates_build_command(tag, platform) + " --from-source",
        )
    if not _image_present(pin["ref"]):
        _pull_image(pin["ref"], tag, platform)
    return pin["ref"]


def build_image_status(tag: str, platforms: list[str], arch: str = DEFAULT_ARCH) -> list[str]:
    """doctor lines: is each platform's pinned build image pinned and pulled?"""
    try:
        pins = load_image_pins()
    except ToolError as exc:
        return ["warning: {0}\nRun: {1}".format(exc, exc.next_command)]
    if not pins:
        return [
            "note: this install pins no build images (a source checkout); "
            "templates build compiles them locally the first time"
        ]
    docker = _docker_available()
    lines = []
    for platform in platforms:
        pin = pinned_build_image(tag, platform, arch, pins)
        if pin is None:
            lines.append("warning: no pinned build image for godot {0} {1}".format(tag, platform))
        elif docker and _image_present(pin["ref"]):
            lines.append("ok: pinned build image for {0} {1} is pulled ({2})".format(tag, platform, pin["ref"]))
        else:
            lines.append(
                "note: pinned build image for {0} {1} is not pulled yet; templates build pulls {2}".format(
                    tag, platform, pin["ref"]
                )
            )
    return lines


def build_templates(
    *,
    godot: str,
    platforms: list[str],
    secret_file: str | None = None,
    environ: dict[str, str] | None = None,
    cwd: Path | None = None,
    cache_dir: str | Path | None = None,
    patches_dir: Path | None = None,
    skip_scons: bool = False,
    dialect: bool = True,
    require_signature: bool = False,
    key_epoch: int = 0,
    from_source: bool = False,
    image: str | None = None,
) -> list[Path]:
    """
    Generate fortressgd_gen.cpp, build each platform's template in Docker, scan the
    result and copy it into the cache. Returns cached template paths.

    By default the template is relinked in a build image holding a precompiled Godot
    tree (DESIGN.md §18.4): `image` if given, else the one this release pins by
    digest, else one built locally the first time. from_source=True, or dialect off,
    compiles everything in a fresh container instead.
    """
    env = os.environ if environ is None else environ
    hex_secret = load_secret_hex(secret_file=secret_file, environ=env, cwd=cwd)
    secret = secret_bytes_from_hex(hex_secret)
    tag = concrete_godot_tag(godot)
    secrethash = secret_hash(secret)
    plats = [normalize_platform(p) for p in platforms]
    if not plats:
        raise UserError("no platforms to build", NEXT_TEMPLATES)
    if image and (from_source or not dialect):
        raise UserError(
            "--image is a build image to relink in; it cannot be used with --from-source or dialect = false",
            templates_build_command(tag, plats[0]),
        )
    if image and len(plats) != 1:
        raise UserError(
            "--image is one platform's build image; build one --platform at a time with it",
            templates_build_command(tag, plats[0]) + " --image " + image,
        )

    root = patches_root() if patches_dir is None else Path(patches_dir)
    tag_dir = patch_dir_for_tag(tag, root)
    require_series(tag_dir)
    pset = patchset_id(template_patchset_inputs(tag_dir))

    _salt, _masks, _shards, did = dialect_material(secret, tag, key_epoch=key_epoch)
    needles = secret_needles(secret, tag, key_epoch=key_epoch)

    dest_root = templates_cache_dir(cache_dir)
    dest_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="fortressgd-tmpl-") as tmp:
        tmp_path = Path(tmp)
        gen_cpp = tmp_path / "fortressgd_gen.cpp"
        # Generator v2 (DESIGN.md §18.3): a separate translation unit that decodes
        # the pack key and the public dialect values at runtime. The container
        # also gets the fixed common/ headers; Godot's own objects include only
        # the fixed shim header, so a new project recompiles just this file
        # (§18.4). The project secret is never written here or passed to the
        # container, and the raw key never appears in the file. require_signature
        # is a compile-time flag (FGD_REQUIRE_SIGNATURE), not a value in the file.
        gen_cpp.write_text(render_gen_cpp(secret, tag, key_epoch=key_epoch), encoding="utf-8")
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        skip = skip_scons or env.get("FORTRESSGD_SKIP_SCONS") == "1"
        # Skip-scons is a test path through the source build; a build image needs a
        # real compile.
        use_image = not from_source and dialect and not skip
        if not from_source and not dialect:
            print("fortressgd: dialect is off; building templates from source", file=sys.stderr)
        if not _docker_available():
            raise ToolError(
                "docker is required to build templates",
                "install Docker, then: fortressgd templates build",
            )
        if not use_image:
            ensure_docker_image()
        produced = []
        for platform in plats:
            build_image = (
                resolve_build_image(tag, platform, patches_dir=patches_dir, image=image) if use_image else None
            )
            run = _run_build_container(
                {
                    "GODOT_VERSION": godot_git_tag(tag),
                    "FGD_GODOT": tag,
                    "FGD_PLATFORM": platform,
                    "FGD_ARCH": DEFAULT_ARCH,
                    "FGD_DIALECT_ID": did,
                    "FGD_PATCHSET": pset,
                    "FGD_SECRET_HASH": secrethash,
                    "FGD_KEY_EPOCH": str(int(key_epoch)),
                    "FORTRESSGD_SKIP_SCONS": "1" if skip else "0",
                    "FGD_DIALECT": "1" if dialect else "0",
                    "FGD_REQUIRE_SIGNATURE": "1" if require_signature else "0",
                    "FGD_GENERATOR": str(CODEGEN_VERSION),
                    "FGD_MODE": "relink" if build_image else "source",
                },
                # A build image carries its own patches and common files.
                patches=None if build_image else tag_dir,
                gen_cpp=gen_cpp,
                common=None if build_image else root / "common",
                out_dir=out_dir,
                image=build_image,
            )
            if run.returncode != 0:
                detail = redact((run.stderr or run.stdout or "").strip(), needles)
                raise ToolError(
                    "template build failed for {0}: {1}".format(platform, detail),
                    templates_build_command(tag, platform),
                )
            name = template_filename(
                tag, platform, DEFAULT_ARCH, pset, secrethash,
                require_signature=require_signature, key_epoch=key_epoch,
            )
            src_bin = out_dir / name
            src_man = out_dir / (name + ".manifest.json")
            if not src_man.is_file():
                # entrypoint may write manifest.json next to the artifact
                alt = out_dir / "manifest.json"
                if alt.is_file():
                    src_man = alt
            if not src_man.is_file():
                raise ToolError(
                    "template build did not emit manifest.json for {0}".format(platform),
                    templates_build_command(tag, platform),
                )
            dest_bin = dest_root / name
            dest_man = dest_root / (name + ".manifest.json")
            if not src_bin.is_file():
                raise ToolError(
                    "template build did not emit {0}".format(name),
                    templates_build_command(tag, platform),
                )
            leaks = scan_paths([src_bin, src_man], needles)
            if leaks:
                raise ToolError(
                    "refusing to cache template output that contains secret material:\n"
                    + format_leaks(leaks),
                    templates_build_command(tag, platform),
                )
            shutil.copy2(src_bin, dest_bin)
            shutil.copy2(src_man, dest_man)
            _assert_manifest_safe(dest_man, secrethash, require_signature, key_epoch)
            produced.append(dest_bin)
        return produced


def _run_build_container(
    env: dict[str, str],
    *,
    patches: Path | None,
    out_dir: Path,
    header: Path | None = None,
    gen_cpp: Path | None = None,
    common: Path | None = None,
    image: str | None = None,
) -> subprocess.CompletedProcess:
    """Run entrypoint.sh in the build image with the inputs read-only.

    Editor builds pass the fixed ``header`` (installed as core/dialect.gen.h). Template
    builds pass the generated ``gen_cpp`` and the fixed ``common`` directory (the shim
    header, its source and the API header); the entrypoint installs them in core/.
    A relink passes the build ``image`` and only ``gen_cpp``: the image holds the
    patched tree, its patches and common files.
    """
    cmd = ["docker", "run", "--rm"]
    for key, value in env.items():
        cmd += ["-e", "{0}={1}".format(key, value)]
    if patches is not None:
        cmd += ["-v", "{0}:/patches:ro".format(patches)]
    if header is not None:
        cmd += ["-v", "{0}:/src/dialect.gen.h:ro".format(header)]
    if gen_cpp is not None:
        cmd += ["-v", "{0}:/src/fortressgd_gen.cpp:ro".format(gen_cpp)]
    if common is not None:
        cmd += ["-v", "{0}:/common:ro".format(common)]
    cmd += ["-v", "{0}:/out".format(out_dir), image or docker_image()]
    return subprocess.run(cmd, capture_output=True, text=True)


def build_editor(
    *,
    godot: str,
    environ: dict[str, str] | None = None,
    cache_dir: str | Path | None = None,
    patches_dir: Path | None = None,
    skip_scons: bool = False,
) -> Path:
    """
    Build the shared export editor for one Godot tag (DESIGN.md §18.5) and cache it.

    It needs no project secret: the container gets the fixed editor header, and
    `fortressgd export` passes each project's dialect at export time.
    """
    env = os.environ if environ is None else environ
    tag = concrete_godot_tag(godot)
    root = patches_root() if patches_dir is None else Path(patches_dir)
    tag_dir = patch_dir_for_tag(tag, root)
    require_series(tag_dir)
    pset = patchset_id(patchset_inputs(tag_dir))
    header = editor_header_path(root)
    if not header.is_file():
        raise ToolError("missing {0}".format(header.as_posix()), NEXT_TEMPLATES)
    name = editor_filename(tag, DEFAULT_ARCH, pset, editor_header_id(root))
    dest_root = templates_cache_dir(cache_dir)
    dest_root.mkdir(parents=True, exist_ok=True)
    skip = skip_scons or env.get("FORTRESSGD_SKIP_SCONS") == "1"
    ensure_docker_image()
    with tempfile.TemporaryDirectory(prefix="fortressgd-editor-") as tmp:
        out_dir = Path(tmp) / "out"
        out_dir.mkdir()
        run = _run_build_container(
            {
                "GODOT_VERSION": godot_git_tag(tag),
                "FGD_GODOT": tag,
                "FGD_PLATFORM": EDITOR_PLATFORM,
                "FGD_ARCH": DEFAULT_ARCH,
                "FGD_PATCHSET": pset,
                "FGD_TARGET": "editor",
                "FORTRESSGD_SKIP_SCONS": "1" if skip else "0",
            },
            patches=tag_dir,
            header=header,
            out_dir=out_dir,
        )
        if run.returncode != 0:
            raise ToolError(
                "editor build failed: {0}".format((run.stderr or run.stdout or "").strip()),
                editor_build_command(tag),
            )
        src_bin = out_dir / name
        src_man = out_dir / (name + ".manifest.json")
        if not src_bin.is_file() or not src_man.is_file():
            raise ToolError(
                "editor build did not emit {0} and its manifest".format(name), editor_build_command(tag)
            )
        manifest = json.loads(src_man.read_text(encoding="utf-8"))
        if manifest.get("target") != "editor" or manifest.get("patchset_id") != pset:
            raise ToolError("editor manifest does not match {0}".format(name), editor_build_command(tag))
        dest_bin = dest_root / name
        shutil.copy2(src_bin, dest_bin)
        shutil.copy2(src_man, dest_root / (name + ".manifest.json"))
        dest_bin.chmod(dest_bin.stat().st_mode | 0o111)
        return dest_bin


def _assert_manifest_safe(
    path: Path, secrethash: str, require_signature: bool = False, key_epoch: int = 0
) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("kdf") != KDF_NAME:
        raise ToolError("manifest kdf is not {0}".format(KDF_NAME), NEXT_TEMPLATES)
    if "aes_key" in data or "secret" in data:
        raise ToolError("manifest contains secret or aes_key", NEXT_TEMPLATES)
    if data.get("secret_hash") != secrethash:
        raise ToolError("manifest secret_hash mismatch", NEXT_TEMPLATES)
    if bool(data.get("require_signature", False)) != bool(require_signature):
        raise ToolError("manifest require_signature mismatch", NEXT_TEMPLATES)
    if int(data.get("key_epoch", 0)) != int(key_epoch):
        raise ToolError("manifest key_epoch mismatch", NEXT_TEMPLATES)

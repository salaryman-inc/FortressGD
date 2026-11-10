"""Release helpers for .github/workflows/release.yml (DESIGN.md §18.4).

Not part of the `fortressgd` command. The release workflow runs:

    python -m fortressgd.release check-version --tag v0.2.0
    python -m fortressgd.release build-image --godot 4.6.2 --platform linux \\
        --repository ghcr.io/<owner>/fortressgd-build --out entry.json
    python -m fortressgd.release write-lock --commit <sha> entry-*.json

write-lock writes fortressgd/images.lock.json, which the wheel and sdist built
next carry: that is how each CLI release pins its build images by digest.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from fortressgd.core.errors import ToolError, UserError
from fortressgd.core.paths import images_lock_path, package_root
from fortressgd.core.templates import (
    DEFAULT_ARCH,
    IMAGE_LOCK_SCHEMA,
    SUPPORTED_PLATFORMS,
    TEMPLATE_LTO,
    build_build_image,
    load_image_pins,
)
from fortressgd.core.version import SUPPORTED_GODOT, __version__

SOURCE_URL = "https://github.com/salaryman-inc/FortressGD"
_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._-]*(\.[a-z0-9-]+)*(/[a-z0-9._-]+)+$")


def check_version(tag: str) -> str:
    """The tag must be v<__version__>, and the editor plugin must say the same."""
    if tag != "v" + __version__:
        raise UserError(
            "tag {0} does not match the package version {1}".format(tag, __version__),
            "set __version__ in fortressgd/core/version.py and plugin.cfg, then tag v<version>",
        )
    cfg = (package_root() / "plugin" / "addons" / "fortressgd" / "plugin.cfg").read_text(encoding="utf-8")
    if 'version="{0}"'.format(__version__) not in cfg:
        raise UserError(
            "plugin.cfg does not say version {0}".format(__version__),
            "set version in fortressgd/plugin/addons/fortressgd/plugin.cfg",
        )
    return __version__


def _docker(args: list[str]) -> str:
    run = subprocess.run(["docker"] + args, capture_output=True, text=True)
    if run.returncode != 0:
        raise ToolError(
            "docker {0} failed: {1}".format(" ".join(args), (run.stderr or run.stdout).strip()),
            "re-run the release workflow",
        )
    return run.stdout


def build_and_push(godot: str, platform: str, repository: str, *, revision: str) -> dict[str, str]:
    """Build one build image, push it under two tags, and return its lock entry."""
    if not _REPOSITORY.match(repository):
        raise UserError("{0} is not a lowercase image repository".format(repository), "pass --repository ghcr.io/<owner>/fortressgd-build")
    if godot not in SUPPORTED_GODOT or platform not in SUPPORTED_PLATFORMS:
        raise UserError("unsupported godot {0} or platform {1}".format(godot, platform), "see SUPPORTED_GODOT")
    arch = DEFAULT_ARCH
    release_tag = "{0}:v{1}-godot{2}-{3}-{4}".format(repository, __version__, godot, platform, arch)
    # Two registry tags: the release tag for people browsing the registry, and the
    # content tag (the local tag's name, which hashes the image's inputs).
    local = build_build_image(
        godot,
        platform,
        arch=arch,
        lto=TEMPLATE_LTO,
        extra_tags=(release_tag,),
        labels={
            "org.opencontainers.image.source": SOURCE_URL,
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.version": __version__,
            "org.opencontainers.image.description": "FortressGD build image: Godot {0} {1} {2}, precompiled".format(
                godot, platform, arch
            ),
        },
    )
    content_tag = "{0}:{1}".format(repository, local.split(":", 1)[1])
    _docker(["tag", local, content_tag])
    for name in (content_tag, release_tag):
        push = subprocess.run(["docker", "push", name], stdout=2)
        if push.returncode != 0:
            raise ToolError("docker push {0} failed (log above)".format(name), "re-run the release workflow")
    digests = json.loads(_docker(["image", "inspect", "--format", "{{json .RepoDigests}}", local]) or "[]")
    refs = sorted({d for d in digests if d.startswith(repository + "@sha256:")})
    if len(refs) != 1:
        raise ToolError(
            "expected one {0} digest after the push, got {1}".format(repository, refs or "none"),
            "re-run the release workflow",
        )
    return {"godot": godot, "platform": platform, "arch": arch, "tag": local, "ref": refs[0]}


def write_lock(entries: list[dict[str, str]], *, commit: str, path: Path | None = None) -> Path:
    """Write images.lock.json: exactly one entry per supported tag and platform."""
    want = {(g, p, DEFAULT_ARCH) for g in SUPPORTED_GODOT for p in SUPPORTED_PLATFORMS}
    got = {}
    for entry in entries:
        key = (entry.get("godot"), entry.get("platform"), entry.get("arch"))
        if key in got:
            raise UserError("two build images for {0}".format(" ".join(map(str, key))), "re-run the release workflow")
        got[key] = entry
    if set(got) != want:
        missing = sorted(want - set(got))
        extra = sorted(set(got) - want, key=str)
        raise UserError(
            "the build images do not cover every supported tag and platform (missing {0}, extra {1})".format(
                missing or "none", extra or "none"
            ),
            "re-run the release workflow",
        )
    lock = images_lock_path() if path is None else Path(path)
    data = {
        "schema": IMAGE_LOCK_SCHEMA,
        "fortressgd": __version__,
        "commit": commit,
        "images": [got[k] for k in sorted(want)],
    }
    lock.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Read it back the way templates build will.
    if len(load_image_pins(lock)) != len(want):
        raise ToolError("{0} did not round-trip".format(lock), "re-run the release workflow")
    return lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fortressgd.release")
    sub = parser.add_subparsers(dest="command", required=True)
    cv = sub.add_parser("check-version")
    cv.add_argument("--tag", required=True)
    bi = sub.add_parser("build-image")
    bi.add_argument("--godot", required=True)
    bi.add_argument("--platform", required=True)
    bi.add_argument("--repository", required=True)
    bi.add_argument("--revision", required=True)
    bi.add_argument("--out", required=True)
    wl = sub.add_parser("write-lock")
    wl.add_argument("--commit", required=True)
    wl.add_argument("entries", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.command == "check-version":
            print(check_version(args.tag))
        elif args.command == "build-image":
            entry = build_and_push(args.godot, args.platform, args.repository, revision=args.revision)
            Path(args.out).write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(entry["ref"])
        else:
            entries = [json.loads(Path(p).read_text(encoding="utf-8")) for p in args.entries]
            print(write_lock(entries, commit=args.commit))
    except (UserError, ToolError) as exc:
        sys.stderr.write(exc.format() + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

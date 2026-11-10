"""Release pins (DESIGN.md §18.4): images.lock.json, pulling a pinned build image by
digest, --image, doctor's report and the release workflow's helpers.

docker is a recording fake: the real pull, push and attestation run in
.github/workflows/release.yml.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PKG = Path(__file__).resolve().parents[1] / "fortressgd"
DIGEST = "sha256:" + "ab" * 32

FAKE_DOCKER = """#!{python}
import json, os, sys
from pathlib import Path
sys.path.insert(0, {root!r})
from fortressgd.core.templates import manifest_dict, template_filename, write_manifest
args = sys.argv[1:]
with Path(os.environ["FAKE_DOCKER_LOG"]).open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")
have = Path(os.environ["FAKE_DOCKER_HAVE"])
key = lambda ref: have / ref.replace("/", "_").replace(":", "_").replace("@", "_")
if args[:2] == ["image", "inspect"]:
    if "--format" in args:
        print(json.dumps(os.environ.get("FAKE_REPO_DIGESTS", "").split()))
        sys.exit(0)
    ref = args[2]
    local = not ref.startswith("fortressgd-build:") and "@" not in ref and "/" not in ref
    sys.exit(0 if local or key(ref).exists() else 1)
if args[0] == "pull":
    if os.environ.get("FAKE_PULL_FAILS"):
        sys.exit(1)
    key(args[1]).write_text("pulled")
    sys.exit(0)
if args[0] in ("push", "tag"):
    sys.exit(0)
if args[0] == "build":
    for i, a in enumerate(args):
        if a == "-t":
            key(args[i + 1]).write_text("built")
    sys.exit(0)
env, vols, i = {{}}, {{}}, 1
while i < len(args) - 1:
    if args[i] in ("-e", "-v"):
        if args[i] == "-e":
            k, v = args[i + 1].split("=", 1)
            env[k] = v
        else:
            parts = args[i + 1].split(":")
            vols[parts[1]] = parts[0]
        i += 2
    else:
        i += 1
name = template_filename(env["FGD_GODOT"], env["FGD_PLATFORM"], env["FGD_ARCH"], env["FGD_PATCHSET"], env["FGD_SECRET_HASH"])
out = Path(vols["/out"])
(out / name).write_bytes(b"fake template")
write_manifest(out / (name + ".manifest.json"), manifest_dict(
    godot=env["FGD_GODOT"], patchset=env["FGD_PATCHSET"], secrethash=env["FGD_SECRET_HASH"],
    dialect=env["FGD_DIALECT_ID"], platform=env["FGD_PLATFORM"]))
"""


def _entries(ref_digest: str = DIGEST) -> list[dict[str, str]]:
    from fortressgd.core.templates import build_image_tag, patchset_for_tag

    return [
        {
            "godot": g,
            "platform": p,
            "arch": "x86_64",
            "tag": build_image_tag(g, p, "x86_64", patchset_for_tag(g)),
            "ref": "ghcr.io/example/fortressgd-build@" + ref_digest,
        }
        for g in ("4.6.2", "4.7.2")
        for p in ("linux", "windows")
    ]


class _Tmp(unittest.TestCase):
    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.tmp = Path(holder.name)


class LockTests(_Tmp):
    def test_write_lock_round_trips(self) -> None:
        from fortressgd.core.templates import load_image_pins, pinned_build_image
        from fortressgd.release import write_lock

        lock = write_lock(_entries(), commit="c0ffee", path=self.tmp / "images.lock.json")
        data = json.loads(lock.read_text())
        self.assertEqual(data["schema"], 1)
        self.assertEqual(data["commit"], "c0ffee")
        pins = load_image_pins(lock)
        self.assertEqual(len(pins), 4)
        pin = pinned_build_image("4.7.2", "windows", pins=pins)
        self.assertEqual(pin["ref"], "ghcr.io/example/fortressgd-build@" + DIGEST)

    def test_write_lock_needs_every_tag_and_platform_once(self) -> None:
        from fortressgd.core.errors import UserError
        from fortressgd.release import write_lock

        entries = _entries()
        with self.assertRaisesRegex(UserError, "missing"):
            write_lock(entries[:-1], commit="c", path=self.tmp / "a.json")
        with self.assertRaisesRegex(UserError, "two build images"):
            write_lock(entries + entries[:1], commit="c", path=self.tmp / "b.json")

    def test_load_refuses_a_tag_reference_or_another_schema(self) -> None:
        from fortressgd.core.errors import ToolError
        from fortressgd.core.templates import load_image_pins

        entries = _entries()
        entries[0]["ref"] = "ghcr.io/example/fortressgd-build:latest"
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"schema": 1, "images": entries}))
        with self.assertRaisesRegex(ToolError, "sha256"):
            load_image_pins(bad)
        bad.write_text(json.dumps({"schema": 2, "images": []}))
        with self.assertRaisesRegex(ToolError, "schema 1"):
            load_image_pins(bad)

    def test_a_source_checkout_pins_nothing(self) -> None:
        from fortressgd.core.paths import images_lock_path
        from fortressgd.core.templates import load_image_pins

        self.assertFalse(images_lock_path().exists(), "images.lock.json is written by the release workflow only")
        self.assertEqual(load_image_pins(), [])

    def test_check_version(self) -> None:
        from fortressgd.core.errors import UserError
        from fortressgd.core.version import __version__
        from fortressgd.release import check_version

        self.assertEqual(check_version("v" + __version__), __version__)
        with self.assertRaises(UserError):
            check_version("v99.0.0")
        with self.assertRaises(UserError):
            check_version(__version__)


class _FakeDocker(_Tmp):
    def setUp(self) -> None:
        super().setUp()
        bindir = self.tmp / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(FAKE_DOCKER.format(python=sys.executable, root=str(PKG.parent)), encoding="utf-8")
        docker.chmod(0o755)
        self.log = self.tmp / "docker.jsonl"
        have = self.tmp / "have"
        have.mkdir()
        self.env = {
            "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_DOCKER_HAVE": str(have),
        }
        self.lock = self.tmp / "images.lock.json"
        patcher = mock.patch("fortressgd.core.templates.images_lock_path", return_value=self.lock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.log.unlink()
        return calls

    def _pin(self, entries: list[dict[str, str]] | None = None) -> None:
        self.lock.write_text(json.dumps({"schema": 1, "images": entries or _entries()}))

    def _build(self, platforms=("linux",), env=None, **kwargs) -> list[list[str]]:
        from fortressgd.core.secret import generate_secret_hex, write_secret_file
        from fortressgd.core.templates import build_templates

        secret_file = self.tmp / "secret"
        if not secret_file.exists():
            write_secret_file(secret_file, generate_secret_hex())
        with mock.patch.dict(os.environ, dict(self.env, **(env or {}))):
            build_templates(godot="4.6.2", platforms=list(platforms), secret_file=str(secret_file),
                            environ={}, cwd=self.tmp, cache_dir=self.tmp / "cache", **kwargs)
        return self._calls()


class PinnedImageTests(_FakeDocker):
    REF = "ghcr.io/example/fortressgd-build@" + DIGEST

    def test_pulls_the_pinned_digest_once_and_relinks_in_it(self) -> None:
        self._pin()
        first = self._build()
        self.assertIn(["pull", self.REF], first)
        self.assertEqual([c for c in first if c[0] == "build"], [], "a pinned image is never built locally")
        (run,) = [c for c in first if c[0] == "run"]
        self.assertEqual(run[-1], self.REF)
        self.assertIn("FGD_MODE=relink", run)
        second = self._build()
        self.assertEqual([c for c in second if c[0] == "pull"], [])

    def test_refuses_a_pin_for_other_inputs(self) -> None:
        from fortressgd.core.errors import ToolError

        entries = _entries()
        for e in entries:
            e["tag"] = e["tag"][:-8] + "00000000"
        self._pin(entries)
        with self.assertRaises(ToolError) as ctx:
            self._build()
        self.assertIn("other inputs", str(ctx.exception))
        self.assertIn("--from-source", ctx.exception.next_command)

    def test_a_failed_pull_names_from_source(self) -> None:
        from fortressgd.core.errors import ToolError

        self._pin()
        with self.assertRaises(ToolError) as ctx:
            self._build(env={"FAKE_PULL_FAILS": "1"})
        self.assertIn("could not pull", str(ctx.exception))
        self.assertIn("--from-source", ctx.exception.next_command)

    def test_image_overrides_the_pin(self) -> None:
        self._pin()
        other = "registry.example/mine/fortressgd-build@sha256:" + "cd" * 32
        calls = self._build(image=other)
        self.assertIn(["pull", other], calls)
        self.assertNotIn(["pull", self.REF], calls)
        (run,) = [c for c in calls if c[0] == "run"]
        self.assertEqual(run[-1], other)

    def test_image_needs_one_platform_and_the_relink_path(self) -> None:
        from fortressgd.core.errors import UserError

        ref = "registry.example/x@" + DIGEST
        with self.assertRaisesRegex(UserError, "one --platform"):
            self._build(platforms=("linux", "windows"), image=ref)
        with self.assertRaisesRegex(UserError, "--from-source"):
            self._build(image=ref, from_source=True)
        with self.assertRaisesRegex(UserError, "dialect"):
            self._build(image=ref, dialect=False)

    def test_patches_dir_ignores_the_pins(self) -> None:
        from fortressgd.core.paths import patches_root

        self._pin()
        calls = self._build(patches_dir=patches_root())
        self.assertEqual([c for c in calls if c[0] == "pull"], [])
        self.assertEqual(len([c for c in calls if c[0] == "build"]), 1)

    def test_doctor_lines(self) -> None:
        from fortressgd.core.templates import build_image_status

        with mock.patch.dict(os.environ, self.env):
            self.assertIn("pins no build images", build_image_status("4.6.2", ["linux"])[0])
            self._pin()
            (line,) = build_image_status("4.6.2", ["linux"])
            self.assertTrue(line.startswith("note: pinned build image for 4.6.2 linux is not pulled"), line)
            self._build()
            (line,) = build_image_status("4.6.2", ["linux"])
            self.assertTrue(line.startswith("ok: pinned build image for 4.6.2 linux is pulled"), line)


class ReleaseBuildImageTests(_FakeDocker):
    def test_build_and_push(self) -> None:
        from fortressgd.core.templates import build_image_tag, patchset_for_tag
        from fortressgd.core.version import __version__
        from fortressgd.release import build_and_push

        repo = "ghcr.io/example/fortressgd-build"
        env = dict(self.env, FAKE_REPO_DIGESTS="{0}@{1} other.example/x@sha256:{2}".format(repo, DIGEST, "0" * 64))
        with mock.patch.dict(os.environ, env):
            entry = build_and_push("4.7.2", "windows", repo, revision="c0ffee")
        local = build_image_tag("4.7.2", "windows", "x86_64", patchset_for_tag("4.7.2"))
        self.assertEqual(entry, {"godot": "4.7.2", "platform": "windows", "arch": "x86_64",
                                 "tag": local, "ref": repo + "@" + DIGEST})
        calls = self._calls()
        (build,) = [c for c in calls if c[0] == "build"]
        release_tag = "{0}:v{1}-godot4.7.2-windows-x86_64".format(repo, __version__)
        self.assertIn(release_tag, build)
        self.assertIn("org.opencontainers.image.revision=c0ffee", build)
        self.assertIn("org.opencontainers.image.source=https://github.com/salaryman-inc/FortressGD", build)
        content_tag = repo + ":" + local.split(":", 1)[1]
        self.assertIn(["tag", local, content_tag], calls)
        self.assertEqual(sorted(c[1] for c in calls if c[0] == "push"), sorted([content_tag, release_tag]))

    def test_refuses_an_uppercase_repository(self) -> None:
        from fortressgd.core.errors import UserError
        from fortressgd.release import build_and_push

        with self.assertRaises(UserError):
            build_and_push("4.6.2", "linux", "ghcr.io/Example/fortressgd-build", revision="c")


if __name__ == "__main__":
    unittest.main()

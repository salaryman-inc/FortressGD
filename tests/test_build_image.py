"""Build image prebuild and relink modes of the template entrypoint (DESIGN.md §18.4).

A fake ``scons`` on PATH stands in for the compile: it records its arguments,
"compiles" core/fortressgd_gen.cpp only when that file's content changed since the
previous run (as SCons's MD5 decider would), and writes a binary carrying the string
the entrypoint checks for. The real compile and relink are covered by the e2e
workflow.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.kdf import secret_hash
from fortressgd.core.secret import SECRET_BYTES
from fortressgd.core.templates import template_filename
from fortressgd.generator.generate import render_gen_cpp
from tests.support import PKG, seed_mini_godot_tree

ENTRY = PKG / "docker" / "entrypoint.sh"
COMMON = PKG / "patches" / "common"
SECRET = bytes(range(SECRET_BYTES))

FAKE_SCONS = """#!{python}
import hashlib, os, pathlib, sys
with open(os.environ["FAKE_SCONS_LOG"], "a", encoding="utf-8") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\\n")
gen = pathlib.Path("core/fortressgd_gen.cpp")
stamp = pathlib.Path(".fake-scons-gen.md5")
digest = hashlib.md5(gen.read_bytes()).hexdigest()
if os.environ.get("FAKE_SCONS_STALE") != "1" and (not stamp.exists() or stamp.read_text() != digest):
    print("Compiling core/fortressgd_gen.cpp ...")
stamp.write_text(digest)
args = dict(a.split("=", 1) for a in sys.argv[1:] if "=" in a and not a.startswith("-"))
suffix = ".exe" if args["platform"] == "windows" else ""
pathlib.Path("bin").mkdir(exist_ok=True)
out = pathlib.Path("bin/godot.{{0}}.template_release.{{1}}{{2}}".format(args["platform"], args["arch"], suffix))
out.write_bytes(b"fake template: Pack signature check failed.")
"""


class BuildImageModeTests(unittest.TestCase):
    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.tmp = Path(holder.name)
        # Patches with a build-deps.sh that needs no network; the patchset id is
        # computed from this copy on both sides.
        self.patches = self.tmp / "patches"
        shutil.copytree(PKG / "patches" / "4.6.2", self.patches)
        (self.patches / "build-deps.sh").write_text(
            "#!/bin/sh\necho accesskit_sdk_path=$PWD/bin/build_deps/accesskit/\n", encoding="utf-8"
        )
        bindir = self.tmp / "bin"
        bindir.mkdir()
        scons = bindir / "scons"
        scons.write_text(FAKE_SCONS.format(python=sys.executable), encoding="utf-8")
        scons.chmod(0o755)
        self.scons_log = self.tmp / "scons-args.txt"
        self.godot_src = seed_mini_godot_tree("4.6.2", self.tmp / "godot")
        self.out = self.tmp / "out"
        self.path = str(bindir) + os.pathsep + os.environ.get("PATH", "")

    def _env(self, mode: str, **extra: str) -> dict[str, str]:
        env = os.environ.copy()
        for key in ("FGD_SECRET_HASH", "FGD_PATCHSET", "FGD_LTO", "FORTRESSGD_GEN_CPP"):
            env.pop(key, None)
        env.update({
            "PATH": self.path, "FAKE_SCONS_LOG": str(self.scons_log),
            "GODOT_VERSION": "4.6.2-stable", "FGD_GODOT": "4.6.2", "FGD_PLATFORM": "linux",
            "FGD_ARCH": "x86_64", "FGD_MODE": mode, "FGD_DIALECT": "1",
            "PATCHES_DIR": str(self.patches), "FORTRESSGD_COMMON": str(COMMON),
            "GODOT_SRC": str(self.godot_src), "OUT_DIR": str(self.out), "GIT_TERMINAL_PROMPT": "0",
        })
        env.update(extra)
        return env

    def _run(self, env: dict[str, str]) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(ENTRY)], capture_output=True, text=True, env=env, timeout=180)

    def _prebuild(self) -> None:
        run = self._run(self._env("prebuild"))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def _relink_env(self, **extra: str) -> dict[str, str]:
        gen = self.tmp / "fortressgd_gen.cpp"
        gen.write_text(render_gen_cpp(SECRET, "4.6.2"), encoding="utf-8")
        values = {"FGD_SECRET_HASH": secret_hash(SECRET), "FORTRESSGD_GEN_CPP": str(gen), "FGD_DIALECT_ID": "d" * 16}
        values.update(extra)
        return self._env("relink", **values)

    def test_prebuild_compiles_the_placeholder_and_records_state(self) -> None:
        self._prebuild()
        core = self.godot_src / "core"
        placeholder = (COMMON / "fortressgd_gen_placeholder.cpp").read_bytes()
        self.assertEqual((core / "fortressgd_gen.cpp").read_bytes(), placeholder)
        self.assertIn("#define FGD_REQUIRE_PACK_SIGNATURE 0", (core / "fortressgd_variant.h").read_text())
        state = self.godot_src / ".fortressgd"
        self.assertEqual((state / "platform").read_text().strip(), "linux")
        self.assertEqual((state / "godot").read_text().strip(), "4.6.2")
        self.assertIn("FORTRESSGD_DIALECT", (state / "defines").read_text())
        self.assertIn("accesskit_sdk_path=", (state / "deps_flags").read_text())
        # No binary linked against the placeholder stays in the tree.
        self.assertEqual(list((self.godot_src / "bin").glob("godot.*template_release*")), [])
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_relink_replays_the_prebuild_and_writes_the_template(self) -> None:
        self._prebuild()
        run = self._run(self._relink_env(FGD_REQUIRE_SIGNATURE="1"))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        calls = self.scons_log.read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1], "the relink must replay the prebuild's exact SCons arguments")
        self.assertIn("relink compiled 1 file(s)", run.stdout)
        core = self.godot_src / "core"
        self.assertEqual(core.joinpath("fortressgd_gen.cpp").read_text(), render_gen_cpp(SECRET, "4.6.2"))
        self.assertIn("#define FGD_REQUIRE_PACK_SIGNATURE 1", (core / "fortressgd_variant.h").read_text())
        pset = (self.godot_src / ".fortressgd" / "patchset").read_text().strip()
        name = template_filename("4.6.2", "linux", "x86_64", pset, secret_hash(SECRET), require_signature=True)
        self.assertTrue((self.out / name).is_file(), sorted(p.name for p in self.out.iterdir()))
        manifest = json.loads((self.out / (name + ".manifest.json")).read_text())
        self.assertIs(manifest["require_signature"], True)
        self.assertEqual(manifest["generator_version"], "2")

    def test_relink_refuses_the_placeholder(self) -> None:
        self._prebuild()
        run = self._run(self._relink_env(FORTRESSGD_GEN_CPP=str(COMMON / "fortressgd_gen_placeholder.cpp")))
        self.assertEqual(run.returncode, 3)
        self.assertIn("placeholder", run.stderr)

    def test_relink_refuses_a_file_the_generator_did_not_write(self) -> None:
        self._prebuild()
        other = self.tmp / "other.cpp"
        other.write_text("void fgd_derive_key(unsigned char *k) {}\n", encoding="utf-8")
        run = self._run(self._relink_env(FORTRESSGD_GEN_CPP=str(other)))
        self.assertEqual(run.returncode, 3)
        self.assertIn("not written by the fortressgd generator", run.stderr)

    def test_relink_without_a_prebuilt_tree_fails(self) -> None:
        run = self._run(self._relink_env())
        self.assertEqual(run.returncode, 3)
        self.assertIn("needs a build image", run.stderr)

    def test_relink_refuses_an_image_for_another_patchset_platform_or_lto(self) -> None:
        self._prebuild()
        for extra, message in (
            ({"FGD_PATCHSET": "0" * 12}, "patchset_id mismatch"),
            ({"FGD_PLATFORM": "windows"}, "build image is for linux"),
            ({"FGD_LTO": "none"}, "lto=''"),
        ):
            with self.subTest(extra=extra):
                run = self._run(self._relink_env(**extra))
                self.assertEqual(run.returncode, 3, run.stdout + run.stderr)
                self.assertIn(message, run.stderr)

    def test_relink_fails_when_the_generated_file_was_not_recompiled(self) -> None:
        self._prebuild()
        run = self._run(self._relink_env(FAKE_SCONS_STALE="1"))
        self.assertEqual(run.returncode, 3)
        self.assertIn("did not recompile core/fortressgd_gen.cpp", run.stderr)

    def test_image_modes_need_the_dialect_and_build_templates_only(self) -> None:
        for extra, message in (
            ({"FGD_DIALECT": "0"}, "build dialect-off templates from source"),
            ({"FGD_TARGET": "editor"}, "builds templates only"),
            ({"FGD_LTO": "fast"}, "FGD_LTO must be"),
        ):
            with self.subTest(extra=extra):
                run = self._run(self._env("prebuild", **extra))
                self.assertEqual(run.returncode, 3)
                self.assertIn(message, run.stderr)

    def test_skip_scons_is_for_source_builds_only(self) -> None:
        run = self._run(self._env("prebuild", FORTRESSGD_SKIP_SCONS="1"))
        self.assertEqual(run.returncode, 3)
        self.assertIn("FGD_MODE=source only", run.stderr)



class TemplatePatchsetTests(unittest.TestCase):
    def test_template_id_covers_the_fixed_common_files(self) -> None:
        from fortressgd.core.patches import TEMPLATE_COMMON_FILES, patchset_id, template_patchset_inputs
        from fortressgd.core.templates import editor_patchset_for_tag, patchset_for_tag

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "patches"
            shutil.copytree(PKG / "patches", root)
            inputs = template_patchset_inputs(root / "4.6.2")
            self.assertEqual([p.name for p in inputs[-3:]], list(TEMPLATE_COMMON_FILES))
            before = patchset_for_tag("4.6.2", root)
            editor_before = editor_patchset_for_tag("4.6.2", root)
            self.assertNotEqual(before, editor_before)
            shim = root / "common" / "fortressgd_gen_shim.cpp"
            shim.write_text(shim.read_text() + "\n// changed\n")
            self.assertNotEqual(patchset_for_tag("4.6.2", root), before)
            self.assertEqual(editor_patchset_for_tag("4.6.2", root), editor_before)
            self.assertEqual(patchset_for_tag("4.6.2", root), patchset_id(template_patchset_inputs(root / "4.6.2")))



RECORDING_DOCKER = """#!{python}
import json, os, sys
from pathlib import Path
sys.path.insert(0, {root!r})
from fortressgd.core.templates import manifest_dict, template_filename, write_manifest
args = sys.argv[1:]
log = Path(os.environ["FAKE_DOCKER_LOG"])
with log.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")
built = Path(os.environ["FAKE_DOCKER_BUILT"])
if args[:2] == ["image", "inspect"]:
    # The template image exists; a build image exists once `docker build` made it.
    sys.exit(0 if not args[2].startswith("fortressgd-build:") or (built / args[2].replace("/", "_")).exists() else 1)
if args[0] == "build":
    (built / args[args.index("-t") + 1].replace("/", "_")).write_text("built")
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


class HostBuildImageTests(unittest.TestCase):
    def setUp(self) -> None:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.tmp = Path(holder.name)
        bindir = self.tmp / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(RECORDING_DOCKER.format(python=sys.executable, root=str(PKG.parent)), encoding="utf-8")
        docker.chmod(0o755)
        self.log = self.tmp / "docker.jsonl"
        self.built = self.tmp / "built"
        self.built.mkdir()
        self.env = {
            "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_DOCKER_BUILT": str(self.built),
        }

    def _build(self, secret_hex: str, **kwargs) -> list[list[str]]:
        from unittest import mock

        from fortressgd.core.secret import write_secret_file
        from fortressgd.core.templates import build_templates

        secret_file = self.tmp / ("secret-" + secret_hex[:6])
        write_secret_file(secret_file, secret_hex)
        if self.log.exists():
            self.log.unlink()
        with mock.patch.dict(os.environ, self.env):
            build_templates(godot="4.6.2", platforms=["linux"], secret_file=str(secret_file),
                            environ={}, cwd=self.tmp, cache_dir=self.tmp / "cache", **kwargs)
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    @staticmethod
    def _runs(calls: list[list[str]]) -> list[list[str]]:
        return [c for c in calls if c and c[0] == "run"]

    @staticmethod
    def _mounts(call: list[str]) -> list[str]:
        return [call[i + 1].split(":")[1] for i, a in enumerate(call) if a == "-v"]

    def test_default_builds_the_image_once_then_relinks(self) -> None:
        from fortressgd.core.secret import generate_secret_hex
        from fortressgd.core.templates import patchset_for_tag

        first = self._build(generate_secret_hex())
        builds = [c for c in first if c[0] == "build"]
        self.assertEqual(len(builds), 1)
        build = builds[0]
        self.assertTrue(build[build.index("-t") + 1].startswith("fortressgd-build:godot4.6.2-linux-x86_64-fgd"))
        self.assertIn("FGD_PATCHSET=" + patchset_for_tag("4.6.2"), build)
        self.assertIn("FGD_PLATFORM=linux", build)
        (run,) = self._runs(first)
        self.assertEqual(run[-1], build[build.index("-t") + 1])
        self.assertEqual(sorted(self._mounts(run)), ["/out", "/src/fortressgd_gen.cpp"])
        self.assertIn("FGD_MODE=relink", run)
        # A second project reuses the image: no docker build.
        second = self._build(generate_secret_hex())
        self.assertEqual([c for c in second if c[0] == "build"], [])
        self.assertEqual(len(self._runs(second)), 1)

    def test_no_secret_reaches_docker(self) -> None:
        from fortressgd.core.secret import generate_secret_hex

        secret_hex = generate_secret_hex()
        calls = self._build(secret_hex)
        flat = " ".join(" ".join(c) for c in calls)
        self.assertNotIn(secret_hex, flat)

    def test_from_source_and_dialect_off_skip_the_build_image(self) -> None:
        from fortressgd.core.secret import generate_secret_hex
        from fortressgd.core.templates import docker_image

        for kwargs in ({"from_source": True}, {"dialect": False}):
            with self.subTest(**kwargs):
                calls = self._build(generate_secret_hex(), **kwargs)
                self.assertEqual([c for c in calls if c[0] == "build"], [])
                (run,) = self._runs(calls)
                self.assertEqual(run[-1], docker_image())
                self.assertIn("/patches", self._mounts(run))
                self.assertIn("/common", self._mounts(run))
                self.assertIn("FGD_MODE=source", run)

    def test_image_tag_changes_with_its_inputs(self) -> None:
        from fortressgd.core.templates import build_image_tag

        base = build_image_tag("4.6.2", "linux", "x86_64", "a" * 12)
        self.assertNotEqual(base, build_image_tag("4.6.2", "linux", "x86_64", "b" * 12))
        self.assertNotEqual(base, build_image_tag("4.6.2", "linux", "x86_64", "a" * 12, lto="none"))
        self.assertNotEqual(base, build_image_tag("4.6.2", "windows", "x86_64", "a" * 12))


if __name__ == "__main__":
    unittest.main()

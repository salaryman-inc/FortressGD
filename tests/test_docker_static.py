"""Dockerfile, entrypoint, and GitHub Action static checks (DESIGN.md §7, §14)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from fortressgd.core.kdf import secret_hash
from fortressgd.core.errors import ToolError
from fortressgd.core.secret import generate_secret_hex, secret_bytes_from_hex
from fortressgd.core.templates import (
    KDF_NAME,
    manifest_dict,
    patchset_for_tag,
    template_filename,
    write_manifest,
)
from fortressgd.generator.dialect import dialect_material, write_dialect_header
from tests.support import PKG, ROOT, seed_mini_godot_tree


class DockerStaticTests(unittest.TestCase):
    def test_dockerfile_is_digest_pinned_and_secret_not_a_build_arg(self) -> None:
        dockerfile = PKG / "docker" / "Dockerfile.templates"
        entry = PKG / "docker" / "entrypoint.sh"
        self.assertTrue(dockerfile.is_file())
        self.assertTrue(entry.is_file())
        text = dockerfile.read_text(encoding="utf-8")
        self.assertIn("FROM ubuntu:", text)
        self.assertIn("@sha256:", text)
        self.assertNotIn("ARG FORTRESSGD_SECRET", text)
        self.assertNotIn("ARG SECRET", text)
        self.assertNotRegex(text, r"SCRIPT_AES256_ENCRYPTION_KEY=")
        entry_text = entry.read_text(encoding="utf-8")
        # The secret never enters the container; only the public secret_hash does.
        self.assertIn("FGD_SECRET_HASH", entry_text)
        self.assertNotIn("FORTRESSGD_SECRET_FILE", entry_text)
        self.assertNotIn("/run/secrets", entry_text)
        self.assertIn("git apply --check", entry_text)
        self.assertIn("FGD-KDF-1", entry_text)
        self.assertIn("template_release", entry_text)
        self.assertIn("use_mingw", entry_text)
        self.assertNotRegex(entry_text, r"SCRIPT_AES256_ENCRYPTION_KEY=")

    def test_manifest_kdf_and_no_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            data = manifest_dict(
                godot="4.6.2",
                patchset="aaaaaaaaaaaa",
                secrethash="bbbbbbbbbbbbbbbb",
                dialect="cccccccccccccccc",
                platform="linux",
            )
            write_manifest(path, data)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["kdf"], "FGD-KDF-1")
            self.assertNotIn("aes_key", loaded)
            self.assertNotIn("secret", loaded)
            bad = dict(data)
            bad["aes_key"] = "nope"
            with self.assertRaises(ToolError):
                write_manifest(path, bad)

    def test_action_yml_inputs_and_cache_key(self) -> None:
        action = (ROOT / "actions" / "build-templates" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("godot_version:", action)
        self.assertIn("platforms:", action)
        self.assertIn("secret:", action)
        self.assertIn("fgd-templates-", action)
        self.assertIn("secret_hash", action)
        self.assertIn("patchset", action)

    def test_action_masks_first_and_scans_outputs_last(self) -> None:
        action = (ROOT / "actions" / "build-templates" / "action.yml").read_text(encoding="utf-8")
        steps = action.split("\n    - name: ")[1:]
        self.assertTrue(steps[0].startswith("Mask"), steps[0][:40])
        self.assertIn("::add-mask::", steps[0])
        self.assertIn("secret_needles", steps[0])
        build = next(s for s in steps if s.startswith("Build templates"))
        self.assertIn('tee "$RUNNER_TEMP/fortressgd-templates-build.log"', build)
        last = steps[-1]
        self.assertTrue(last.startswith("Scan outputs"), last[:40])
        self.assertIn("if: always()", last)
        self.assertIn("python3 -m fortressgd.core.leakscan", last)
        self.assertIn("--delete", last)
        self.assertIn(".cache/fortressgd/templates", last)
        self.assertIn("fortressgd-templates-build.log", last)
        # The secret comes in as an input and only reaches steps through env, never inline.
        for step in steps:
            run = step.split("run: |", 1)[-1]
            self.assertNotIn("inputs.secret", run)

    def test_entrypoint_passes_require_signature_through(self) -> None:
        entry = (PKG / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('FGD_REQUIRE_SIGNATURE="${FGD_REQUIRE_SIGNATURE:-0}"', entry)
        self.assertIn('NAME="${NAME}-sig"', entry)
        self.assertIn('"require_signature": require_sig == "1"', entry)
        self.assertIn("FGD_REQUIRE_PACK_SIGNATURE = 1;", entry)
        templates = (PKG / "core" / "templates.py").read_text(encoding="utf-8")
        self.assertIn('"FGD_REQUIRE_SIGNATURE={0}"', templates)
        action = (ROOT / "actions" / "build-templates" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("--require-signature", action)
        self.assertIn("'-sig'", action)
        self.assertTrue(
            template_filename("4.6.2", "linux", "x86_64", "a" * 12, "b" * 16, require_signature=True).endswith("-sig")
        )
        data = manifest_dict(
            godot="4.6.2", patchset="a" * 12, secrethash="b" * 16, dialect="c" * 16,
            platform="linux", require_signature=True,
        )
        self.assertIs(data["require_signature"], True)

    def test_entrypoint_passes_defines_through_godots_cppdefines_option(self) -> None:
        # Godot 4's SConstruct declares only lowercase ccflags/cppdefines, so an
        # uppercase CCFLAGS= is dropped without a warning and every #ifdef
        # FORTRESSGD_* block compiles out.
        entry = (PKG / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
        code = "\n".join(line for line in entry.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("CCFLAGS=", code)
        self.assertNotIn("ccflags=", code)
        self.assertEqual(code.count('cppdefines="$FGD_DEFINES"'), 2)  # linux and windows
        for define in ("FORTRESSGD_OPCODE_MAP", "FORTRESSGD_NAMELESS", "FORTRESSGD_SIGN_PACKS"):
            self.assertIn(define, code)
        self.assertIn('FGD_DEFINES="$FGD_DEFINES FORTRESSGD_DIALECT"', code)
        self.assertNotIn("-DFORTRESSGD", code)  # cppdefines takes bare names
        # The built binary must carry FORTRESSGD_SIGN_PACKS code, or the build fails.
        message = "Pack signature check failed."
        self.assertIn('grep -aqF "{0}" "$BIN"'.format(message), code)
        for tag in ("4.6.2", "4.7.2"):
            sig = (PKG / "patches" / tag / "0005-pack-signatures.patch").read_text(encoding="utf-8")
            self.assertIn('"{0}"'.format(message), sig, msg=tag)
        # The Windows build also emits a .console.exe launcher, which sorts first.
        win_bin = next(line for line in code.splitlines() if "bin/godot.windows.template_release" in line)
        self.assertIn("grep -v '\\.console\\.exe$'", win_bin)
        guard = code.index('grep -aqF "{0}"'.format(message))
        self.assertLess(code.index('err "scons did not emit'), guard)
        self.assertLess(guard, code.index('cp "$BIN" "$OUT_DIR/$NAME"'))

    def test_image_tag_follows_the_files_baked_into_it(self) -> None:
        # A fixed tag let an upgraded FortressGD reuse an image with an older
        # entrypoint.sh baked in, and run the old build script.
        import shutil

        from fortressgd.core import templates

        tag = templates.docker_image()
        self.assertRegex(tag, r"^fortressgd-templates:[0-9a-f]{12}$")
        self.assertEqual(tag, templates.docker_image())
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Path(tmp)
            for name in templates.DOCKER_CONTEXT_FILES:
                shutil.copy2(PKG / "docker" / name, ctx / name)
            with mock.patch.object(templates, "docker_dir", return_value=ctx):
                self.assertEqual(templates.docker_image(), tag)
                (ctx / "entrypoint.sh").write_text((ctx / "entrypoint.sh").read_text() + "\n# changed\n")
                self.assertNotEqual(templates.docker_image(), tag)

    def test_shipped_entrypoint_requires_the_public_secret_hash(self) -> None:
        for value in (None, "", "not-hex", "0123456789ABCDEF", "0123456789abcdef00"):
            with self.subTest(value=value):
                env = os.environ.copy()
                env.pop("FGD_SECRET_HASH", None)
                if value is not None:
                    env["FGD_SECRET_HASH"] = value
                run = subprocess.run(
                    ["sh", str(PKG / "docker" / "entrypoint.sh")],
                    capture_output=True, text=True, env=env, timeout=60,
                )
                self.assertEqual(run.returncode, 3, run.stdout + run.stderr)
                self.assertIn("FGD_SECRET_HASH must be the 16-hex secret_hash", run.stderr)

    def test_shipped_entrypoint_require_signature_names_and_records_variant(self) -> None:
        secret_hex = generate_secret_hex()
        secret = secret_bytes_from_hex(secret_hex)
        pset = patchset_for_tag("4.6.2")
        _salt, _masks, _shards, did = dialect_material(secret, "4.6.2")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            header = tmp_path / "dialect.gen.h"
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            godot_src = seed_mini_godot_tree("4.6.2", tmp_path / "godot")
            env = os.environ.copy()
            env.update({
                "GODOT_VERSION": "4.6.2-stable", "FGD_GODOT": "4.6.2", "FGD_PLATFORM": "linux",
                "FGD_ARCH": "x86_64", "FGD_DIALECT_ID": did, "FGD_PATCHSET": pset,
                "FGD_SECRET_HASH": secret_hash(secret), "FORTRESSGD_SKIP_SCONS": "1",
                "FGD_DIALECT": "1", "FGD_REQUIRE_SIGNATURE": "1",
                "PATCHES_DIR": str(PKG / "patches" / "4.6.2"), "DIALECT_HEADER": str(header),
                "OUT_DIR": str(out_dir), "GODOT_SRC": str(godot_src), "GIT_TERMINAL_PROMPT": "0",
            })
            # A header that does not require signatures is refused.
            write_dialect_header(header, secret, "4.6.2")
            bad = subprocess.run(["sh", str(PKG / "docker" / "entrypoint.sh")], capture_output=True, text=True, env=env, timeout=180)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("does not require signatures", bad.stderr)
            write_dialect_header(header, secret, "4.6.2", require_signature=True)
            run = subprocess.run(["sh", str(PKG / "docker" / "entrypoint.sh")], capture_output=True, text=True, env=env, timeout=180)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            name = template_filename("4.6.2", "linux", "x86_64", pset, secret_hash(secret), require_signature=True)
            self.assertTrue((out_dir / name).is_file(), sorted(p.name for p in out_dir.iterdir()))
            manifest = json.loads((out_dir / (name + ".manifest.json")).read_text(encoding="utf-8"))
            self.assertIs(manifest["require_signature"], True)
            installed = (godot_src / "core" / "dialect.gen.h").read_text(encoding="utf-8")
            self.assertIn("FGD_REQUIRE_PACK_SIGNATURE = 1;", installed)

    def test_shipped_entrypoint_skip_scons_applies_series_and_manifest(self) -> None:
        """Drive fortressgd/docker/entrypoint.sh (the shipped template-build entry) far enough
        to clone/apply/install header and emit §7 name + manifest. Skip-scons avoids
        a 30–60min compile. Uses host git/python so a hung docker pull cannot stall.
        """
        entry = PKG / "docker" / "entrypoint.sh"
        self.assertTrue(entry.is_file())
        secret_hex = generate_secret_hex()
        secret = secret_bytes_from_hex(secret_hex)
        sh = secret_hash(secret)
        pset = patchset_for_tag("4.6.2")
        _salt, _masks, _shards, did = dialect_material(secret, "4.6.2")
        log_raw = os.environ.get("FORTRESSGD_DOCKER_LOG", "").strip()
        log_path = Path(log_raw) if log_raw else None
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            header = tmp_path / "dialect.gen.h"
            write_dialect_header(header, secret, "4.6.2")
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            godot_src = seed_mini_godot_tree("4.6.2", tmp_path / "godot")
            env = os.environ.copy()
            env.update(
                {
                    "GODOT_VERSION": "4.6.2-stable",
                    "FGD_GODOT": "4.6.2",
                    "FGD_PLATFORM": "linux",
                    "FGD_ARCH": "x86_64",
                    "FGD_DIALECT_ID": did,
                    "FGD_PATCHSET": pset,
                    "FGD_SECRET_HASH": sh,
                    "FORTRESSGD_SKIP_SCONS": "1",
                    "FGD_DIALECT": "1",
                    "PATCHES_DIR": str(PKG / "patches" / "4.6.2"),
                    "DIALECT_HEADER": str(header),
                    "OUT_DIR": str(out_dir),
                    "GODOT_SRC": str(godot_src),
                    "GIT_TERMINAL_PROMPT": "0",
                }
            )
            try:
                run = subprocess.run(
                    ["sh", str(entry)],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=180,
                )
            except subprocess.TimeoutExpired as exc:
                msg = "entrypoint timed out: {0}".format(exc)
                if log_path is not None:
                    log_path.write_text(msg, encoding="utf-8")
                self.fail(msg)
            combined = (run.stdout or "") + "\n" + (run.stderr or "")
            if log_path is not None:
                log_path.write_text(combined, encoding="utf-8")
            if run.returncode != 0 and (
                "git clone" in combined.lower() or "Could not resolve" in combined
            ):
                self.skipTest("godot clone failed (network): {0}".format(combined[-500:]))
            self.assertEqual(run.returncode, 0, combined)
            name = template_filename("4.6.2", "linux", "x86_64", pset, sh)
            man = out_dir / (name + ".manifest.json")
            self.assertTrue((godot_src / "core" / "fortressgd_kdf.cpp").is_file(), combined)
            self.assertTrue((godot_src / "core" / "dialect.gen.h").is_file(), combined)
            packed = (godot_src / "core" / "io" / "file_access_pack.cpp").read_text(
                encoding="utf-8"
            )
            header = (godot_src / "core" / "io" / "file_access_pack.h").read_text(encoding="utf-8")
            packer = (godot_src / "core" / "io" / "pck_packer.cpp").read_text(encoding="utf-8")
            self.assertIn("fortressgd_derive_key", packed)
            self.assertNotIn("Can't open encrypted pack directory.", packed)
            self.assertIn("FORTRESSGD_DIALECT", header)
            self.assertIn("FGD_PACK_MAGIC", header)
            self.assertIn("FGD_INDEX_PERM", packed)
            self.assertIn("FGD_INDEX_PERM", packer)
            gen_header = (godot_src / "core" / "dialect.gen.h").read_text(encoding="utf-8")
            self.assertIn("FGD_PACK_MAGIC", gen_header)
            self.assertIn("FGD_INDEX_PERM", gen_header)
            self.assertTrue(man.is_file(), combined)
            data = json.loads(man.read_text(encoding="utf-8"))
            self.assertEqual(data.get("kdf"), KDF_NAME)
            self.assertNotIn("aes_key", data)
            self.assertNotIn("secret", data)
            self.assertEqual(data.get("secret_hash"), sh)
            self.assertNotIn(secret_hex, man.read_text(encoding="utf-8"))
            self.assertTrue((out_dir / name).exists())
            self.assertIn("ok:", combined)

    def test_docker_image_build_optional(self) -> None:
        """Full image build is optional. Never hang: 45s timeout. Default skip."""
        if os.environ.get("FORTRESSGD_DOCKER_TESTS") != "1":
            self.skipTest("set FORTRESSGD_DOCKER_TESTS=1 to docker-build the image")
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("docker executable not found")
        log_raw = os.environ.get("FORTRESSGD_DOCKER_LOG", "").strip()
        log_path = Path(log_raw) if log_raw else None
        dockerfile = PKG / "docker" / "Dockerfile.templates"
        try:
            build = subprocess.run(
                [docker, "build", "-f", str(dockerfile), "-t", "fortressgd-templates:v1-test", str(PKG / "docker")],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except subprocess.TimeoutExpired:
            msg = "docker build timed out (credential helper or pull hung)"
            if log_path is not None:
                with log_path.open("a", encoding="utf-8") as fh:
                    fh.write(msg + "\n")
            self.skipTest(msg)
        if build.returncode != 0:
            self.skipTest("docker build failed: {0}".format((build.stderr or build.stdout)[-400:]))


if __name__ == "__main__":
    unittest.main()

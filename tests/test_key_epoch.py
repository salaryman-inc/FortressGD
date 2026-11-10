"""[production].key_epoch: a per-release-line pack key without rotating the secret."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.config import ConfigError, default_toml_text, key_epoch, parse_toml, validate
from fortressgd.core.kdf import SALT_LEN, aes_key_hex, fgd_kdf_1, hkdf_sha256, secret_hash
from fortressgd.core.leakscan import secret_needles
from fortressgd.core.pack import PACK_DIR_ENCRYPTED
from fortressgd.core.pack_dialect import dialect_key_for_secret, dialect_params_for_secret
from fortressgd.core.pack_sign import signing_seed
from fortressgd.core.secret import read_secret_file, secret_bytes_from_hex
from fortressgd.core.templates import patchset_for_tag, template_filename, templates_cache_dir
from fortressgd.generator.dialect import (
    _domain_salt,
    _info,
    derive_dialect_salt,
    derive_index_perm,
    derive_pack_magic,
    dialect_material,
)
from fortressgd.generator.generate import render_gen_cpp
from fortressgd.generator.opcode_map import opcode_map
from tests.gdpc_fixture import make_gdpc
from tests.support import PKG, run_fortressgd, seed_mini_godot_tree, write_godot_stub
from tests.test_templates_export import PRESETS, _write_godot_stub_bin
from tests.support import base_env

SECRET = bytes(range(32))


def _toml_with_epoch(epoch: int, *, dialect: bool = False) -> str:
    text = default_toml_text().replace("key_epoch = 0", "key_epoch = {0}".format(epoch))
    if not dialect:
        text = text.replace("dialect = true", "dialect = false")
    return text


class KeyEpochConfigTests(unittest.TestCase):
    def test_example_config_has_epoch_zero(self) -> None:
        cfg = validate(parse_toml(default_toml_text()))
        self.assertEqual(cfg["production"]["key_epoch"], 0)
        self.assertEqual(key_epoch(cfg), 0)

    def test_absent_epoch_is_zero(self) -> None:
        self.assertEqual(key_epoch({"production": {"dialect": True}}), 0)
        self.assertEqual(key_epoch(None), 0)

    def test_epoch_must_be_a_non_negative_integer(self) -> None:
        self.assertEqual(key_epoch(validate(parse_toml(_toml_with_epoch(7)))), 7)
        for bad in ("-1", "true", '"3"', "2147483648"):
            with self.subTest(value=bad):
                text = default_toml_text().replace("key_epoch = 0", "key_epoch = " + bad)
                with self.assertRaises(ConfigError) as ctx:
                    validate(parse_toml(text))
                self.assertIn("key_epoch", str(ctx.exception))
        # The TOML subset has no floats; the parser itself refuses this one.
        with self.assertRaises(ConfigError):
            validate(parse_toml(default_toml_text().replace("key_epoch = 0", "key_epoch = 1.5")))


class KeyEpochDerivationTests(unittest.TestCase):
    def test_epoch_zero_is_the_original_derivation(self) -> None:
        # Projects that never set key_epoch keep their key, packs and templates.
        original = hkdf_sha256(SECRET, _domain_salt("4.6.2", "salt"), _info(None), SALT_LEN)
        self.assertEqual(derive_dialect_salt(SECRET, "4.6.2"), original)
        self.assertEqual(derive_dialect_salt(SECRET, "4.6.2", key_epoch=0), original)
        self.assertEqual(dialect_key_for_secret(SECRET, "4.6.2"), fgd_kdf_1(SECRET, original))

    def test_each_epoch_has_its_own_pack_key(self) -> None:
        keys = {dialect_key_for_secret(SECRET, "4.6.2", key_epoch=e) for e in (0, 1, 2, 1000)}
        self.assertEqual(len(keys), 4)
        self.assertEqual(
            dialect_key_for_secret(SECRET, "4.6.2", key_epoch=3),
            dialect_key_for_secret(SECRET, "4.6.2", key_epoch=3),
        )

    def test_epoch_changes_only_the_pack_key(self) -> None:
        for epoch in (1, 9):
            with self.subTest(epoch=epoch):
                m0, p0, k0 = dialect_params_for_secret(SECRET, "4.6.2")
                m1, p1, k1 = dialect_params_for_secret(SECRET, "4.6.2", key_epoch=epoch)
                self.assertEqual((m0, p0), (m1, p1))
                self.assertNotEqual(k0, k1)
        self.assertEqual(derive_pack_magic(SECRET, "4.6.2"), derive_pack_magic(SECRET, "4.6.2"))
        self.assertEqual(derive_index_perm(SECRET, "4.6.2"), derive_index_perm(SECRET, "4.6.2"))
        self.assertEqual(signing_seed(SECRET, "4.6.2"), signing_seed(SECRET, "4.6.2"))
        self.assertEqual(opcode_map(SECRET, "4.6.2"), opcode_map(SECRET, "4.6.2"))

    def test_header_carries_the_epoch_key(self) -> None:
        for epoch in (0, 4):
            with self.subTest(epoch=epoch):
                salt, masks, shards, _did = dialect_material(SECRET, "4.6.2", key_epoch=epoch)
                self.assertEqual(salt, derive_dialect_salt(SECRET, "4.6.2", key_epoch=epoch))
                self.assertEqual(
                    bytes(a ^ b for a, b in zip(shards, masks)),
                    dialect_key_for_secret(SECRET, "4.6.2", key_epoch=epoch),
                )

    def test_leak_needles_cover_the_epoch_key(self) -> None:
        key = dialect_key_for_secret(SECRET, "4.6.2", key_epoch=5)
        needles = {needle for _label, needle in secret_needles(SECRET, "4.6.2", key_epoch=5)}
        self.assertIn(key, needles)
        self.assertIn(key.hex().encode("ascii"), needles)

    def test_template_names_mark_non_zero_epochs(self) -> None:
        base = template_filename("4.6.2", "linux", "x86_64", "a" * 12, "b" * 16)
        self.assertEqual(template_filename("4.6.2", "linux", "x86_64", "a" * 12, "b" * 16, key_epoch=0), base)
        self.assertEqual(template_filename("4.6.2", "linux", "x86_64", "a" * 12, "b" * 16, key_epoch=3), base + "-e3")
        self.assertEqual(
            template_filename("4.6.2", "linux", "x86_64", "a" * 12, "b" * 16, key_epoch=3, require_signature=True),
            base + "-e3-sig",
        )


class KeyEpochEntrypointTests(unittest.TestCase):
    def _env(self, tmp: Path, epoch: str) -> tuple[dict[str, str], Path, Path]:
        gen_cpp = tmp / "fortressgd_gen.cpp"
        gen_cpp.write_text(
            render_gen_cpp(SECRET, "4.6.2", key_epoch=int(epoch) if epoch.isdigit() else 0),
            encoding="utf-8",
        )
        out_dir = tmp / "out"
        out_dir.mkdir()
        godot_src = seed_mini_godot_tree("4.6.2", tmp / "godot")
        env = os.environ.copy()
        env.update({
            "GODOT_VERSION": "4.6.2-stable", "FGD_GODOT": "4.6.2", "FGD_PLATFORM": "linux",
            "FGD_ARCH": "x86_64", "FGD_DIALECT_ID": "d" * 16, "FGD_PATCHSET": patchset_for_tag("4.6.2"),
            "FGD_SECRET_HASH": secret_hash(SECRET), "FORTRESSGD_SKIP_SCONS": "1", "FGD_DIALECT": "0",
            "FGD_KEY_EPOCH": epoch, "PATCHES_DIR": str(PKG / "patches" / "4.6.2"),
            "FORTRESSGD_GEN_CPP": str(gen_cpp), "FORTRESSGD_COMMON": str(PKG / "patches" / "common"),
            "OUT_DIR": str(out_dir), "GODOT_SRC": str(godot_src),
            "GIT_TERMINAL_PROMPT": "0",
        })
        return env, out_dir, godot_src

    def test_entrypoint_names_and_records_the_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env, out_dir, _src = self._env(Path(tmp), "3")
            run = subprocess.run(["sh", str(PKG / "docker" / "entrypoint.sh")], capture_output=True, text=True, env=env, timeout=180)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            name = template_filename("4.6.2", "linux", "x86_64", patchset_for_tag("4.6.2"), secret_hash(SECRET), key_epoch=3)
            self.assertTrue((out_dir / name).is_file(), sorted(p.name for p in out_dir.iterdir()))
            manifest = json.loads((out_dir / (name + ".manifest.json")).read_text(encoding="utf-8"))
            self.assertEqual(manifest["key_epoch"], 3)

    def test_entrypoint_rejects_a_bad_epoch(self) -> None:
        for bad in ("-1", "x", "01"):
            with self.subTest(epoch=bad), tempfile.TemporaryDirectory() as tmp:
                env, _out, _src = self._env(Path(tmp), bad)
                run = subprocess.run(["sh", str(PKG / "docker" / "entrypoint.sh")], capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(run.returncode, 3, run.stdout + run.stderr)
                self.assertIn("FGD_KEY_EPOCH", run.stderr)


class KeyEpochExportVerifyTests(unittest.TestCase):
    def _project(self, tmp: str, epoch: int) -> tuple[Path, bytes]:
        root = Path(tmp)
        write_godot_stub(root)
        self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
        cache = root / "cache"
        text = _toml_with_epoch(epoch).replace(
            'cache_dir = "~/.cache/fortressgd"', 'cache_dir = "{0}"'.format(cache.as_posix())
        )
        (root / ".fortressgd.toml").write_text(text, encoding="utf-8")
        (root / "export_presets.cfg").write_text(PRESETS, encoding="utf-8")
        self.assertEqual(run_fortressgd("secret", "generate", cwd=root).returncode, 0)
        return root, secret_bytes_from_hex(read_secret_file(root / ".fortressgd.secret"))

    def _cache_template(self, root: Path, secret: bytes, epoch: int) -> None:
        cache = templates_cache_dir(root / "cache")
        cache.mkdir(parents=True, exist_ok=True)
        name = template_filename("4.6.2", "linux", "x86_64", patchset_for_tag("4.6.2"), secret_hash(secret), key_epoch=epoch)
        (cache / name).write_bytes(b"stub-template")

    def _export(self, root: Path) -> tuple[subprocess.CompletedProcess, dict]:
        bindir = root / "bin"
        log = root / "godot-env.json"
        _write_godot_stub_bin(bindir, log)
        env = base_env()
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
        data = json.loads(log.read_text(encoding="utf-8")) if log.is_file() else {}
        return proc, data

    def test_export_uses_the_epoch_template_and_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, secret = self._project(tmp, 2)
            self._cache_template(root, secret, 2)
            proc, data = self._export(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            want = aes_key_hex(secret, derive_dialect_salt(secret, "4.6.2", key_epoch=2))
            self.assertEqual(data["GODOT_SCRIPT_ENCRYPTION_KEY"], want)
            self.assertNotEqual(want, aes_key_hex(secret, derive_dialect_salt(secret, "4.6.2")))
            self.assertIn("-e2", data["presets"])

    def test_export_refuses_a_template_from_another_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, secret = self._project(tmp, 2)
            self._cache_template(root, secret, 0)
            proc, _data = self._export(root)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("key_epoch=2", proc.stderr)
            self.assertIn("fortressgd templates build", proc.stderr)

    def test_verify_reads_packs_with_the_configured_epoch_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, secret = self._project(tmp, 2)
            pck = root / "game.pck"
            pck.write_bytes(
                make_gdpc(["main.tscn"], flags=PACK_DIR_ENCRYPTED,
                          aes_key=dialect_key_for_secret(secret, "4.6.2", key_epoch=2))
            )
            ok = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            (root / ".fortressgd.toml").write_text(
                (root / ".fortressgd.toml").read_text(encoding="utf-8").replace("key_epoch = 2", "key_epoch = 0"),
                encoding="utf-8",
            )
            wrong = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(wrong.returncode, 1, wrong.stdout + wrong.stderr)
            self.assertIn("invalid key", wrong.stderr)


if __name__ == "__main__":
    unittest.main()

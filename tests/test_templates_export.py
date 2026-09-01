"""CLI templates list + export with a stub godot recording GODOT_SCRIPT_ENCRYPTION_KEY."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.kdf import aes_key_hex, secret_hash
from core.secret import read_secret_file
from core.templates import (
    patchset_for_tag,
    template_filename,
    templates_cache_dir,
)
from generator.dialect import derive_dialect_salt
from tests.support import base_env, run_fortressgd, write_godot_stub


PRESETS = """[preset.0]

name="Linux"
platform="Linux"
runnable=true
dedicated_server=false
custom_features="fortressgd_production"
export_filter="all_resources"
export_path="build/game.x86_64"
encrypt_pck=false
encrypt_directory=false
script_export_mode=1

[preset.0.options]

custom_template/debug=""
custom_template/release=""
"""


def _write_godot_stub_bin(directory: Path, log_path: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "godot"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "log = Path({0!r})\n"
        "payload = {{\n"
        "    'argv': sys.argv,\n"
        "    'GODOT_SCRIPT_ENCRYPTION_KEY': os.environ.get('GODOT_SCRIPT_ENCRYPTION_KEY'),\n"
        "    'FORTRESSGD_SECRET': os.environ.get('FORTRESSGD_SECRET'),\n"
        "}}\n"
        "log.write_text(json.dumps(payload), encoding='utf-8')\n"
        "raise SystemExit(0)\n".format(str(log_path)),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class TemplatesExportCliTests(unittest.TestCase):
    def _project(self, tmp: str) -> Path:
        root = Path(tmp)
        write_godot_stub(root)
        self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
        toml = root / ".fortressgd.toml"
        text = toml.read_text(encoding="utf-8")
        cache = root / "cache"
        text = text.replace(
            'cache_dir = "~/.cache/fortressgd"',
            'cache_dir = "{0}"'.format(cache.as_posix()),
        )
        toml.write_text(text, encoding="utf-8")
        (root / "export_presets.cfg").write_text(PRESETS, encoding="utf-8")
        self.assertEqual(run_fortressgd("secret", "generate", cwd=root).returncode, 0)
        return root

    def _set_dialect(self, root: Path, enabled: bool) -> None:
        toml = root / ".fortressgd.toml"
        text = toml.read_text(encoding="utf-8")
        if enabled:
            text = text.replace("dialect = false", "dialect = true")
        else:
            text = text.replace("dialect = true", "dialect = false")
        toml.write_text(text, encoding="utf-8")

    def test_templates_list_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            proc = run_fortressgd("templates", "list", cwd=root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("no templates cached", proc.stdout)

    def test_export_sets_derived_key_not_secret_and_does_not_persist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            secret_hex = read_secret_file(root / ".fortressgd.secret")
            secret = bytes.fromhex(secret_hex)
            salt = derive_dialect_salt(secret, "4.6.2")
            derived = aes_key_hex(secret, salt)
            self.assertNotEqual(derived, secret_hex)
            sh = secret_hash(secret)
            pset = patchset_for_tag("4.6.2")
            cache = templates_cache_dir(root / "cache")
            cache.mkdir(parents=True, exist_ok=True)
            name = template_filename("4.6.2", "linux", "x86_64", pset, sh)
            (cache / name).write_bytes(b"stub-template")

            logs = []
            keys = []
            for i in range(2):
                bindir = root / "bin{0}".format(i)
                log = root / "godot-env-{0}.json".format(i)
                _write_godot_stub_bin(bindir, log)
                env = base_env()
                env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
                env.pop("FORTRESSGD_SECRET", None)
                proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
                self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
                data = json.loads(log.read_text(encoding="utf-8"))
                logs.append(data)
                keys.append(data["GODOT_SCRIPT_ENCRYPTION_KEY"])
                self.assertEqual(data["GODOT_SCRIPT_ENCRYPTION_KEY"], derived)
                self.assertNotEqual(data["GODOT_SCRIPT_ENCRYPTION_KEY"], secret_hex)
                self.assertIsNone(data["FORTRESSGD_SECRET"])
                self.assertIn("--export-release", data["argv"])
                self.assertNotIn("--export-pack", data["argv"])

            self.assertEqual(keys[0], keys[1])
            presets = (root / "export_presets.cfg").read_text(encoding="utf-8")
            self.assertNotIn(derived, presets)
            self.assertNotIn(secret_hex, presets)
            self.assertEqual(presets, PRESETS)
            for path in cache.rglob("*"):
                if path.is_file():
                    blob = path.read_bytes()
                    self.assertNotIn(secret_hex.encode("ascii"), blob)
                    self.assertNotIn(derived.encode("ascii"), blob)

    def test_missing_templates_prints_build_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            bindir = root / "bin"
            log = root / "godot-env.json"
            _write_godot_stub_bin(bindir, log)
            env = base_env()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
            self.assertNotEqual(proc.returncode, 0)
            combined = proc.stdout + proc.stderr
            self.assertIn("error:", combined)
            self.assertIn("fortressgd templates build", combined)

    def test_dialect_export_uses_export_pack_not_python_packer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, True)
            secret_hex = read_secret_file(root / ".fortressgd.secret")
            secret = bytes.fromhex(secret_hex)
            salt = derive_dialect_salt(secret, "4.6.2")
            derived = aes_key_hex(secret, salt)
            sh = secret_hash(secret)
            pset = patchset_for_tag("4.6.2")
            cache = templates_cache_dir(root / "cache")
            cache.mkdir(parents=True, exist_ok=True)
            name = template_filename("4.6.2", "linux", "x86_64", pset, sh)
            (cache / name).write_bytes(b"stub-template")

            for i in range(2):
                bindir = root / "bin-dialect-{0}".format(i)
                log = root / "godot-dialect-{0}.json".format(i)
                _write_godot_stub_bin(bindir, log)
                env = base_env()
                env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
                env.pop("FORTRESSGD_SECRET", None)
                proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
                self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
                data = json.loads(log.read_text(encoding="utf-8"))
                self.assertIn("--export-pack", data["argv"])
                self.assertNotIn("--export-release", data["argv"])
                self.assertEqual(data["GODOT_SCRIPT_ENCRYPTION_KEY"], derived)
                self.assertIsNone(data["FORTRESSGD_SECRET"])
                argv_join = " ".join(data["argv"])
                self.assertNotIn("pack.py", argv_join)
                self.assertNotIn("python -m", argv_join)

            presets = (root / "export_presets.cfg").read_text(encoding="utf-8")
            self.assertNotIn(derived, presets)
            self.assertNotIn(secret_hex, presets)
            self.assertEqual(presets, PRESETS)


if __name__ == "__main__":
    unittest.main()

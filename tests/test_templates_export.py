"""CLI templates list + export with a stub godot recording GODOT_SCRIPT_ENCRYPTION_KEY."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.kdf import aes_key_hex, secret_hash
from fortressgd.core.secret import read_secret_file
from fortressgd.core.templates import (
    patchset_for_tag,
    template_filename,
    templates_cache_dir,
)
from fortressgd.generator.dialect import derive_dialect_salt
from tests.support import ROOT, base_env, run_fortressgd, write_godot_stub


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
        "    'presets': (Path(sys.argv[sys.argv.index('--path') + 1]) / 'export_presets.cfg')"
        ".read_text(encoding='utf-8') if '--path' in sys.argv else None,\n"
        "}}\n"
        "log.write_text(json.dumps(payload), encoding='utf-8')\n"
        "sys.path.insert(0, {1!r})\n"
        "from tests.godot_stub import write_artifact\n"
        "write_artifact(sys.argv)\n"
        "raise SystemExit(0)\n".format(str(log_path), str(ROOT)),
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

    def _cache_linux_template(self, root: Path) -> None:
        secret = bytes.fromhex(read_secret_file(root / ".fortressgd.secret"))
        cache = templates_cache_dir(root / "cache")
        cache.mkdir(parents=True, exist_ok=True)
        name = template_filename("4.6.2", "linux", "x86_64", patchset_for_tag("4.6.2"), secret_hash(secret))
        (cache / name).write_bytes(b"stub-template")

    def _export_and_read_presets_seen_by_godot(self, root: Path) -> str:
        bindir = root / "bin"
        log = root / "godot-env.json"
        _write_godot_stub_bin(bindir, log)
        env = base_env()
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        return json.loads(log.read_text(encoding="utf-8"))["presets"]

    def test_export_creates_missing_output_folder(self) -> None:
        # Godot refuses an output folder that does not exist (the stub does too),
        # so export must create build/linux/ before running it.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            (root / "export_presets.cfg").write_text(
                PRESETS.replace('export_path="build/game.x86_64"', 'export_path="build/linux/game.x86_64"'),
                encoding="utf-8",
            )
            self._cache_linux_template(root)
            self.assertFalse((root / "build").exists())
            self._export_and_read_presets_seen_by_godot(root)
            self.assertTrue((root / "build" / "linux" / "game.x86_64").is_file())

    def test_export_encrypts_every_file_body_by_default(self) -> None:
        # Godot encrypts a body only when it matches encryption_include_filters;
        # empty encrypts none. export sets "*" for its run and restores the file.
        for dialect in (False, True):
            with self.subTest(dialect=dialect), tempfile.TemporaryDirectory() as tmp:
                root = self._project(tmp)
                self._set_dialect(root, dialect)
                self._cache_linux_template(root)
                seen = self._export_and_read_presets_seen_by_godot(root)
                section = seen.split("[preset.0.options]")[0]
                self.assertIn('encryption_include_filters="*"', section)
                self.assertIn("encrypt_pck=true", section)
                self.assertIn("encrypt_directory=true", section)
                self.assertEqual((root / "export_presets.cfg").read_text(encoding="utf-8"), PRESETS)

    def test_export_keeps_a_preset_encryption_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            presets = PRESETS.replace(
                "encrypt_directory=false\n",
                'encrypt_directory=false\nencryption_include_filters="*.gdc, *.tscn"\n',
            )
            (root / "export_presets.cfg").write_text(presets, encoding="utf-8")
            self._cache_linux_template(root)
            seen = self._export_and_read_presets_seen_by_godot(root)
            self.assertIn('encryption_include_filters="*.gdc, *.tscn"', seen)
            self.assertNotIn('encryption_include_filters="*"', seen)
            self.assertEqual((root / "export_presets.cfg").read_text(encoding="utf-8"), presets)

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


    def _export_with_stub(self, root: Path, *, require_signature: bool = False, **stub_env: str):
        """Cache a stub template, then run `fortressgd export` with a stub godot."""
        secret = bytes.fromhex(read_secret_file(root / ".fortressgd.secret"))
        cache = templates_cache_dir(root / "cache")
        cache.mkdir(parents=True, exist_ok=True)
        name = template_filename(
            "4.6.2", "linux", "x86_64", patchset_for_tag("4.6.2"), secret_hash(secret),
            require_signature=require_signature,
        )
        (cache / name).write_bytes(b"stub-template")
        bindir = root / "bin"
        _write_godot_stub_bin(bindir, root / "godot-env.json")
        env = base_env()
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        env.update(stub_env)
        return run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)

    def _set_verify_on_export(self, root: Path, enabled: bool) -> None:
        toml = root / ".fortressgd.toml"
        text = toml.read_text(encoding="utf-8")
        text = text.replace(
            "verify_on_export = true", "verify_on_export = {0}".format("true" if enabled else "false")
        )
        toml.write_text(text, encoding="utf-8")

    def test_export_runs_verify_and_fails_on_leak(self) -> None:
        for dialect in (False, True):
            with self.subTest(dialect=dialect), tempfile.TemporaryDirectory() as tmp:
                root = self._project(tmp)
                self._set_dialect(root, dialect)
                proc = self._export_with_stub(root, FGD_STUB_FILES="main.tscn,scripts/main.gd")
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn("scripts/main.gd", proc.stderr)
                self.assertIn("leaked", proc.stderr)

    def test_export_verify_passes_clean_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            proc = self._export_with_stub(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("ok: exported preset Linux", proc.stdout)
            self.assertIn("ok: no production leaks in game.x86_64 (2 packed files)", proc.stdout)

    def test_export_verify_off_skips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            self._set_verify_on_export(root, False)
            proc = self._export_with_stub(root, FGD_STUB_FILES="main.tscn,scripts/main.gd")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertNotIn("no production leaks", proc.stdout)

    def test_export_verify_absent_key_means_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            toml = root / ".fortressgd.toml"
            toml.write_text(
                toml.read_text(encoding="utf-8").replace("verify_on_export = true\n", ""), encoding="utf-8"
            )
            self.assertNotIn("verify_on_export", toml.read_text(encoding="utf-8"))
            proc = self._export_with_stub(root, FGD_STUB_FILES="main.tscn,scripts/main.gd")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)

    def test_export_verify_uses_sibling_pck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            proc = self._export_with_stub(root, FGD_STUB_SIBLING="1")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("ok: no production leaks in game.pck", proc.stdout)
            leak = self._export_with_stub(root, FGD_STUB_SIBLING="1", FGD_STUB_FILES="main.tscn,x.gd")
            self.assertEqual(leak.returncode, 2, leak.stdout + leak.stderr)
            self.assertIn("x.gd", leak.stderr)

    def test_export_verify_without_any_pack_names_both_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            proc = self._export_with_stub(root, FGD_STUB_NO_ARTIFACT="1")
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("game.x86_64", proc.stderr)
            self.assertIn("game.pck", proc.stderr)

    def test_export_fails_when_godot_leaves_no_artifact_even_without_verify(self) -> None:
        # The plugin deletes a refused artifact and Godot still exits 0.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            self._set_verify_on_export(root, False)
            proc = self._export_with_stub(root, FGD_STUB_NO_ARTIFACT="1")
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("produced no artifact", proc.stderr)
            self.assertNotIn("ok: exported", proc.stdout)


    def _enable_sign_packs(self, root: Path) -> None:
        toml = root / ".fortressgd.toml"
        toml.write_text(
            toml.read_text(encoding="utf-8").replace("sign_packs = false", "sign_packs = true"), encoding="utf-8"
        )

    def test_export_sign_packs_refuses_template_without_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            self._enable_sign_packs(root)
            proc = self._export_with_stub(root, require_signature=False)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("without the signature requirement", proc.stderr)
            self.assertIn("fortressgd templates build", proc.stderr)

    def test_export_sign_packs_signs_encrypted_pack_and_verify_checks_it(self) -> None:
        for dialect in (False, True):
            for sibling in ("", "1"):
                with self.subTest(dialect=dialect, sibling=bool(sibling)), tempfile.TemporaryDirectory() as tmp:
                    root = self._project(tmp)
                    self._set_dialect(root, dialect)
                    self._enable_sign_packs(root)
                    proc = self._export_with_stub(root, require_signature=True, FGD_STUB_SIBLING=sibling)
                    self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                    self.assertIn("no production leaks", proc.stdout)
                    pack = root / "build" / ("game.pck" if sibling or dialect else "game.x86_64")
                    data = bytearray(pack.read_bytes())
                    self.assertNotEqual(bytes(data[40:104]), b"\x00" * 64)
                    ok = run_fortressgd("verify", str(pack), cwd=root)
                    self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
                    # A zeroed signature no longer verifies.
                    data[40:104] = b"\x00" * 64
                    pack.write_bytes(bytes(data))
                    bad = run_fortressgd("verify", str(pack), cwd=root)
                    self.assertEqual(bad.returncode, 2, bad.stdout + bad.stderr)
                    self.assertIn("pack signature", bad.stderr)


    def test_export_without_export_path_fails_early(self) -> None:
        for presets in (PRESETS.replace('export_path="build/game.x86_64"\n', ""),
                        PRESETS.replace('export_path="build/game.x86_64"', 'export_path=""')):
            with tempfile.TemporaryDirectory() as tmp:
                root = self._project(tmp)
                self._set_dialect(root, False)
                (root / "export_presets.cfg").write_text(presets, encoding="utf-8")
                proc = self._export_with_stub(root)
                self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                self.assertIn('export preset "Linux" has no export path', proc.stderr)
                self.assertEqual((root / "export_presets.cfg").read_text(encoding="utf-8"), presets)
                self.assertFalse((root / "godot-env.json").exists(), "stub godot must not run")
                # The old behavior wrote <project-dir>.fortressgd.map.json beside the project.
                self.assertFalse(Path(str(root.resolve()) + ".fortressgd.map.json").exists())


    def test_export_warns_on_dotnet_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self._set_dialect(root, False)
            (root / ".godot" / "mono").mkdir(parents=True)
            proc = self._export_with_stub(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("warning: .NET project", proc.stderr)


if __name__ == "__main__":
    unittest.main()

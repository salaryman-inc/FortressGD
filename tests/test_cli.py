"""Subprocess tests against the shipped fortressgd command."""

from __future__ import annotations

import re
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from core.config import ALLOWED_KEYS, load_path, looks_like_secret_blob
from core.secret import ENV_NAME, SECRET_BYTES, SECRET_HEX_LEN
from tests.support import SAMPLE_PROJECT, base_env, run_fortressgd, write_godot_stub

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class CliTests(unittest.TestCase):
    def test_init_requires_godot_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_fortressgd("init", cwd=Path(tmp))
            self.assertEqual(proc.returncode, 1)
            combined = proc.stdout + proc.stderr
            self.assertIn("error:", combined)
            self.assertIn("Run:", combined)
            self.assertIn("fortressgd init", combined)

    def test_init_writes_toml_plugin_and_gitignore_suggestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            (root / ".gitignore").write_text("*.os\n", encoding="utf-8")
            proc = run_fortressgd("init", cwd=root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            combined = proc.stdout + proc.stderr
            self.assertIn(".fortressgd.secret", combined)
            toml_path = root / ".fortressgd.toml"
            self.assertTrue(toml_path.is_file())
            text = toml_path.read_text(encoding="utf-8")
            self.assertFalse(looks_like_secret_blob(text))
            self.assertNotIn("secret =", text.lower().replace(" ", ""))
            cfg = load_path(toml_path)
            self.assertEqual(set(cfg) - ALLOWED_KEYS["root"], set(ALLOWED_KEYS) - {"root"})
            for section, keys in ALLOWED_KEYS.items():
                if section == "root":
                    for key in keys:
                        self.assertIn(key, cfg)
                else:
                    self.assertIn(section, cfg)
                    for key in keys:
                        self.assertIn(key, cfg[section])
            plugin_cfg = root / "addons" / "fortressgd" / "plugin.cfg"
            plugin_gd = root / "addons" / "fortressgd" / "plugin.gd"
            self.assertTrue(plugin_cfg.is_file())
            self.assertIn("EditorPlugin", plugin_gd.read_text(encoding="utf-8"))
            gi = (root / ".gitignore").read_text(encoding="utf-8")
            self.assertIn(".fortressgd.secret", gi)

    def test_secret_generate_status_and_never_prints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            gen = run_fortressgd("secret", "generate", cwd=root)
            self.assertEqual(gen.returncode, 0, gen.stderr)
            secret_path = root / ".fortressgd.secret"
            self.assertTrue(secret_path.is_file())
            secret = secret_path.read_text(encoding="ascii").strip()
            self.assertEqual(len(secret), SECRET_HEX_LEN)
            self.assertTrue(_HEX64.fullmatch(secret))
            self.assertEqual(len(bytes.fromhex(secret)), SECRET_BYTES)
            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
            gen_out = gen.stdout + gen.stderr
            self.assertNotIn(secret, gen_out)
            status = run_fortressgd("secret", "status", cwd=root)
            self.assertEqual(status.returncode, 0, status.stderr)
            status_out = status.stdout + status.stderr
            self.assertIn("present", status_out)
            self.assertNotIn(secret, status_out)

    def test_secret_generate_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            first = run_fortressgd("secret", "generate", cwd=root)
            self.assertEqual(first.returncode, 0, first.stderr)
            secret_path = root / ".fortressgd.secret"
            before = secret_path.read_text(encoding="ascii")
            second = run_fortressgd("secret", "generate", cwd=root)
            self.assertEqual(second.returncode, 1, second.stdout)
            self.assertIn("--force", second.stderr)
            self.assertIn("already exists", second.stderr)
            self.assertNotIn(before.strip(), second.stdout + second.stderr)
            self.assertEqual(secret_path.read_text(encoding="ascii"), before)

    def test_secret_generate_force_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            self.assertEqual(run_fortressgd("secret", "generate", cwd=root).returncode, 0)
            secret_path = root / ".fortressgd.secret"
            before = secret_path.read_text(encoding="ascii")
            forced = run_fortressgd("secret", "generate", "--force", cwd=root)
            self.assertEqual(forced.returncode, 0, forced.stderr)
            after = secret_path.read_text(encoding="ascii")
            self.assertNotEqual(after, before)
            self.assertEqual(len(after.strip()), SECRET_HEX_LEN)
            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)

    def test_secret_status_missing_and_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = run_fortressgd("secret", "status", cwd=root)
            self.assertEqual(missing.returncode, 0, missing.stderr)
            miss_out = missing.stdout + missing.stderr
            self.assertIn("missing", miss_out)
            self.assertIn("Run:", miss_out)
            self.assertIn("fortressgd secret generate", miss_out)
            env = base_env()
            # Generate via --secret-file so cwd has no default file.
            other = root / "elsewhere.secret"
            gen = run_fortressgd(
                "--secret-file",
                str(other),
                "secret",
                "generate",
                cwd=root,
            )
            self.assertEqual(gen.returncode, 0, gen.stderr)
            secret = other.read_text(encoding="ascii").strip()
            self.assertNotIn(secret, gen.stdout + gen.stderr)
            env[ENV_NAME] = secret
            present = run_fortressgd("secret", "status", cwd=root, env=env)
            self.assertEqual(present.returncode, 0, present.stderr)
            present_out = present.stdout + present.stderr
            self.assertIn("present", present_out)
            self.assertIn(ENV_NAME, present_out)
            self.assertNotIn(secret, present_out)

    def test_doctor_valid_toml_ok_unknown_key_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            init = run_fortressgd("init", cwd=root)
            self.assertEqual(init.returncode, 0, init.stderr)
            ok = run_fortressgd("doctor", cwd=root)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            toml_path = root / ".fortressgd.toml"
            with toml_path.open("a", encoding="utf-8") as fh:
                fh.write("\n[bogus]\nnope = 1\n")
            bad = run_fortressgd("doctor", cwd=root)
            self.assertEqual(bad.returncode, 1)
            combined = bad.stdout + bad.stderr
            self.assertIn("bogus", combined)
            self.assertIn("error:", combined)
            self.assertIn("Run:", combined)
            self.assertRegex(combined, r"Run:\s*fortressgd\s+\S+")

    def test_doctor_warns_if_plugin_differs_from_cli_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
            plugin_gd = root / "addons" / "fortressgd" / "plugin.gd"
            plugin_gd.write_text(
                plugin_gd.read_text(encoding="utf-8") + "\n# drift\n",
                encoding="utf-8",
            )
            doc = run_fortressgd("doctor", cwd=root)
            self.assertEqual(doc.returncode, 0, doc.stderr)
            combined = doc.stdout + doc.stderr
            self.assertIn("warning", combined.lower())
            self.assertIn("differ", combined.lower())
            self.assertIn("Run:", combined)
            self.assertIn("fortressgd init", combined)

    def test_user_path_on_sample_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "sample"
            shutil.copytree(SAMPLE_PROJECT, root)
            init = run_fortressgd("init", cwd=root)
            self.assertEqual(init.returncode, 0, init.stderr)
            gen = run_fortressgd("secret", "generate", cwd=root)
            self.assertEqual(gen.returncode, 0, gen.stderr)
            secret = (root / ".fortressgd.secret").read_text(encoding="ascii").strip()
            status = run_fortressgd("secret", "status", cwd=root)
            self.assertEqual(status.returncode, 0)
            self.assertIn("present", status.stdout + status.stderr)
            self.assertNotIn(secret, status.stdout + status.stderr)
            doc = run_fortressgd("doctor", cwd=root)
            self.assertEqual(doc.returncode, 0, doc.stderr)


if __name__ == "__main__":
    unittest.main()

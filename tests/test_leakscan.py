"""Secret-material scan for build outputs, logs, and the template cache (issue #38)."""

from __future__ import annotations

import io
import os
import stat
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from core import leakscan
from core.errors import ToolError
from core.pack_dialect import dialect_key_for_secret
from core.secret import ENV_NAME, generate_secret_hex, secret_bytes_from_hex, write_secret_file
from core.templates import build_templates
from tests.support import ROOT

FAKE_DOCKER = """#!{python}
import os, sys
from pathlib import Path
sys.path.insert(0, {root!r})
from core.kdf import secret_hash
from core.templates import manifest_dict, template_filename, write_manifest

args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    sys.exit(0)
env, vols = {{}}, {{}}
i = 1
while i < len(args):
    if args[i] == "-e":
        key, value = args[i + 1].split("=", 1)
        env[key] = value
        i += 2
    elif args[i] == "-v":
        parts = args[i + 1].split(":")
        vols[parts[1]] = parts[0]
        i += 2
    else:
        i += 1
hex_secret = Path(vols["/run/secrets/fortressgd"]).read_text().strip()
mode = os.environ.get("FAKE_DOCKER_LEAK", "")
if mode == "stderr":
    sys.stderr.write("scons: debug FORTRESSGD_SECRET=" + hex_secret + "\\n")
    sys.exit(2)
sh = secret_hash(bytes.fromhex(hex_secret))
name = template_filename(env["FGD_GODOT"], env["FGD_PLATFORM"], env["FGD_ARCH"], env["FGD_PATCHSET"], sh)
out = Path(vols["/out"])
body = b"\\x7fELF fake template"
if mode == "binary":
    body += b"\\x00" + bytes.fromhex(hex_secret)
(out / name).write_bytes(body)
write_manifest(
    out / (name + ".manifest.json"),
    manifest_dict(godot=env["FGD_GODOT"], patchset=env["FGD_PATCHSET"], secrethash=sh,
                  dialect=env["FGD_DIALECT_ID"], platform=env["FGD_PLATFORM"]),
)
"""


class LeakScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hex_secret = generate_secret_hex()
        self.secret = secret_bytes_from_hex(self.hex_secret)
        self.needles = leakscan.secret_needles(self.secret, "4.6.2")

    def test_finds_secret_and_derived_key_in_every_encoding(self) -> None:
        key = dialect_key_for_secret(self.secret, "4.6.2")
        samples = {
            "hex.log": b"step 3: " + self.hex_secret.encode() + b"\n",
            "upper.log": self.hex_secret.upper().encode(),
            "raw.bin": b"\x00" * 100 + self.secret,
            "utf16.txt": self.hex_secret.encode("utf-16-le"),
            "key.json": b'{"debug": "' + key.hex().encode() + b'"}',
            "keyraw.bin": b"MZ" + key,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, data in samples.items():
                (root / name).write_bytes(data)
            (root / "clean.txt").write_text("nothing here " + "ab" * 40, encoding="ascii")
            leaks = leakscan.scan_paths([root], self.needles)
            self.assertEqual({leak.path.name for leak in leaks}, set(samples))
            self.assertIn(("raw.bin", 100), {(l.path.name, l.offset) for l in leaks})
            report = leakscan.format_leaks(leaks)
            self.assertNotIn(self.hex_secret, report)
            self.assertNotIn(key.hex(), report)
            self.assertIn("derived AES key", report)

    def test_redact_removes_secret_text(self) -> None:
        text = "boom " + self.hex_secret + " / " + self.hex_secret.upper()
        out = leakscan.redact(text, self.needles)
        self.assertNotIn(self.hex_secret, out.lower())
        self.assertIn("***", out)

    def test_cli_deletes_offending_files_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "manifest.json"
            bad.write_text('{"secret_debug": "' + self.hex_secret + '"}', encoding="ascii")
            good = root / "template.bin"
            good.write_bytes(b"\x7fELF clean")
            err, out = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, {ENV_NAME: self.hex_secret}), redirect_stderr(err), redirect_stdout(out):
                code = leakscan.main(["--godot", "4.6.2", "--delete", str(root)])
            self.assertEqual(code, 1)
            self.assertFalse(bad.exists())
            self.assertTrue(good.exists())
            self.assertIn("manifest.json", err.getvalue())
            self.assertNotIn(self.hex_secret, err.getvalue() + out.getvalue())
            with mock.patch.dict(os.environ, {ENV_NAME: self.hex_secret}), redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(leakscan.main([str(root)]), 0)

    def test_scan_of_large_output_is_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "template"
            big.write_bytes(os.urandom(64 * 1024 * 1024))
            start = time.monotonic()
            leakscan.scan_paths([big], self.needles)
            self.assertLess(time.monotonic() - start, 5.0)


class TemplatesBuildLeakGuardTests(unittest.TestCase):
    """build_templates against a stub `docker` that can plant the secret in its output."""

    def _run_build(self, mode: str) -> tuple[Path, str]:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        tmp = Path(holder.name)
        bindir = tmp / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(FAKE_DOCKER.format(python=sys.executable, root=str(ROOT)), encoding="utf-8")
        docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
        hex_secret = generate_secret_hex()
        secret_file = tmp / "secret"
        write_secret_file(secret_file, hex_secret)
        env = {"PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""), "FAKE_DOCKER_LEAK": mode}
        cache = tmp / "cache"
        with mock.patch.dict(os.environ, env):
            try:
                build_templates(
                    godot="4.6.2",
                    platforms=["linux"],
                    secret_file=str(secret_file),
                    environ={},
                    cwd=tmp,
                    cache_dir=cache,
                )
            except ToolError as err:
                return cache, hex_secret + "|" + err.format()
        return cache, hex_secret + "|"

    def _cached(self, cache: Path) -> list[str]:
        directory = cache / "templates"
        return sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []

    def test_clean_build_is_cached(self) -> None:
        cache, result = self._run_build("")
        _secret, error = result.split("|", 1)
        self.assertEqual(error, "")
        self.assertEqual(len(self._cached(cache)), 2)

    def test_planted_secret_aborts_cache_write(self) -> None:
        cache, result = self._run_build("binary")
        hex_secret, error = result.split("|", 1)
        self.assertIn("refusing to cache", error)
        self.assertIn("project secret", error)
        self.assertNotIn(hex_secret, error)
        self.assertEqual(self._cached(cache), [])

    def test_failed_container_output_is_redacted(self) -> None:
        _cache, result = self._run_build("stderr")
        hex_secret, error = result.split("|", 1)
        self.assertIn("template build failed", error)
        self.assertIn("***", error)
        self.assertNotIn(hex_secret, error)


if __name__ == "__main__":
    unittest.main()

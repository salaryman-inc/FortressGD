"""Direct tests of secret generate/status helpers."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.secret import (
    ENV_NAME,
    SECRET_BYTES,
    SECRET_HEX_LEN,
    generate_secret_hex,
    secret_status,
    secret_weakness,
    write_secret_file,
)
from core.errors import UserError


class SecretHelperTests(unittest.TestCase):
    def test_generate_is_32_bytes_64_hex(self) -> None:
        value = generate_secret_hex()
        self.assertEqual(len(value), SECRET_HEX_LEN)
        decoded = bytes.fromhex(value)
        self.assertEqual(len(decoded), SECRET_BYTES)
        other = generate_secret_hex()
        self.assertNotEqual(value, other)

    def test_write_secret_file_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "custom.secret"
            value = generate_secret_hex()
            write_secret_file(path, value)
            on_disk = path.read_text(encoding="ascii").strip()
            self.assertEqual(on_disk, value)
            self.assertEqual(len(bytes.fromhex(on_disk)), SECRET_BYTES)
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_write_secret_file_refuses_existing_unless_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".fortressgd.secret"
            first = generate_secret_hex()
            write_secret_file(path, first)
            with self.assertRaises(UserError) as ctx:
                write_secret_file(path, generate_secret_hex())
            self.assertIn("already exists", str(ctx.exception))
            self.assertIn("--force", ctx.exception.next_command)
            self.assertEqual(path.read_text(encoding="ascii").strip(), first)
            second = generate_secret_hex()
            write_secret_file(path, second, overwrite=True)
            self.assertEqual(path.read_text(encoding="ascii").strip(), second)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_secret_weakness_flags_placeholders_not_random(self) -> None:
        for weak in ("00" * 32, "ff" * 32, "deadbeef" * 8, "0123456789abcdef" * 4, "0001" * 16):
            self.assertIsNotNone(secret_weakness(weak), weak[:8])
        for _ in range(200):
            self.assertIsNone(secret_weakness(generate_secret_hex()))

    def test_status_present_file_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            missing = secret_status(cwd=cwd, environ={})
            self.assertEqual(missing["state"], "missing")
            path = cwd / ".fortressgd.secret"
            value = generate_secret_hex()
            write_secret_file(path, value)
            present = secret_status(cwd=cwd, environ={})
            self.assertEqual(present["state"], "present")
            self.assertEqual(present["source"], "file")
            self.assertNotIn(value, str(present))

    def test_status_environment(self) -> None:
        value = generate_secret_hex()
        with tempfile.TemporaryDirectory() as tmp:
            info = secret_status(cwd=Path(tmp), environ={ENV_NAME: value})
            self.assertEqual(info["state"], "present")
            self.assertEqual(info["source"], "environment")
            self.assertNotIn(value, str(info))


if __name__ == "__main__":
    unittest.main()

"""Direct tests of the shared toml parse/validate helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.config import ConfigError, default_toml_text, load_path, parse_toml, validate
from core.errors import NEXT_DOCTOR
from tests.support import ROOT


class ConfigTests(unittest.TestCase):
    def test_example_round_trip_validate(self) -> None:
        text = default_toml_text()
        data = validate(parse_toml(text))
        self.assertEqual(data["schema"], 1)
        self.assertIsInstance(data["godot"], str)
        self.assertTrue(data["production"]["verify_on_export"])
        self.assertEqual(data["filters"]["include"], [])
        self.assertIn("windows", data["platforms"]["build"])

    def test_unknown_key_is_error_with_next_command(self) -> None:
        data = parse_toml(default_toml_text())
        data["not_a_real_key"] = 1
        with self.assertRaises(ConfigError) as ctx:
            validate(data)
        self.assertIn("not_a_real_key", str(ctx.exception))
        self.assertEqual(ctx.exception.next_command, NEXT_DOCTOR)
        self.assertIn("Run: fortressgd doctor", ctx.exception.format())

    def test_unknown_nested_key_is_error(self) -> None:
        data = parse_toml(default_toml_text())
        data["production"]["explode"] = True
        with self.assertRaises(ConfigError) as ctx:
            validate(data)
        self.assertIn("production.explode", str(ctx.exception))

    def test_load_path_rejects_unknown_key_in_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".fortressgd.toml"
            path.write_text(default_toml_text() + "\nnope = 1\n", encoding="utf-8")
            with self.assertRaises(ConfigError) as ctx:
                load_path(path)
            self.assertIn("nope", str(ctx.exception))

    def test_duplicate_key_in_table_is_error(self) -> None:
        text = 'schema = 1\ngodot = "4.6.2"\n[production]\ndialect = true\nmangle_scripts = true\ndialect = false\n'
        with self.assertRaises(ConfigError) as ctx:
            parse_toml(text)
        self.assertEqual(str(ctx.exception), "duplicate key production.dialect in .fortressgd.toml")
        self.assertIn("Run: fortressgd doctor", ctx.exception.format())

    def test_duplicate_root_key_is_error(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            parse_toml('schema = 1\ngodot = "4.6.2"\ngodot = "4.7.2"\n')
        self.assertEqual(str(ctx.exception), "duplicate key godot in .fortressgd.toml")

    def test_same_key_in_different_tables_is_allowed(self) -> None:
        data = parse_toml("[a]\nx = 1\n[b]\nx = 2\n")
        self.assertEqual(data, {"a": {"x": 1}, "b": {"x": 2}})

    def test_parser_matches_stdlib_tomllib_on_example(self) -> None:
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib not available")
        raw = (ROOT / ".fortressgd.example.toml").read_text(encoding="utf-8")
        std = tomllib.loads(raw)
        ours = parse_toml(raw)
        self.assertEqual(ours, std)


if __name__ == "__main__":
    unittest.main()

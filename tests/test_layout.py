"""Layout and plugin source checks for DESIGN.md Phase 0."""

from __future__ import annotations

import json
import unittest

from tests.support import ROOT, SAMPLE_PROJECT

from core.config import ALLOWED_KEYS, load_path, load_schema_file, looks_like_secret_blob, parse_toml


class LayoutTests(unittest.TestCase):
    def test_design_and_threat_model_remain(self) -> None:
        self.assertTrue((ROOT / "DESIGN.md").is_file())
        self.assertTrue((ROOT / "THREAT_MODEL.md").is_file())

    def test_example_toml_has_section6_keys_and_no_secret(self) -> None:
        path = ROOT / ".fortressgd.example.toml"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("secret =", text.lower().replace(" ", ""))
        self.assertFalse(looks_like_secret_blob(text))
        data = parse_toml(text)
        self.assertEqual(set(data) - set(ALLOWED_KEYS["root"]), set(ALLOWED_KEYS) - {"root"})
        self.assertEqual(set(data["production"]), ALLOWED_KEYS["production"])
        self.assertEqual(set(data["filters"]), ALLOWED_KEYS["filters"])
        self.assertEqual(set(data["platforms"]), ALLOWED_KEYS["platforms"])
        self.assertEqual(set(data["templates"]), ALLOWED_KEYS["templates"])
        validated = load_path(path)
        self.assertEqual(validated["schema"], 1)

    def test_schema_json_matches_python_allowed_keys(self) -> None:
        schema = load_schema_file()
        self.assertEqual({k: frozenset(v) for k, v in schema.items()}, ALLOWED_KEYS)

    def test_sample_project_is_tiny_2d(self) -> None:
        self.assertTrue((SAMPLE_PROJECT / "project.godot").is_file())
        scenes = list(SAMPLE_PROJECT.glob("*.tscn")) + list(SAMPLE_PROJECT.glob("**/*.tscn"))
        scripts = [
            p
            for p in list(SAMPLE_PROJECT.glob("*.gd")) + list(SAMPLE_PROJECT.glob("**/*.gd"))
            if p.name != "plugin.gd"
        ]
        self.assertEqual(len({p.resolve() for p in scenes}), 1, "expected exactly one scene")
        self.assertEqual(len({p.resolve() for p in scripts}), 1, "expected exactly one script")
        scene_text = scenes[0].read_text(encoding="utf-8")
        self.assertIn("Node2D", scene_text)
        godot = (SAMPLE_PROJECT / "project.godot").read_text(encoding="utf-8")
        self.assertIn("config_version=5", godot)

    def test_plugin_is_godot_editor_plugin_that_reads_toml(self) -> None:
        addon = ROOT / "plugin" / "addons" / "fortressgd"
        cfg = (addon / "plugin.cfg").read_text(encoding="utf-8")
        self.assertIn('script="plugin.gd"', cfg)
        self.assertIn("version=", cfg)
        plugin_gd = (addon / "plugin.gd").read_text(encoding="utf-8")
        self.assertIn("extends EditorPlugin", plugin_gd)
        self.assertIn("config.gd", plugin_gd)
        config_gd = (addon / "config.gd").read_text(encoding="utf-8")
        self.assertIn(".fortressgd.toml", config_gd)
        self.assertIn("unknown key", config_gd)
        self.assertIn("load_project_toml", config_gd)
        schema = json.loads((addon / "schema.json").read_text(encoding="utf-8"))
        self.assertIn("root", schema)


if __name__ == "__main__":
    unittest.main()

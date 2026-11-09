"""Layout and plugin source checks for DESIGN.md Phase 0–1."""

from __future__ import annotations

import json
import re
import unittest

from tests.support import PKG, ROOT, SAMPLE_PROJECT

from fortressgd.core.config import ALLOWED_KEYS, load_path, load_schema_file, looks_like_secret_blob, parse_toml


class LayoutTests(unittest.TestCase):
    def test_design_and_threat_model_remain(self) -> None:
        self.assertTrue((ROOT / "DESIGN.md").is_file())
        self.assertTrue((ROOT / "THREAT_MODEL.md").is_file())

    def test_project_documents_exist(self) -> None:
        for name in ("LICENSE", "README.md", "SECURITY.md", "CONTRIBUTING.md"):
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file())

    def test_plugin_version_matches_package_version(self) -> None:
        from fortressgd import __version__

        cfg = (PKG / "plugin" / "addons" / "fortressgd" / "plugin.cfg").read_text(encoding="utf-8")
        self.assertIn('version="{0}"'.format(__version__), cfg)
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        # pyproject reads the version from fortressgd/core/version.py.
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn('attr = "fortressgd.core.version.__version__"', pyproject)

    def test_shipped_data_lives_inside_the_package(self) -> None:
        # fortressgd/core/paths.py resolves these inside the installed package;
        # a copy at the repository root would be stale and never shipped.
        from fortressgd.core import paths

        self.assertEqual(paths.package_root(), PKG.resolve())
        self.assertTrue((paths.plugin_source_dir() / "plugin.cfg").is_file())
        self.assertTrue(paths.example_toml_path().is_file())
        self.assertTrue((paths.docker_dir() / "Dockerfile.templates").is_file())
        self.assertTrue((paths.patches_root() / "common").is_dir())
        for stale in ("plugin", "patches", "docker", "core", "cli", "generator", ".fortressgd.example.toml"):
            with self.subTest(stale=stale):
                self.assertFalse((ROOT / stale).exists())

    def test_example_toml_has_section6_keys_and_no_secret(self) -> None:
        path = PKG / "fortressgd.example.toml"
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
        addon = PKG / "plugin" / "addons" / "fortressgd"
        cfg = (addon / "plugin.cfg").read_text(encoding="utf-8")
        self.assertIn('script="plugin.gd"', cfg)
        self.assertIn("version=", cfg)
        plugin_gd = (addon / "plugin.gd").read_text(encoding="utf-8")
        self.assertIn("extends EditorPlugin", plugin_gd)
        self.assertIn("config.gd", plugin_gd)
        self.assertIn("add_export_plugin", plugin_gd)
        self.assertIn("export_plugin.gd", plugin_gd)
        config_gd = (addon / "config.gd").read_text(encoding="utf-8")
        self.assertIn(".fortressgd.toml", config_gd)
        self.assertIn("unknown key", config_gd)
        self.assertIn("load_project_toml", config_gd)
        schema = json.loads((addon / "schema.json").read_text(encoding="utf-8"))
        self.assertIn("root", schema)

    def test_export_plugin_skips_section_6_3_on_production_tag(self) -> None:
        addon = PKG / "plugin" / "addons" / "fortressgd"
        export_gd = (addon / "export_plugin.gd").read_text(encoding="utf-8")
        self.assertIn("extends EditorExportPlugin", export_gd)
        self.assertIn("_export_file", export_gd)
        self.assertIn("skip()", export_gd)
        self.assertIn("fortressgd_production", export_gd)
        filters_gd = (addon / "filters.gd").read_text(encoding="utf-8")
        self.assertIn("should_skip_forced", filters_gd)
        self.assertIn("filters.json", filters_gd)
        for pattern in (
            "*.cs",
            "*.gd",
            "*.sln",
            "*.csproj",
            "*.blend",
            "*.psd",
            "*.kra",
            "*.tmp",
            "addons/fortressgd/**",
            "*.fortressgd.map.json",
        ):
            self.assertIn('"{0}"'.format(pattern), (addon / "filters.json").read_text(encoding="utf-8"))

    def test_export_plugin_runs_on_both_sides_of_godots_gdscript_plugin(self) -> None:
        """Godot sorts export plugins by name and stops at the first skip or remap.

        Its GDScript plugin ("GDScript", modules/gdscript/register_types.cpp) remaps
        every *.gd, so a plugin sorted after it never sees a script.
        """
        addon = PKG / "plugin" / "addons" / "fortressgd"
        export_gd = (addon / "export_plugin.gd").read_text(encoding="utf-8")
        early = re.search(r'const EARLY_NAME := "([^"]+)"', export_gd).group(1)
        late = re.search(r'const LATE_NAME := "([^"]+)"', export_gd).group(1)
        self.assertLess(early, "GDScript")
        self.assertLess("GDScript", late)
        self.assertIn("return LATE_NAME if _late else EARLY_NAME", export_gd)
        plugin_gd = (addon / "plugin.gd").read_text(encoding="utf-8")
        self.assertIn("FGDExportPlugin.new()", plugin_gd)
        self.assertIn("FGDExportPlugin.new(true)", plugin_gd)
        self.assertEqual(plugin_gd.count("add_export_plugin("), 2)
        self.assertEqual(plugin_gd.count("remove_export_plugin("), 2)
        # The early instance keeps scripts that only "*.gd" excludes, for bytecode;
        # the late one drops whatever text is left.
        self.assertIn("should_skip_before_bytecode(path, _include, _exclude)", export_gd)
        filters_gd = (addon / "filters.gd").read_text(encoding="utf-8")
        start = filters_gd.index("static func should_skip_before_bytecode")
        body = filters_gd[start : filters_gd.index("\nstatic func ", start + 1)]
        self.assertIn("should_skip_forced(path, include_patterns, exclude_patterns)", body)
        self.assertIn("pat != TEXT_SCRIPT_PATTERN", body)
        self.assertIn('const TEXT_SCRIPT_PATTERN := "*.gd"', filters_gd)
        # Only the early instance mangles, writes the map or refuses the artifact.
        end = export_gd[export_gd.index("func _export_end") :]
        self.assertTrue(end.split("\n", 2)[1].strip() == "if _late:", end[:80])

    def test_plugin_secret_order_matches_cli(self) -> None:
        export_gd = (PKG / "plugin" / "addons" / "fortressgd" / "export_plugin.gd").read_text(
            encoding="utf-8"
        )
        start = export_gd.index("func _load_secret_hex")
        end = export_gd.find("\nfunc ", start + 1)
        body = export_gd[start : end if end != -1 else len(export_gd)]
        body = "\n".join(
            line for line in body.splitlines() if not line.strip().startswith("#")
        )
        file_pos = body.index(".fortressgd.secret")
        env_pos = body.index("FORTRESSGD_SECRET")
        self.assertLess(file_pos, env_pos, "plugin must read the file before the env var, like the CLI")

    def test_plugin_toml_parser_rejects_duplicates_like_cli(self) -> None:
        config_gd = (PKG / "plugin" / "addons" / "fortressgd" / "config.gd").read_text(encoding="utf-8")
        start = config_gd.index("static func _parse_toml")
        body = config_gd[start : config_gd.index("\nstatic func ", start + 1)]
        self.assertIn('"duplicate key %s in %s"', body)
        self.assertIn("current.has(key)", body)
        self.assertIn('"duplicate table [%s] in %s"', body)
        self.assertIn('"empty key in %s"', body)
        self.assertIn('"empty table name in %s"', body)

    def test_plugin_fails_closed_on_config_error_for_production(self) -> None:
        export_gd = (PKG / "plugin" / "addons" / "fortressgd" / "export_plugin.gd").read_text(encoding="utf-8")
        start = export_gd.index("func _export_begin")
        body = export_gd[start : export_gd.index("\nfunc ", start + 1)]
        load_at = body.index("FGDConfig.load_project_toml()")
        failure = body[load_at : body.index("var data", load_at)]
        self.assertIn('if not result.get("ok", false):', failure)
        self.assertIn("features.has(FGDFilters.production_feature_tag())", failure)
        self.assertIn("push_error", failure)
        self.assertIn("_mangle_abort = true", failure)

    def test_plugin_applies_custom_excludes(self) -> None:
        addon = PKG / "plugin" / "addons" / "fortressgd"
        export_gd = (addon / "export_plugin.gd").read_text(encoding="utf-8")
        self.assertIn('filters.get("exclude", [])', export_gd)
        self.assertIn("should_skip_forced(path, _include, _exclude)", export_gd)
        filters_gd = (addon / "filters.gd").read_text(encoding="utf-8")
        self.assertRegex(
            filters_gd,
            r"static func should_skip_forced\(path: String, include_patterns: PackedStringArray, exclude_patterns",
        )
        start = filters_gd.index("static func should_skip_forced")
        body = filters_gd[start : filters_gd.index("\nstatic func ", start + 1)]
        self.assertIn("for pat in exclude_patterns:", body)
        # include is checked first, so it overrides both forced and custom excludes
        self.assertLess(body.index("include_patterns:"), body.index("forced_exclude_patterns()"))

    def test_getting_started_covers_verify_without_custom_templates(self) -> None:
        path = ROOT / "docs" / "getting-started.md"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        lower = text.lower()
        self.assertIn("fortressgd verify", lower)
        self.assertIn("fortressgd_production", text)
        self.assertIn("official", lower)
        self.assertTrue(
            "not required" in lower or "without custom templates" in lower,
            "getting-started must not make custom templates a prerequisite",
        )
        self.assertNotRegex(
            text,
            r"(?i)first\s+run\s+`?fortressgd templates build",
        )


if __name__ == "__main__":
    unittest.main()

"""Unit tests for shipped DESIGN.md §6.3 matching (core.filters)."""

from __future__ import annotations

import json
import unittest

from fortressgd.core.filters import (
    find_leaks,
    forced_exclude_patterns,
    glob_match,
    load_filters_file,
    production_feature_tag,
    effective_exclude_patterns,
    should_force_exclude,
    spec_forced_exclude_patterns,
)
from tests.support import PKG, ROOT


class FilterMatchTests(unittest.TestCase):
    def test_shipped_patterns_match_design_section_6_3(self) -> None:
        self.assertEqual(forced_exclude_patterns(), spec_forced_exclude_patterns())
        data = load_filters_file()
        self.assertEqual(tuple(data["forced_exclude"]), spec_forced_exclude_patterns())
        self.assertEqual(production_feature_tag(), "fortressgd_production")
        plugin_json = json.loads(
            (PKG / "plugin" / "addons" / "fortressgd" / "filters.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(plugin_json, data)

    def test_gd_and_cs_match_nested_and_res_paths(self) -> None:
        self.assertTrue(glob_match("main.gd", "*.gd"))
        self.assertTrue(glob_match("res://scripts/player.gd", "*.gd"))
        self.assertTrue(glob_match("src/Foo.cs", "*.cs"))
        self.assertFalse(glob_match("main.gdc", "*.gd"))
        self.assertFalse(glob_match("main.tscn", "*.gd"))

    def test_dcc_and_map_and_addon_tree(self) -> None:
        self.assertTrue(glob_match("art/hero.blend", "*.blend"))
        self.assertTrue(glob_match("tex.psd", "*.psd"))
        self.assertTrue(glob_match("paint.kra", "*.kra"))
        self.assertTrue(glob_match("scratch.tmp", "*.tmp"))
        self.assertTrue(glob_match("Game.sln", "*.sln"))
        self.assertTrue(glob_match("Game.csproj", "*.csproj"))
        self.assertTrue(glob_match("export.fortressgd.map.json", "*.fortressgd.map.json"))
        self.assertTrue(glob_match("addons/fortressgd/plugin.gd", "addons/fortressgd/**"))
        self.assertTrue(glob_match("res://addons/fortressgd/export_plugin.gd", "addons/fortressgd/**"))
        self.assertFalse(glob_match("addons/other/mod.gd", "addons/fortressgd/**"))

    def test_clean_pack_has_no_leaks(self) -> None:
        leaks = find_leaks(["main.tscn", "main.gdc", "icon.svg", "project.binary"])
        self.assertEqual(leaks, [])

    def test_each_forced_kind_is_a_leak(self) -> None:
        cases = [
            ("scripts/main.gd", "*.gd"),
            ("Net.cs", "*.cs"),
            ("scene.blend", "*.blend"),
            ("out.fortressgd.map.json", "*.fortressgd.map.json"),
            ("addons/fortressgd/plugin.cfg", "addons/fortressgd/**"),
        ]
        for path, pattern in cases:
            with self.subTest(path=path):
                leaks = find_leaks(["main.tscn", path])
                self.assertEqual(len(leaks), 1, leaks)
                self.assertEqual(leaks[0].path, path)
                self.assertEqual(leaks[0].pattern, pattern)

    def test_include_allowlist_exempts_pattern(self) -> None:
        leaks = find_leaks(["mods/hook.gd", "secret.cs"], include=["*.gd"])
        self.assertEqual([x.path for x in leaks], ["secret.cs"])
        self.assertFalse(should_force_exclude("mods/hook.gd", include=["*.gd"]))
        self.assertTrue(should_force_exclude("secret.cs", include=["*.gd"]))

    def test_include_specific_path_does_not_exempt_others(self) -> None:
        leaks = find_leaks(["keep.gd", "drop.gd"], include=["keep.gd"])
        self.assertEqual([x.path for x in leaks], ["drop.gd"])


    def test_custom_exclude_is_a_leak(self) -> None:
        leaks = find_leaks(["main.tscn", "design_docs/notes.txt"], exclude=["design_docs/*"])
        self.assertEqual([(l.path, l.pattern) for l in leaks], [("design_docs/notes.txt", "design_docs/*")])
        self.assertTrue(should_force_exclude("design_docs/notes.txt", exclude=["design_docs/*"]))
        self.assertEqual(find_leaks(["design_docs/notes.txt"]), [])

    def test_include_overrides_custom_exclude(self) -> None:
        leaks = find_leaks(
            ["design_docs/notes.txt", "design_docs/credits.txt"],
            include=["design_docs/credits.txt"],
            exclude=["design_docs/*"],
        )
        self.assertEqual([l.path for l in leaks], ["design_docs/notes.txt"])

    def test_forced_pattern_reported_before_duplicate_custom_one(self) -> None:
        leaks = find_leaks(["main.gd"], exclude=["*.gd", "*.gd"])
        self.assertEqual(leaks[0].pattern, "*.gd")
        self.assertEqual(effective_exclude_patterns(["*.gd", "x/*", "x/*"]).count("*.gd"), 1)
        merged = effective_exclude_patterns(["x/*", "x/*"])
        self.assertEqual(merged.count("x/*"), 1)
        self.assertEqual(merged[-1], "x/*")


if __name__ == "__main__":
    unittest.main()

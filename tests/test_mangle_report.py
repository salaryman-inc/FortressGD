"""fortressgd mangle-report: what mangling leaves readable, and why."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.mangle import (
    collect_resource_reference_names,
    collect_scan_only_names,
    iter_gdscript_files,
    iter_scan_only_gdscript_files,
    mangle_scripts,
)
from fortressgd.core.mangle_report import (
    ADDON,
    CLASS_NAME,
    EXPORT,
    FOREIGN,
    KEEP,
    SCENE,
    STRING,
    analyze_project,
)
from tests.support import base_env, run_fortressgd, write_godot_stub
from tests import test_mangle as mangle_tests

PLAYER = """class_name Hero
extends CharacterBody2D

@export var speed := 200.0
var hit_points := 3
var secret_combo := 0
## fortressgd:keep
var mod_hook_state := 1


func take_damage(amount: int) -> void:
\thit_points -= amount
\tsecret_combo = 0


func _on_door_opened() -> void:
\tpass


func talk(npc) -> void:
\tnpc.greeting = "hi"
\temit_signal("combo_finished")
"""

ENEMY = """extends Node

var greeting := ""
var patrol_radius := 50.0
signal combo_finished
"""

SCENE_TEXT = """[gd_scene format=3]

[node name="Door" type="Area2D"]

[connection signal="opened" from="Door" to="." method="_on_door_opened"]
"""

ADDON_SCRIPT = """extends Node

func poke(target) -> void:
\ttarget.call_deferred("patrol_radius")
"""


def _write_project(root: Path) -> None:
    write_godot_stub(root)
    (root / "player.gd").write_text(PLAYER, encoding="utf-8")
    (root / "enemy.gd").write_text(ENEMY, encoding="utf-8")
    (root / "main.tscn").write_text(SCENE_TEXT, encoding="utf-8")
    addon = root / "addons" / "helper" / "helper.gd"
    addon.parent.mkdir(parents=True)
    addon.write_text(ADDON_SCRIPT, encoding="utf-8")


class MangleReportAnalysisTests(unittest.TestCase):
    def test_every_reason_is_reported_with_its_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_project(root)
            report = analyze_project(root)
            kept = report.kept
            self.assertEqual(kept["speed"], {EXPORT: ["player.gd"]})
            self.assertEqual(kept["Hero"], {CLASS_NAME: ["player.gd"]})
            self.assertEqual(kept["mod_hook_state"], {KEEP: ["player.gd"]})
            self.assertEqual(kept["_on_door_opened"], {SCENE: ["main.tscn"]})
            self.assertEqual(kept["greeting"], {FOREIGN: ["player.gd"]})
            self.assertEqual(kept["combo_finished"], {STRING: ["player.gd"]})
            self.assertEqual(kept["patrol_radius"], {ADDON: ["addons/helper/helper.gd"]})
            for name in ("hit_points", "secret_combo", "take_damage", "talk", "amount", "npc"):
                with self.subTest(name=name):
                    self.assertIn(name, report.renamed)
                    self.assertNotIn(name, kept)

    def test_report_matches_what_export_renames(self) -> None:
        # Same inputs as fortressgd export (export.py), so the report cannot drift.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_project(root)
            sources = {
                p.resolve().relative_to(root.resolve()).as_posix(): p.read_text(encoding="utf-8")
                for p in iter_gdscript_files(root)
            }
            exclude = collect_resource_reference_names(root) | collect_scan_only_names(
                p.read_text(encoding="utf-8") for p in iter_scan_only_gdscript_files(root)
            )
            _out, mapping = mangle_scripts(sources, mangle_key="report-test", rename=True, exclude=exclude)
            report = analyze_project(root)
            self.assertEqual(sorted(mapping), report.renamed)
            self.assertFalse(set(mapping) & set(report.kept))


class MangleReportCliTests(unittest.TestCase):
    def test_cli_text_and_json_need_no_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_project(root)
            env = base_env()
            env.pop("FORTRESSGD_SECRET", None)
            self.assertFalse((root / ".fortressgd.secret").exists())
            text = run_fortressgd("mangle-report", cwd=root, env=env)
            self.assertEqual(text.returncode, 0, text.stdout + text.stderr)
            self.assertIn("kept readable: 7 name(s)", text.stdout)
            self.assertIn(SCENE, text.stdout)
            self.assertIn("_on_door_opened  (main.tscn)", text.stdout)
            data = run_fortressgd("mangle-report", "--json", cwd=root, env=env)
            self.assertEqual(data.returncode, 0, data.stderr)
            payload = json.loads(data.stdout)
            self.assertIn("secret_combo", payload["renamed"])
            self.assertEqual(payload["kept"]["speed"], {EXPORT: ["player.gd"]})

    def test_cli_limits_and_all(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            names = "\n".join("@export var exported_{0} := 0".format(i) for i in range(12))
            (root / "many.gd").write_text("extends Node\n" + names + "\n", encoding="utf-8")
            short = run_fortressgd("mangle-report", cwd=root)
            self.assertIn("... 4 more (use --all)", short.stdout)
            full = run_fortressgd("mangle-report", "--all", cwd=root)
            self.assertNotIn("more (use --all)", full.stdout)
            self.assertIn("exported_11", full.stdout)

    def test_cli_outside_a_godot_project_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_fortressgd("mangle-report", cwd=Path(tmp))
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)


class MangleReportExportSummaryTests(unittest.TestCase):
    def test_export_prints_the_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Reuse the export fixture (stub Godot, cached template) without
            # inheriting, and re-running, that class's tests.
            root = mangle_tests.MangleExportPathTests._project(self, tmp, mangle=True, script=PLAYER)
            bindir = root / "bin"
            mangle_tests._write_godot_stub_bin(bindir, root / "godot.json")
            env = base_env()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertRegex(proc.stdout, r"mangle: renamed \d+ name\(s\); \d+ stay readable \(run: fortressgd mangle-report\)")

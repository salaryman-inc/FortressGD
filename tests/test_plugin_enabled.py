"""The FortressGD plugin must be enabled in project.godot: init enables it,
doctor reports it, and export refuses without it (DESIGN.md §6.3)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fortressgd.core.project import (
    PLUGIN_CFG_RES,
    enable_plugin,
    enabled_editor_plugins,
    plugin_enabled,
)
from tests.support import run_fortressgd, write_godot_stub

OTHER = "res://addons/other/plugin.cfg"


def _disable(root: Path) -> None:
    path = root / "project.godot"
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text("".join(l for l in lines if PLUGIN_CFG_RES not in l), encoding="utf-8")


class EnabledPluginsParseTests(unittest.TestCase):
    def test_absent_section_or_empty_array(self) -> None:
        self.assertEqual(enabled_editor_plugins("config_version=5\n"), [])
        self.assertEqual(enabled_editor_plugins("[editor_plugins]\n\nenabled=PackedStringArray()\n"), [])

    def test_lists_every_enabled_plugin(self) -> None:
        text = '[editor_plugins]\n\nenabled=PackedStringArray("{0}", "{1}")\n'.format(OTHER, PLUGIN_CFG_RES)
        self.assertEqual(enabled_editor_plugins(text), [OTHER, PLUGIN_CFG_RES])

    def test_key_in_another_section_does_not_count(self) -> None:
        text = '[other]\nenabled=PackedStringArray("{0}")\n'.format(PLUGIN_CFG_RES)
        self.assertEqual(enabled_editor_plugins(text), [])


class EnablePluginTests(unittest.TestCase):
    def _root(self, tmp: str, project_text: str) -> Path:
        root = Path(tmp)
        (root / "project.godot").write_text(project_text, encoding="utf-8")
        return root

    def test_adds_section_once_and_keeps_the_rest(self) -> None:
        original = 'config_version=5\n\n[application]\n\nconfig/name="X"\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, original)
            self.assertFalse(plugin_enabled(root))
            self.assertTrue(enable_plugin(root))
            text = (root / "project.godot").read_text(encoding="utf-8")
            self.assertTrue(text.startswith(original))
            self.assertIn('[editor_plugins]\nenabled=PackedStringArray("{0}")\n'.format(PLUGIN_CFG_RES), text)
            self.assertTrue(plugin_enabled(root))
            self.assertFalse(enable_plugin(root))
            self.assertEqual((root / "project.godot").read_text(encoding="utf-8"), text)

    def test_keeps_other_enabled_plugins(self) -> None:
        original = 'config_version=5\n\n[editor_plugins]\n\nenabled=PackedStringArray("{0}")\n\n[rendering]\n\nx=1\n'.format(OTHER)
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp, original)
            self.assertTrue(enable_plugin(root))
            text = (root / "project.godot").read_text(encoding="utf-8")
            self.assertEqual(enabled_editor_plugins(text), [OTHER, PLUGIN_CFG_RES])
            self.assertIn("[rendering]\n\nx=1\n", text)


class PluginEnabledCliTests(unittest.TestCase):
    def _project(self, tmp: str) -> Path:
        root = Path(tmp)
        write_godot_stub(root)
        proc = run_fortressgd("init", cwd=root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("enabled plugin in project.godot", proc.stdout + proc.stderr)
        return root

    def test_init_enables_plugin_and_rerun_keeps_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            self.assertTrue(plugin_enabled(root))
            proc = run_fortressgd("init", cwd=root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("plugin already enabled in project.godot", proc.stdout + proc.stderr)

    def test_doctor_reports_plugin_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            proc = run_fortressgd("doctor", cwd=root)
            self.assertIn("ok: plugin enabled in project.godot", proc.stdout + proc.stderr)
            _disable(root)
            proc = run_fortressgd("doctor", cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertIn("plugin is not enabled in project.godot", combined)
            self.assertIn("Run: fortressgd init", combined)

    def test_export_refuses_without_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            _disable(root)
            proc = run_fortressgd("export", "--preset", "Linux", cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 1, combined)
            self.assertIn("plugin is not enabled in project.godot", combined)
            self.assertIn("Run: fortressgd init", combined)


if __name__ == "__main__":
    unittest.main()

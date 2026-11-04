"""core.export.upsert_ini_key, which rewrites export_presets.cfg during export."""

from __future__ import annotations

import unittest

from core.export import upsert_ini_key

CFG = """[preset.0]

name="Linux"
encrypt_pck=false

[preset.0.options]

custom_template/release=""
binary_format/embed_pck=false
"""


class UpsertIniKeyTests(unittest.TestCase):
    def test_upsert_replaces_existing_key_keeps_other_lines(self) -> None:
        out = upsert_ini_key(CFG, "preset.0", "encrypt_pck", "true")
        self.assertEqual(out, CFG.replace("encrypt_pck=false", "encrypt_pck=true"))

    def test_upsert_replaces_last_line_without_trailing_newline(self) -> None:
        text = CFG.rstrip("\n")
        out = upsert_ini_key(text, "preset.0.options", "binary_format/embed_pck", "true")
        self.assertTrue(out.endswith("binary_format/embed_pck=true\n"))
        self.assertEqual(out.count("binary_format/embed_pck"), 1)

    def test_upsert_inserts_into_existing_section(self) -> None:
        out = upsert_ini_key(CFG, "preset.0", "encrypt_directory", "true")
        self.assertLess(out.index("encrypt_directory=true"), out.index("[preset.0.options]"))
        self.assertGreater(out.index("encrypt_directory=true"), out.index("[preset.0]"))
        self.assertEqual(out.replace("encrypt_directory=true\n", ""), CFG)

    def test_upsert_inserts_at_end_of_last_section_without_trailing_newline(self) -> None:
        out = upsert_ini_key(CFG.rstrip("\n"), "preset.0.options", "custom_template/debug", '""')
        self.assertIn('binary_format/embed_pck=false\ncustom_template/debug=""\n', out)

    def test_upsert_appends_missing_section(self) -> None:
        out = upsert_ini_key(CFG, "preset.1", "name", '"Windows"')
        self.assertTrue(out.startswith(CFG))
        self.assertTrue(out.endswith('[preset.1]\nname="Windows"\n'))
        self.assertEqual(upsert_ini_key("", "a", "k", "v"), "[a]\nk=v\n")


if __name__ == "__main__":
    unittest.main()

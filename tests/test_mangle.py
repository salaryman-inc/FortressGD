"""Phase 4 mangler: shipped transform, unsafe-call fail, map emission, plugin wiring."""

from __future__ import annotations

import inspect
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.export import export_preset, write_export_source_map
from core.kdf import secret_hash
from core.mangle import (
    MangleError,
    collect_user_identifiers,
    mangled_identifier,
    mangle_scripts,
    reserved_names,
    rewrite_source,
    source_map_json,
    source_map_path,
)
from core.secret import read_secret_file
from core.templates import patchset_for_tag, template_filename, templates_cache_dir
from tests.support import ROOT, base_env, run_fortressgd, write_godot_stub


SAMPLE_SCRIPT = """extends Node2D
class_name SampleHero

# strip this comment
func _ready() -> void:
	var health := 10
	assert(health > 0)
	print_debug("debug")
	breakpoint
	my_attack()
	public_mod_hook()

## fortressgd:keep
func public_mod_hook() -> void:
	pass

func my_attack() -> void:
	pass
"""

PRESETS = """[preset.0]

name="Linux"
platform="Linux"
runnable=true
dedicated_server=false
custom_features="fortressgd_production"
export_filter="all_resources"
export_path="build/game.x86_64"
encrypt_pck=false
encrypt_directory=false
script_export_mode=1

[preset.0.options]

custom_template/debug=""
custom_template/release=""
"""


def _write_godot_stub_bin(directory: Path, log_path: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "godot"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "log = Path({0!r})\n"
        "scripts = {{}}\n"
        "root = Path.cwd()\n"
        "for p in root.rglob('*.gd'):\n"
        "    rel = p.relative_to(root).as_posix()\n"
        "    if rel.startswith('addons/fortressgd/'):\n"
        "        continue\n"
        "    scripts[rel] = p.read_text(encoding='utf-8')\n"
        "payload = {{\n"
        "    'argv': sys.argv,\n"
        "    'GODOT_SCRIPT_ENCRYPTION_KEY': os.environ.get('GODOT_SCRIPT_ENCRYPTION_KEY'),\n"
        "    'FORTRESSGD_SECRET': os.environ.get('FORTRESSGD_SECRET'),\n"
        "    'FORTRESSGD_CLI_EXPORT': os.environ.get('FORTRESSGD_CLI_EXPORT'),\n"
        "    'scripts': scripts,\n"
        "}}\n"
        "log.write_text(json.dumps(payload), encoding='utf-8')\n"
        "sys.path.insert(0, {1!r})\n"
        "from tests.godot_stub import write_artifact\n"
        "write_artifact(sys.argv)\n"
        "raise SystemExit(0)\n".format(str(log_path), str(ROOT)),
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _mangle_gd() -> str:
    return (ROOT / "plugin" / "addons" / "fortressgd" / "mangle.gd").read_text(encoding="utf-8")


def _gd_func_body(source: str, name: str) -> str:
    """Text of `static func <name>` up to the next top-level func."""
    start = source.index("static func {0}(".format(name))
    end = source.find("\nstatic func ", start + 1)
    return source[start : end if end != -1 else len(source)]


class MangleTransformTests(unittest.TestCase):
    """Drive the shipped mangling transform used by export (core.mangle.mangle_scripts)."""

    HASH = "0123456789abcdef"

    def test_strip_replaces_statement_with_pass(self) -> None:
        src = "extends Node\n\nfunc _ready():\n    if true:\n        assert(1 == 1)\n    print_debug(\"x\")\n"
        out, _ = mangle_scripts({"b.gd": src}, secret_hash="abc123", rename=True)
        self.assertEqual(
            out["b.gd"], "extends Node\n\nfunc _ready():\n    if true:\n        pass\n    pass\n"
        )

    def test_strip_one_line_if(self) -> None:
        self.assertEqual(rewrite_source("if a: assert(b)\n", {}), "if a: pass\n")
        self.assertEqual(rewrite_source("x = 1; assert(y);\n", {}), "x = 1; pass\n")

    def test_strip_breakpoint_only_function_body(self) -> None:
        self.assertEqual(rewrite_source("func f():\n\tbreakpoint\n", {}), "func f():\n\tpass\n")

    def test_strip_keeps_dotted_call(self) -> None:
        src = 'logger.print_debug("x")\nobj.assert(1)\nother.breakpoint\n'
        self.assertEqual(rewrite_source(src, {}), src)

    def test_foreign_member_access_is_not_renamed(self) -> None:
        src = (
            "extends Node\nvar speed = 5\nfunc _ready():\n"
            "    var other = get_node(\"Enemy\")\n    other.speed = 10\n"
        )
        out, mapping = mangle_scripts({"a.gd": src}, secret_hash="abc123", rename=True)
        self.assertNotIn("speed", mapping)
        self.assertIn("var speed = 5", out["a.gd"])
        # `other` is a local and is still renamed; the member after the dot is not.
        self.assertIn(mapping["other"] + ".speed = 10", out["a.gd"])

    def test_self_member_access_is_renamed(self) -> None:
        src = "extends Node\nvar hp = 3\nfunc hit():\n    self.hp -= 1\n    hp -= 1\n    super.hit()\n"
        out, mapping = mangle_scripts({"a.gd": src}, secret_hash=self.HASH, rename=True)
        self.assertIn("hp", mapping)
        new = mapping["hp"]
        self.assertIn("self.{0} -= 1".format(new), out["a.gd"])
        self.assertIn("\n    {0} -= 1".format(new), out["a.gd"])
        self.assertNotRegex(out["a.gd"], r"\bhp\b")
        # super.hit() keeps hit renameable: it is the same script's method.
        self.assertIn("hit", mapping)

    def test_foreign_access_in_another_file_blocks_rename(self) -> None:
        files = {
            "a.gd": "extends Node\nvar speed = 1\nfunc go():\n    speed += 1\n",
            "b.gd": "extends Node\nfunc push(enemy):\n    enemy.speed = 0\n",
        }
        out, mapping = mangle_scripts(files, secret_hash=self.HASH, rename=True)
        self.assertNotIn("speed", mapping)
        self.assertIn("var speed = 1", out["a.gd"])
        self.assertIn(".speed = 0", out["b.gd"])

    def test_enum_member_via_type_is_not_renamed(self) -> None:
        src = "extends Node\nenum State { IDLE, RUN }\nvar s = State.IDLE\nfunc f():\n    return IDLE\n"
        out, mapping = mangle_scripts({"a.gd": src}, secret_hash=self.HASH, rename=True)
        self.assertNotIn("IDLE", mapping)
        # The enum type is still renamed consistently; only the member is kept.
        self.assertIn(mapping["State"] + ".IDLE", out["a.gd"])
        self.assertIn("return IDLE", out["a.gd"])
        self.assertIn("{ IDLE,", out["a.gd"])

    def test_numbers_do_not_count_as_member_access(self) -> None:
        src = "extends Node\nvar scale_x = 1.5\nfunc f():\n    return scale_x * 2.0\n"
        _out, mapping = mangle_scripts({"a.gd": src}, secret_hash=self.HASH, rename=True)
        self.assertIn("scale_x", mapping)

    def test_reserved_set_keeps_lifecycle(self) -> None:
        names = reserved_names()
        self.assertIn("_ready", names)
        self.assertIn("_process", names)
        self.assertIn("func", names)
        self.assertNotEqual(
            mangled_identifier("my_attack", self.HASH),
            mangled_identifier("my_attack", "fedcba9876543210"),
        )
        self.assertEqual(
            mangled_identifier("my_attack", self.HASH),
            mangled_identifier("my_attack", self.HASH),
        )

    def test_transform_strips_renames_and_is_deterministic(self) -> None:
        files = {"player.gd": SAMPLE_SCRIPT}
        out1, mapping1 = mangle_scripts(files, secret_hash=self.HASH, rename=True)
        out2, mapping2 = mangle_scripts(files, secret_hash=self.HASH, rename=True)
        self.assertEqual(out1, out2)
        self.assertEqual(mapping1, mapping2)

        result = out1["player.gd"]
        self.assertNotIn("strip this comment", result)
        self.assertNotIn("# ", result)
        self.assertNotIn("assert", result)
        self.assertNotIn("print_debug", result)
        self.assertNotIn("breakpoint", result)
        self.assertNotIn("my_attack", result)
        self.assertIn("_ready", result)
        self.assertIn("public_mod_hook", result)
        self.assertIn("class_name SampleHero", result)
        self.assertIn("my_attack", mapping1)
        self.assertNotIn("public_mod_hook", mapping1)
        self.assertNotIn("_ready", mapping1)
        self.assertNotIn("SampleHero", mapping1)
        self.assertIn(mapping1["my_attack"], result)
        self.assertTrue(mapping1["my_attack"].startswith("_f"))
        self.assertIn("health", mapping1)

        unchanged, empty = mangle_scripts(files, secret_hash=self.HASH, rename=False)
        self.assertEqual(unchanged["player.gd"], SAMPLE_SCRIPT)
        self.assertEqual(empty, {})

    def test_user_identifiers_do_not_include_lifecycle(self) -> None:
        found = collect_user_identifiers(SAMPLE_SCRIPT)
        self.assertIn("my_attack", found)
        self.assertNotIn("_ready", found)
        self.assertNotIn("public_mod_hook", found)
        self.assertNotIn("SampleHero", found)

    def test_unsafe_call_rpc_set_fail_with_file_line_unless_keep(self) -> None:
        bad = {
            "combat.gd": 'extends Node\nfunc _ready() -> void:\n\tcall("my_attack")\n',
        }
        with self.assertRaises(MangleError) as ctx:
            mangle_scripts(bad, secret_hash=self.HASH, rename=True)
        msg = str(ctx.exception)
        self.assertIn("combat.gd:3", msg)
        self.assertIn("call", msg)

        rpc_bad = {
            "net.gd": 'extends Node\nfunc _ready() -> void:\n\trpc("sync_hp")\n',
        }
        with self.assertRaises(MangleError) as rpc_ctx:
            mangle_scripts(rpc_bad, secret_hash=self.HASH, rename=True)
        self.assertIn("net.gd:3", str(rpc_ctx.exception))
        self.assertIn("rpc", str(rpc_ctx.exception))

        set_bad = {
            "props.gd": 'extends Node\nfunc _ready() -> void:\n\tset("hp", 1)\n',
        }
        with self.assertRaises(MangleError) as set_ctx:
            mangle_scripts(set_bad, secret_hash=self.HASH, rename=True)
        self.assertIn("props.gd:3", str(set_ctx.exception))
        self.assertIn("set", str(set_ctx.exception))

        kept = {
            "ok.gd": (
                "extends Node\n"
                "func _ready() -> void:\n"
                "\t## fortressgd:keep\n"
                '\tcall("my_attack")\n'
                "\trpc(\"sync_hp\") ## fortressgd:keep\n"
                "\t## fortressgd:keep\n"
                '\tset("hp", 1)\n'
            ),
        }
        out, _mapping = mangle_scripts(kept, secret_hash=self.HASH, rename=True)
        self.assertIn('call("my_attack")', out["ok.gd"])

    def test_source_map_payload_matches_transform_names(self) -> None:
        files = {"player.gd": SAMPLE_SCRIPT}
        _out, mapping = mangle_scripts(files, secret_hash=self.HASH, rename=True)
        payload = json.loads(source_map_json(self.HASH, mapping))
        self.assertEqual(payload["secret_hash"], self.HASH)
        self.assertEqual(payload["identifiers"]["my_attack"], mapping["my_attack"])
        export_artifact = Path("build") / "game.x86_64"
        mapped = source_map_path(export_artifact)
        self.assertTrue(str(mapped).endswith(".fortressgd.map.json"))
        self.assertNotEqual(mapped.suffix, ".pck")
        self.assertIn("game.x86_64", mapped.name)


class MangleExportPathTests(unittest.TestCase):
    def _project(self, tmp: str, *, mangle: bool, script: str | None) -> Path:
        root = Path(tmp)
        write_godot_stub(root)
        self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
        toml = root / ".fortressgd.toml"
        text = toml.read_text(encoding="utf-8")
        cache = root / "cache"
        text = text.replace(
            'cache_dir = "~/.cache/fortressgd"',
            'cache_dir = "{0}"'.format(cache.as_posix()),
        )
        if not mangle:
            text = text.replace("mangle_scripts = true", "mangle_scripts = false")
        text = text.replace("dialect = true", "dialect = false")
        toml.write_text(text, encoding="utf-8")
        (root / "export_presets.cfg").write_text(PRESETS, encoding="utf-8")
        self.assertEqual(run_fortressgd("secret", "generate", cwd=root).returncode, 0)
        if script is not None:
            (root / "player.gd").write_text(script, encoding="utf-8")
        secret_hex = read_secret_file(root / ".fortressgd.secret")
        secret = bytes.fromhex(secret_hex)
        sh = secret_hash(secret)
        pset = patchset_for_tag("4.6.2")
        cache_dir = templates_cache_dir(root / "cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        name = template_filename("4.6.2", "linux", "x86_64", pset, sh)
        (cache_dir / name).write_bytes(b"stub-template")
        return root

    def test_cli_export_applies_mangle_writes_map_restores_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp, mangle=True, script=SAMPLE_SCRIPT)
            original = (root / "player.gd").read_text(encoding="utf-8")
            bindir = root / "bin"
            log = root / "godot-mangle.json"
            _write_godot_stub_bin(bindir, log)
            env = base_env()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            env.pop("FORTRESSGD_SECRET", None)
            proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertEqual((root / "player.gd").read_text(encoding="utf-8"), original)

            data = json.loads(log.read_text(encoding="utf-8"))
            packed_view = data["scripts"]["player.gd"]
            self.assertEqual(data["FORTRESSGD_CLI_EXPORT"], "1")
            self.assertNotIn("my_attack", packed_view)
            self.assertIn("_ready", packed_view)
            self.assertIn("public_mod_hook", packed_view)
            self.assertIn("class_name SampleHero", packed_view)
            self.assertNotIn("assert", packed_view)
            self.assertNotIn("print_debug", packed_view)
            self.assertNotIn("breakpoint", packed_view)
            self.assertNotIn("strip this comment", packed_view)

            expected_map = source_map_path(root / "build" / "game.x86_64")
            self.assertTrue(
                expected_map.is_file(),
                "missing {0}; maps={1}".format(
                    expected_map,
                    list((root / "build").glob("*")) if (root / "build").is_dir() else [],
                ),
            )
            payload = json.loads(expected_map.read_text(encoding="utf-8"))
            self.assertIn("my_attack", payload["identifiers"])
            mangled = payload["identifiers"]["my_attack"]
            self.assertIn(mangled, packed_view)
            self.assertNotIn("pck", expected_map.name.lower().split("fortressgd")[0])
            self.assertTrue(str(expected_map).endswith(".fortressgd.map.json"))

            secret_hex = read_secret_file(root / ".fortressgd.secret")
            presets = (root / "export_presets.cfg").read_text(encoding="utf-8")
            self.assertNotIn(secret_hex, presets)
            self.assertEqual(presets, PRESETS)

    def test_write_export_source_map_is_what_export_calls(self) -> None:
        src = inspect.getsource(export_preset)
        self.assertIn("write_export_source_map", src)
        self.assertIn("mangle_scripts", src)
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "out" / "game.pck"
            mapping = {"my_attack": "_fabc123def"}
            written = write_export_source_map(artifact, "0123456789abcdef", mapping)
            self.assertEqual(written, source_map_path(artifact))
            self.assertTrue(written.is_file())
            data = json.loads(written.read_text(encoding="utf-8"))
            self.assertEqual(data["identifiers"]["my_attack"], "_fabc123def")
            self.assertNotEqual(written.suffix, ".pck")

    def test_mangle_off_leaves_identifiers_and_skips_map(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp, mangle=False, script=SAMPLE_SCRIPT)
            bindir = root / "bin"
            log = root / "godot-nomangle.json"
            _write_godot_stub_bin(bindir, log)
            env = base_env()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(log.read_text(encoding="utf-8"))
            self.assertIn("my_attack", data["scripts"]["player.gd"])
            self.assertNotEqual(data.get("FORTRESSGD_CLI_EXPORT"), "1")
            self.assertFalse(source_map_path(root / "build" / "game.x86_64").is_file())

    def test_unsafe_call_fails_export_before_godot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = 'extends Node\nfunc _ready() -> void:\n\tcall("my_attack")\n'
            root = self._project(tmp, mangle=True, script=script)
            bindir = root / "bin"
            log = root / "godot-unsafe.json"
            _write_godot_stub_bin(bindir, log)
            env = base_env()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
            self.assertNotEqual(proc.returncode, 0)
            combined = proc.stdout + proc.stderr
            self.assertIn("player.gd:3", combined)
            self.assertIn("call", combined)
            self.assertFalse(log.is_file())
            self.assertEqual((root / "player.gd").read_text(encoding="utf-8"), script)


def _gd_func(source: str, name: str) -> str:
    marker = "func {0}(".format(name)
    start = source.find(marker)
    if start < 0:
        raise AssertionError("missing func {0}".format(name))
    next_static = source.find("\nstatic func ", start + len(marker))
    next_func = source.find("\nfunc ", start + len(marker))
    ends = [i for i in (next_static, next_func) if i >= 0]
    end = min(ends) if ends else len(source)
    return source[start:end]


class MangleStaticChecks(unittest.TestCase):
    def test_plugin_excludes_foreign_member_names(self) -> None:
        gd = _mangle_gd()
        body = _gd_func_body(gd, "collect_foreign_member_names")
        self.assertIn('["self", "super"]', body)
        self.assertIn("collect_foreign_member_names(", _gd_func_body(gd, "apply_project"))
        self.assertIn("user.erase(", _gd_func_body(gd, "apply_project"))

    def test_plugin_strip_emits_pass(self) -> None:
        body = _gd_func_body(_mangle_gd(), "_strip_tokens")
        self.assertEqual(body.count('_tok(KIND_IDENT, "pass"'), 2)

    def test_plugin_participates_when_mangle_scripts_true(self) -> None:
        addon = ROOT / "plugin" / "addons" / "fortressgd"
        export_gd = (addon / "export_plugin.gd").read_text(encoding="utf-8")
        self.assertIn("extends EditorExportPlugin", export_gd)
        self.assertIn("mangle_scripts", export_gd)
        self.assertIn("mangle.gd", export_gd)
        self.assertIn("fortressgd.map.json", export_gd)
        self.assertIn("FORTRESSGD_CLI_EXPORT", export_gd)
        self.assertIn('return "GDScript.FortressGD"', export_gd)
        mangle_gd = (addon / "mangle.gd").read_text(encoding="utf-8")
        self.assertIn("fortressgd:keep", mangle_gd)
        self.assertIn("call", mangle_gd)
        self.assertIn("secret_hash", mangle_gd)
        reserved = json.loads((addon / "mangle_reserved.json").read_text(encoding="utf-8"))
        self.assertIn("_ready", reserved["lifecycle"])

    def test_plugin_walk_keeps_res_scheme_slashes(self) -> None:
        """Godot FileAccess needs res://file, not res:/file from rstrip('/')."""
        mangle_gd = (ROOT / "plugin" / "addons" / "fortressgd" / "mangle.gd").read_text(
            encoding="utf-8"
        )
        walk = _gd_func(mangle_gd, "_walk")
        join = _gd_func(mangle_gd, "join_dir")
        self.assertIn("join_dir(", walk)
        self.assertNotIn('rstrip("/")', walk)
        self.assertIn("path_join", join)
        code_lines = [
            ln for ln in join.splitlines() if ln.strip() and not ln.strip().startswith("#")
        ]
        self.assertTrue(any("path_join" in ln for ln in code_lines), join)
        self.assertFalse(any("rstrip" in ln for ln in code_lines), join)
        # Engine String.path_join keeps a trailing slash; rstrip("/") does not.
        self.assertNotEqual("res://".rstrip("/") + "/" + "main.gd", "res://main.gd")

    def test_plugin_abort_refuses_artifact_after_pack(self) -> None:
        """skip() after GDScript.FortressGD cannot un-pack bytecode; _export_end must."""
        addon = ROOT / "plugin" / "addons" / "fortressgd"
        export_gd = (addon / "export_plugin.gd").read_text(encoding="utf-8")
        mangle_gd = (addon / "mangle.gd").read_text(encoding="utf-8")
        end = _gd_func(export_gd, "_export_end")
        abort_idx = end.find("_mangle_abort")
        self.assertGreaterEqual(abort_idx, 0)
        abort_block = end[abort_idx:]
        ret = abort_block.find("return")
        self.assertGreaterEqual(ret, 0)
        abort_block = abort_block[:ret]
        self.assertIn("refuse_export_artifact", abort_block)
        self.assertNotIn("write_map", abort_block)
        refuse = _gd_func(mangle_gd, "refuse_export_artifact")
        self.assertIn("remove_absolute", refuse)
        begin = _gd_func(export_gd, "_export_begin")
        self.assertIn("_mangle_abort = true", begin)

    def test_no_new_mangler_engine_patch(self) -> None:
        for tag in ("4.6.2", "4.7.2"):
            series = (ROOT / "patches" / tag / "series").read_text(encoding="utf-8")
            self.assertEqual(
                [ln.strip() for ln in series.splitlines() if ln.strip()][:2],
                ["0001-key-derive.patch", "0002-pack-hooks.patch"],
            )
            patch_dir = ROOT / "patches" / tag
            names = sorted(p.name for p in patch_dir.iterdir() if p.suffix == ".patch")
            self.assertIn("0001-key-derive.patch", names)
            self.assertIn("0002-pack-hooks.patch", names)
            # Phase 4 still adds no mangler engine patch; Phase 5 files are later in series.
            self.assertFalse(any("mangle" in n for n in names))

    def test_agent_rules_doc(self) -> None:
        path = ROOT / "docs" / "agent-rules.md"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8").lower()
        self.assertIn("callable", text)
        self.assertTrue("call" in text and "rpc" in text)
        self.assertIn("res://", text)
        self.assertIn("secret", text)
        self.assertTrue("set" in text and "get" in text)


if __name__ == "__main__":
    unittest.main()

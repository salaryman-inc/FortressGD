"""Phase 4 mangler: shipped transform, unsafe-call fail, map emission, plugin wiring."""

from __future__ import annotations

import inspect
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from fortressgd.core.export import export_preset, write_export_source_map
from fortressgd.core.kdf import secret_hash
from fortressgd.core.mangle import (
    MangleError,
    collect_resource_reference_names,
    collect_user_identifiers,
    derive_mangle_key,
    iter_gdscript_files,
    iter_scan_only_gdscript_files,
    mangled_identifier,
    mangle_scripts,
    reserved_names,
    rewrite_source,
    source_map_json,
    source_map_path,
)
from fortressgd.core.secret import read_secret_file
from fortressgd.core.templates import patchset_for_tag, template_filename, templates_cache_dir
from tests.support import PKG, ROOT, base_env, run_fortressgd, write_godot_stub


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
    return (PKG / "plugin" / "addons" / "fortressgd" / "mangle.gd").read_text(encoding="utf-8")


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
        out, _ = mangle_scripts({"b.gd": src}, mangle_key="abc123", rename=True)
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
        out, mapping = mangle_scripts({"a.gd": src}, mangle_key="abc123", rename=True)
        self.assertNotIn("speed", mapping)
        self.assertIn("var speed = 5", out["a.gd"])
        # `other` is a local and is still renamed; the member after the dot is not.
        self.assertIn(mapping["other"] + ".speed = 10", out["a.gd"])

    def test_self_member_access_is_renamed(self) -> None:
        src = "extends Node\nvar hp = 3\nfunc hit():\n    self.hp -= 1\n    hp -= 1\n    super.hit()\n"
        out, mapping = mangle_scripts({"a.gd": src}, mangle_key=self.HASH, rename=True)
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
        out, mapping = mangle_scripts(files, mangle_key=self.HASH, rename=True)
        self.assertNotIn("speed", mapping)
        self.assertIn("var speed = 1", out["a.gd"])
        self.assertIn(".speed = 0", out["b.gd"])

    def test_enum_member_via_type_is_not_renamed(self) -> None:
        src = "extends Node\nenum State { IDLE, RUN }\nvar s = State.IDLE\nfunc f():\n    return IDLE\n"
        out, mapping = mangle_scripts({"a.gd": src}, mangle_key=self.HASH, rename=True)
        self.assertNotIn("IDLE", mapping)
        # The enum type is still renamed consistently; only the member is kept.
        self.assertIn(mapping["State"] + ".IDLE", out["a.gd"])
        self.assertIn("return IDLE", out["a.gd"])
        self.assertIn("{ IDLE,", out["a.gd"])

    def test_numbers_do_not_count_as_member_access(self) -> None:
        src = "extends Node\nvar scale_x = 1.5\nfunc f():\n    return scale_x * 2.0\n"
        _out, mapping = mangle_scripts({"a.gd": src}, mangle_key=self.HASH, rename=True)
        self.assertIn("scale_x", mapping)

    def test_string_member_references_block_rename(self) -> None:
        src = (
            "extends Node\nsignal my_signal\nvar health = 3\nfunc go():\n"
            '    emit_signal("my_signal")\n'
            '    connect("my_signal", Callable(self, "go"))\n'
            '    var h = get("health")\n'
            '    if has_method("go"): pass\n'
        )
        out, mapping = mangle_scripts({"s.gd": src}, mangle_key="z", rename=True)
        for name in ("my_signal", "go", "health"):
            self.assertNotIn(name, mapping)
        # Only the local `h` is renamed.
        self.assertEqual(set(mapping), {"h"})
        for literal in ('"my_signal"', '"go"', '"health"', "signal my_signal", "func go", "var health"):
            self.assertIn(literal, out["s.gd"])

    def test_stringname_and_nodepath_prefixes_block_rename(self) -> None:
        src = 'extends Node\nvar hp = 1\nfunc go():\n    pass\nfunc f():\n    var c = &"go"\n    var p = ^".:hp"\n'
        _out, mapping = mangle_scripts({"s.gd": src}, mangle_key=self.HASH, rename=True)
        self.assertNotIn("go", mapping)
        self.assertNotIn("hp", mapping)

    def test_property_path_segments_block_rename(self) -> None:
        src = 'extends Node2D\nvar speed = Vector2.ZERO\nfunc f():\n    create_tween().tween_property(self, "speed:x", 1.0, 0.5)\n'
        _out, mapping = mangle_scripts({"s.gd": src}, mangle_key=self.HASH, rename=True)
        self.assertNotIn("speed", mapping)

    def test_keep_call_target_is_not_renamed(self) -> None:
        src = 'extends Node\nfunc my_attack():\n    pass\nfunc f():\n    ## fortressgd:keep\n    call("my_attack")\n'
        out, mapping = mangle_scripts({"s.gd": src}, mangle_key=self.HASH, rename=True)
        self.assertNotIn("my_attack", mapping)
        self.assertIn("func my_attack", out["s.gd"])

    def test_non_identifier_strings_do_not_block(self) -> None:
        src = 'extends Node\nvar hello_world = 1\nfunc f():\n    print("hello world")\n    print("a-b", hello_world)\n'
        _out, mapping = mangle_scripts({"s.gd": src}, mangle_key=self.HASH, rename=True)
        self.assertIn("hello_world", mapping)

    def test_string_in_other_file_blocks_rename(self) -> None:
        files = {
            "a.gd": "extends Node\nfunc on_hit():\n    pass\n",
            "b.gd": 'extends Node\nfunc wire(n):\n    n.connect("hit", Callable(n, "on_hit"))\n',
        }
        _out, mapping = mangle_scripts(files, mangle_key=self.HASH, rename=True)
        self.assertNotIn("on_hit", mapping)

    def test_export_annotated_vars_are_never_renamed(self) -> None:
        src = (
            "extends Node2D\n"
            "@export var speed: float = 100.0\n"
            "@export_range(0, 10)\n"
            "var level := 1\n"
            "@export_group(\"G\")\n"
            "var x = 0\n"
            "@export_enum(\"A\", \"B\") var choice = 0\n"
            "@onready\n@export\nvar stacked = 1\n"
            "var plain = 1\n"
            "func _on_button_pressed() -> void:\n    speed += 1.0\n"
        )
        _out, mapping = mangle_scripts({"main.gd": src}, mangle_key="z", rename=True)
        for name in ("speed", "level", "choice", "stacked"):
            self.assertNotIn(name, mapping)
        # @export_group declares nothing, so the plain var after it is renamed.
        self.assertIn("x", mapping)
        self.assertIn("plain", mapping)

    def test_scene_property_and_animation_path_block_rename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "project.godot").write_text(
                'config_version=5\n[autoload]\nGameState="*res://game_state.gd"\n', encoding="utf-8"
            )
            (root / "levels").mkdir()
            (root / "levels" / "main.tscn").write_text(
                '[gd_scene format=3]\n[node name="Hero" type="Node2D"]\nspeed = 250.0\n'
                '[sub_resource type="Animation" id="a"]\ntracks/0/path = NodePath(".:hp")\n',
                encoding="utf-8",
            )
            (root / ".godot").mkdir()
            (root / ".godot" / "cache.tres").write_text("ignored_name = 1\n", encoding="utf-8")
            names = collect_resource_reference_names(root)
            self.assertTrue({"speed", "hp", "GameState"} <= names)
            self.assertNotIn("ignored_name", names)
            src = "extends Node2D\nvar speed = 1\nvar hp = 2\nvar GameState = 3\nvar other = 4\n"
            _out, mapping = mangle_scripts(
                {"hero.gd": src}, mangle_key=self.HASH, rename=True, exclude=names
            )
            self.assertEqual(set(mapping), {"other"})

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
        out1, mapping1 = mangle_scripts(files, mangle_key=self.HASH, rename=True)
        out2, mapping2 = mangle_scripts(files, mangle_key=self.HASH, rename=True)
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

        unchanged, empty = mangle_scripts(files, mangle_key=self.HASH, rename=False)
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
            mangle_scripts(bad, mangle_key=self.HASH, rename=True)
        msg = str(ctx.exception)
        self.assertIn("combat.gd:3", msg)
        self.assertIn("call", msg)

        rpc_bad = {
            "net.gd": 'extends Node\nfunc _ready() -> void:\n\trpc("sync_hp")\n',
        }
        with self.assertRaises(MangleError) as rpc_ctx:
            mangle_scripts(rpc_bad, mangle_key=self.HASH, rename=True)
        self.assertIn("net.gd:3", str(rpc_ctx.exception))
        self.assertIn("rpc", str(rpc_ctx.exception))

        set_bad = {
            "props.gd": 'extends Node\nfunc _ready() -> void:\n\tset("hp", 1)\n',
        }
        with self.assertRaises(MangleError) as set_ctx:
            mangle_scripts(set_bad, mangle_key=self.HASH, rename=True)
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
        out, _mapping = mangle_scripts(kept, mangle_key=self.HASH, rename=True)
        self.assertIn('call("my_attack")', out["ok.gd"])

    def test_source_map_payload_matches_transform_names(self) -> None:
        files = {"player.gd": SAMPLE_SCRIPT}
        _out, mapping = mangle_scripts(files, mangle_key=self.HASH, rename=True)
        payload = json.loads(source_map_json(self.HASH, mapping))
        self.assertEqual(payload["secret_hash"], self.HASH)
        self.assertEqual(payload["identifiers"]["my_attack"], mapping["my_attack"])
        mapped = source_map_path(Path("/proj"), Path("build") / "game.x86_64")
        self.assertEqual(mapped.as_posix(), "/proj/.fortressgd/maps/build/game.x86_64.fortressgd.map.json")

    def test_source_map_path_never_lands_next_to_the_artifact(self) -> None:
        root = Path("/proj")
        cases = {
            "build/linux/game.pck": "/proj/.fortressgd/maps/build/linux/game.pck.fortressgd.map.json",
            "build/windows/game.pck": "/proj/.fortressgd/maps/build/windows/game.pck.fortressgd.map.json",
            "/proj/out/game.exe": "/proj/.fortressgd/maps/out/game.exe.fortressgd.map.json",
            "build/../dist/game.pck": "/proj/.fortressgd/maps/dist/game.pck.fortressgd.map.json",
        }
        for export_path, want in cases.items():
            with self.subTest(export_path=export_path):
                self.assertEqual(source_map_path(root, export_path).as_posix(), want)
        outside = source_map_path(root, "/srv/builds/game.pck").as_posix()
        self.assertRegex(outside, r"^/proj/\.fortressgd/maps/_external/game\.pck-[0-9a-f]{8}\.fortressgd\.map\.json$")
        self.assertNotEqual(outside, source_map_path(root, "/srv/other/game.pck").as_posix())

    def test_mangled_names_need_the_secret_not_secret_hash(self) -> None:
        # v1 hashed the public secret_hash, so anyone holding it could compute a
        # guessed name's mangled form and look it up. v2 is keyed by the secret.
        secret = bytes(range(32))
        key = derive_mangle_key(secret)
        self.assertEqual(len(key), 64)
        self.assertNotEqual(key, secret.hex())
        self.assertNotIn(secret_hash(secret), key)
        _out, mapping = mangle_scripts({"player.gd": SAMPLE_SCRIPT}, mangle_key=key, rename=True)
        self.assertIn("my_attack", mapping)
        for public in (secret_hash(secret), secret.hex()[:16]):
            self.assertNotEqual(mangled_identifier("my_attack", public), mapping["my_attack"])
        other = derive_mangle_key(bytes(range(1, 33)))
        self.assertNotEqual(mangled_identifier("my_attack", other), mapping["my_attack"])


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

            expected_map = source_map_path(root, root / "build" / "game.x86_64")
            self.assertEqual(expected_map.parent, root.resolve() / ".fortressgd" / "maps" / "build")
            self.assertTrue((root / ".fortressgd" / ".gdignore").is_file())
            self.assertEqual(list((root / "build").glob("*.fortressgd.map.json")), [])
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
            secret = bytes.fromhex(read_secret_file(root / ".fortressgd.secret"))
            self.assertEqual(mangled, mangled_identifier("my_attack", derive_mangle_key(secret)))
            self.assertNotIn(derive_mangle_key(secret), expected_map.read_text(encoding="utf-8"))

            secret_hex = read_secret_file(root / ".fortressgd.secret")
            presets = (root / "export_presets.cfg").read_text(encoding="utf-8")
            self.assertNotIn(secret_hex, presets)
            self.assertEqual(presets, PRESETS)

    def test_write_export_source_map_is_what_export_calls(self) -> None:
        src = inspect.getsource(export_preset)
        self.assertIn("write_export_source_map", src)
        self.assertIn("mangle_scripts", src)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "out" / "game.pck"
            mapping = {"my_attack": "_fabc123def"}
            written = write_export_source_map(root, artifact, "0123456789abcdef", mapping)
            self.assertEqual(written, source_map_path(root, artifact))
            self.assertTrue(written.is_file())
            self.assertFalse((root / "out").exists())
            self.assertTrue((root / ".fortressgd" / ".gdignore").is_file())
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
            self.assertFalse(source_map_path(root, root / "build" / "game.x86_64").is_file())

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


class MangleSceneReferenceExportTests(unittest.TestCase):
    _project = MangleExportPathTests._project

    SCRIPT = (
        "extends Node2D\n\n"
        "@export var speed: float = 100.0\n\n"
        "func _on_button_pressed() -> void:\n"
        "\tspeed += 1.0\n\n"
        "func helper() -> void:\n"
        "\tpass\n"
    )

    def _export(self, root: Path):
        bindir = root / "bin"
        log = root / "godot-mangle.json"
        _write_godot_stub_bin(bindir, log)
        env = base_env()
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        proc = run_fortressgd("export", "--preset", "Linux", cwd=root, env=env)
        data = json.loads(log.read_text(encoding="utf-8")) if log.is_file() else {}
        return proc, data

    def test_scene_connection_method_blocks_rename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp, mangle=True, script=self.SCRIPT)
            (root / "main.tscn").write_text(
                '[gd_scene format=3]\n'
                '[node name="Main" type="Node2D"]\n'
                '[node name="Button" type="Button" parent="."]\n'
                '[connection signal="pressed" from="Button" to="." method="_on_button_pressed"]\n',
                encoding="utf-8",
            )
            proc, data = self._export(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            packed_view = data["scripts"]["player.gd"]
            self.assertIn("func _on_button_pressed", packed_view)
            self.assertIn("@export var speed", packed_view)
            self.assertNotIn("func helper", packed_view)

    def test_binary_resource_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp, mangle=True, script=self.SCRIPT)
            (root / "foo.res").write_bytes(b"RSRC\x00binary")
            proc, _data = self._export(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("warning: cannot scan binary resource foo.res for mangled names", proc.stderr)


class MangleAddonExportTests(unittest.TestCase):
    _project = MangleExportPathTests._project
    _export = MangleSceneReferenceExportTests._export

    ADDON = (
        "@tool\nextends Node\n\n"
        "func bar() -> void:\n\tpass\n\n"
        "func go(game) -> void:\n"
        '\tcall("bar")\n'
        "\tprint(game.score)\n"
    )
    GAME = "extends Node\n\nvar score := 0\nvar lives := 3\n\nfunc _ready() -> void:\n\tscore += lives\n"

    def _addon_project(self, tmp: str) -> Path:
        root = self._project(tmp, mangle=True, script=self.GAME)
        addon = root / "addons" / "foo" / "foo.gd"
        addon.parent.mkdir(parents=True)
        addon.write_text(self.ADDON, encoding="utf-8")
        return root

    def test_addon_scripts_are_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._addon_project(tmp)
            proc, data = self._export(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            # The stub records each script as Godot sees it during the export.
            self.assertEqual(data["scripts"]["addons/foo/foo.gd"], self.ADDON)
            self.assertEqual((root / "addons" / "foo" / "foo.gd").read_text(encoding="utf-8"), self.ADDON)

    def test_game_names_used_by_addon_are_not_renamed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._addon_project(tmp)
            proc, data = self._export(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(source_map_path(root, root / "build" / "game.x86_64").read_text(encoding="utf-8"))
            self.assertNotIn("score", payload["identifiers"])
            self.assertIn("lives", payload["identifiers"])
            self.assertIn("var score", data["scripts"]["player.gd"])

    def test_iter_gdscript_files_skips_addons(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("main.gd", "ui/hud.gd", "addons/foo/foo.gd", "addons/fortressgd/mangle.gd", ".godot/x.gd"):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("extends Node\n", encoding="utf-8")
            rels = lambda paths: sorted(p.relative_to(root.resolve()).as_posix() for p in paths)  # noqa: E731
            self.assertEqual(rels(iter_gdscript_files(root)), ["main.gd", "ui/hud.gd"])
            self.assertEqual(rels(iter_scan_only_gdscript_files(root)), ["addons/foo/foo.gd"])


class MangleStaticChecks(unittest.TestCase):
    def test_plugin_has_pure_mangle_sources_for_the_corpus(self) -> None:
        gd = _mangle_gd()
        self.assertIn(
            "static func mangle_sources(files: Dictionary, key: String, exclude: Dictionary = {}) -> Dictionary:",
            gd,
        )
        body = _gd_func_body(gd, "mangle_sources")
        self.assertNotIn("FileAccess", body)
        self.assertNotIn("DirAccess", body)
        runner = (ROOT / "tests" / "gd" / "run_mangle_corpus.gd").read_text(encoding="utf-8")
        self.assertIn("FGDMangle.mangle_sources(files, key, exclude)", runner)
        self.assertIn("FGDMangle.mangle_key(args[1])", runner)

    def test_plugin_never_rewrites_addons(self) -> None:
        gd = _mangle_gd()
        walk = _gd_func_body(gd, "_walk")
        self.assertIn("rel.begins_with(ADDONS_DIR + \"/\")", walk)
        self.assertIn('const ADDONS_DIR := "addons"', gd)
        apply = _gd_func_body(gd, "apply_project")
        self.assertIn("list_scan_only_gdscript_files()", apply)
        self.assertIn("collect_scan_only_names(", apply)
        # Unsafe-call scanning only covers the files that get rewritten.
        self.assertIn("for path in list_gdscript_files()", apply)

    def test_plugin_keeps_scene_and_export_names(self) -> None:
        gd = _mangle_gd()
        self.assertIn('val.begins_with("@export")', _gd_func_body(gd, "_has_export_annotation"))
        self.assertIn('"@export_group"', gd)
        self.assertIn("_has_export_annotation(tokens, i)", _gd_func_body(gd, "collect_user_identifiers"))
        self.assertIn('".tscn"', gd)
        self.assertIn('".tres"', gd)
        self.assertIn('"project.godot"', gd)
        apply = _gd_func_body(gd, "apply_project")
        self.assertIn("collect_resource_reference_names()", apply)
        self.assertIn("push_warning", apply)
        self.assertIn("binary_resource_paths()", apply)

    def test_plugin_excludes_string_identifier_names(self) -> None:
        gd = _mangle_gd()
        body = _gd_func_body(gd, "collect_string_identifier_names")
        self.assertIn('begins_with("&")', body)
        self.assertIn('begins_with("^")', body)
        self.assertIn('.replace(":", "/").replace(".", "/").split("/")', body)
        self.assertIn("collect_string_identifier_names(", _gd_func_body(gd, "mangle_sources"))

    def test_agent_rules_mention_string_literal_and_runtime_names(self) -> None:
        text = (ROOT / "docs" / "agent-rules.md").read_text(encoding="utf-8")
        self.assertIn("string literals", text)
        self.assertIn("built at runtime", text)
        self.assertIn("## fortressgd:keep", text)

    def test_plugin_excludes_foreign_member_names(self) -> None:
        gd = _mangle_gd()
        body = _gd_func_body(gd, "collect_foreign_member_names")
        self.assertIn('["self", "super"]', body)
        self.assertIn("collect_foreign_member_names(", _gd_func_body(gd, "mangle_sources"))
        self.assertIn("user.erase(", _gd_func_body(gd, "mangle_sources"))
        self.assertIn("mangle_sources(files, key, exclude)", _gd_func_body(gd, "apply_project"))

    def test_plugin_strip_emits_pass(self) -> None:
        body = _gd_func_body(_mangle_gd(), "_strip_tokens")
        self.assertEqual(body.count('_tok(KIND_IDENT, "pass"'), 2)

    def test_plugin_participates_when_mangle_scripts_true(self) -> None:
        addon = PKG / "plugin" / "addons" / "fortressgd"
        export_gd = (addon / "export_plugin.gd").read_text(encoding="utf-8")
        self.assertIn("extends EditorExportPlugin", export_gd)
        self.assertIn("mangle_scripts", export_gd)
        self.assertIn("mangle.gd", export_gd)
        self.assertIn("FGDMangle.write_map(", export_gd)
        # Keyed by the secret-derived key, never the public secret_hash.
        self.assertIn("FGDMangle.apply_project(FGDMangle.mangle_key(hex_secret))", export_gd)
        self.assertNotIn("apply_project(_mangle_secret_hash)", export_gd)
        self.assertIn("FORTRESSGD_CLI_EXPORT", export_gd)
        self.assertIn('return "GDScript.FortressGD"', export_gd)
        mangle_gd = (addon / "mangle.gd").read_text(encoding="utf-8")
        self.assertIn("fortressgd:keep", mangle_gd)
        self.assertIn("call", mangle_gd)
        self.assertIn("hmac_digest", _gd_func_body(mangle_gd, "mangled_identifier"))
        self.assertIn('const MANGLE_INFO := "fortressgd-mangle-v2"', mangle_gd)
        self.assertIn('const MAP_DIR := ".fortressgd/maps"', mangle_gd)
        self.assertIn(".gdignore", _gd_func_body(mangle_gd, "write_map"))
        reserved = json.loads((addon / "mangle_reserved.json").read_text(encoding="utf-8"))
        self.assertIn("_ready", reserved["lifecycle"])

    def test_plugin_walk_keeps_res_scheme_slashes(self) -> None:
        """Godot FileAccess needs res://file, not res:/file from rstrip('/')."""
        mangle_gd = (PKG / "plugin" / "addons" / "fortressgd" / "mangle.gd").read_text(
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
        addon = PKG / "plugin" / "addons" / "fortressgd"
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
            series = (PKG / "patches" / tag / "series").read_text(encoding="utf-8")
            self.assertEqual(
                [ln.strip() for ln in series.splitlines() if ln.strip()][:2],
                ["0001-key-derive.patch", "0002-pack-hooks.patch"],
            )
            patch_dir = PKG / "patches" / tag
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

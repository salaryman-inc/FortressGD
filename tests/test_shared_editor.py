"""The shared export editor (DESIGN.md §18.5): its fixed dialect header, the
FORTRESSGD_PACK_PARAMS format, the entrypoint's editor target and build_editor.

The editor is built once per Godot tag with patches/common/fortressgd_editor_dialect.h
installed as core/dialect.gen.h. `fortressgd export` passes each project's pack
magic and index field order in FORTRESSGD_PACK_PARAMS. These tests check that the
C++ reader and the Python writer agree on that format, and that the editor build
holds nothing project-specific.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fortressgd.core.pack_dialect import PACK_PARAMS_ENV, format_pack_params, parse_pack_params
from fortressgd.core.templates import (
    build_editor,
    editor_cache_home,
    editor_filename,
    editor_header_id,
    editor_header_path,
    find_cached_editor,
    patchset_for_tag,
)
from fortressgd.generator.dialect import (
    STOCK_INDEX_PERM,
    STOCK_PACK_MAGIC,
    derive_index_perm,
    derive_pack_magic,
    render_dialect_header,
    write_dialect_header,
)
from tests.support import PKG, ROOT, seed_mini_godot_tree

HEADER = editor_header_path()

# Two translation units that use the header the way the patches do. Both include
# it, so a definition that breaks the one-definition rule fails to link.
_USE = r"""
#include "dialect.gen.h"
#define PACK_HEADER_MAGIC FGD_PACK_MAGIC
int fgd_is_pack_magic(uint32_t magic) { return magic == PACK_HEADER_MAGIC; }
int fgd_field(int i) {
	switch (FGD_INDEX_PERM[i]) {
		case 0: return 10;
		case 1: return 11;
		case 2: return 12;
		case 3: return 13;
	}
	return -1;
}
int fgd_key_byte(int shard, int i) { return FGD_KEY_SHARDS[shard][i] ^ FGD_KEY_MASKS[shard][i]; }
int fgd_requires_signature() { return FGD_REQUIRE_PACK_SIGNATURE ? 1 : FGD_PACK_PUBKEY[0]; }
"""

_MAIN = r"""
#include "dialect.gen.h"
#include <cstdio>
#include <cstring>
int fgd_is_pack_magic(uint32_t magic);
int fgd_field(int i);
int fgd_key_byte(int shard, int i);
int fgd_requires_signature();

int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "parse") == 0) {
		// One line per stdin line: 1 if the editor accepts it, else 0.
		static char line[256];
		while (fgets(line, sizeof(line), stdin)) {
			line[strcspn(line, "\n")] = 0;
			FortressgdPackParams params;
			printf("%d\n", fortressgd_parse_pack_params(line, &params) == 0 ? 1 : 0);
		}
		return 0;
	}
	int key = 0;
	for (int s = 0; s < 4; s++) {
		for (int i = 0; i < 8; i++) {
			key |= fgd_key_byte(s, i);
		}
	}
	printf("%08x %d%d%d%d %d %d %d\n", (unsigned)FGD_PACK_MAGIC, FGD_INDEX_PERM[0], FGD_INDEX_PERM[1],
			FGD_INDEX_PERM[2], FGD_INDEX_PERM[3], fgd_is_pack_magic(FGD_PACK_MAGIC), key, fgd_requires_signature());
	return 0;
}
"""

# Strings the editor must refuse, and the Python parser with it.
MALFORMED = [
    "0",
    "1",
    "1:",
    "2:9f3c1a77:2013",
    "1:9f3c1a7:2013",
    "1:9f3c1a777:2013",
    "1:9F3C1A77:2013",
    "1:9f3c1a7g:2013",
    "1:9f3c1a77:201",
    "1:9f3c1a77:20134",
    "1:9f3c1a77:2213",
    "1:9f3c1a77:2014",
    "1:9f3c1a77-2013",
    "1:00000000:2013",
    "1:{0:08x}:0123".format(STOCK_PACK_MAGIC),
    " 1:9f3c1a77:2013",
    "1:9f3c1a77:2013 ",
]


def _secrets(n: int = 64) -> list[bytes]:
    return [hashlib.sha256(b"fortressgd.test.editor|%d" % i).digest() for i in range(n)]


def _compilers() -> list[str]:
    return [c for c in ("g++", "clang++") if shutil.which(c)]


class PackParamsFormatTests(unittest.TestCase):
    def test_round_trip_for_derived_values(self) -> None:
        for tag in ("4.6.2", "4.7.2"):
            for secret in _secrets(16):
                magic, perm = derive_pack_magic(secret, tag), derive_index_perm(secret, tag)
                text = format_pack_params(magic, perm)
                self.assertRegex(text, r"^1:[0-9a-f]{8}:[0-3]{4}$")
                self.assertEqual(parse_pack_params(text), (magic, perm))

    def test_unset_and_empty_mean_stock(self) -> None:
        self.assertEqual(parse_pack_params(None), (STOCK_PACK_MAGIC, STOCK_INDEX_PERM))
        self.assertEqual(parse_pack_params(""), (STOCK_PACK_MAGIC, STOCK_INDEX_PERM))

    def test_malformed_values_are_refused(self) -> None:
        for text in MALFORMED:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_pack_params(text)

    def test_format_refuses_stock_or_zero_magic_and_bad_order(self) -> None:
        for magic, perm in ((STOCK_PACK_MAGIC, (0, 1, 2, 3)), (0, (0, 1, 2, 3)), (1 << 32, (0, 1, 2, 3)), (5, (0, 0, 1, 2))):
            with self.subTest(magic=magic, perm=perm), self.assertRaises(ValueError):
                format_pack_params(magic, perm)


class EditorHeaderTests(unittest.TestCase):
    """Compile the editor header with each C++ compiler on PATH and run it."""

    @classmethod
    def setUpClass(cls) -> None:
        required = [c for c in os.environ.get("FORTRESSGD_REQUIRE_COMPILERS", "").split(",") if c]
        missing = [c for c in required if c in ("g++", "clang++") and c not in _compilers()]
        if missing:
            raise AssertionError("FORTRESSGD_REQUIRE_COMPILERS names compilers that are not on PATH: {0}".format(missing))
        cls._tmp = tempfile.TemporaryDirectory()
        work = Path(cls._tmp.name)
        shutil.copy2(HEADER, work / "dialect.gen.h")
        (work / "use.cpp").write_text(_USE, encoding="utf-8")
        (work / "main.cpp").write_text(_MAIN, encoding="utf-8")
        cls.binaries = {}
        for cxx in _compilers():
            exe = work / "editor-{0}".format(cxx.replace("+", "p"))
            subprocess.run(
                [cxx, "-std=c++17", "-O2", "-Wall", "-Werror", "-I", str(work), "use.cpp", "main.cpp", "-o", str(exe)],
                cwd=work, check=True, capture_output=True, timeout=120,
            )
            cls.binaries[cxx] = exe

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        if not self.binaries:
            self.skipTest("no C++ compiler on PATH")

    def _run(self, exe: Path, value: str | None, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k != PACK_PARAMS_ENV}
        if value is not None:
            env[PACK_PARAMS_ENV] = value
        return subprocess.run([str(exe), *args], env=env, input=stdin, capture_output=True, text=True, timeout=30)

    def test_unset_and_empty_read_and_write_stock_packs(self) -> None:
        for cxx, exe in self.binaries.items():
            for value in (None, ""):
                with self.subTest(compiler=cxx, value=value):
                    run = self._run(exe, value)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(run.stdout.split(), ["{0:08x}".format(STOCK_PACK_MAGIC), "0123", "1", "0", "0"])

    def test_editor_reads_the_values_export_passes(self) -> None:
        for cxx, exe in self.binaries.items():
            for tag in ("4.6.2", "4.7.2"):
                for secret in _secrets(16):
                    magic, perm = derive_pack_magic(secret, tag), derive_index_perm(secret, tag)
                    with self.subTest(compiler=cxx, tag=tag, magic=magic):
                        run = self._run(exe, format_pack_params(magic, perm))
                        self.assertEqual(run.returncode, 0, run.stderr)
                        # No key and no signature requirement are compiled in.
                        self.assertEqual(
                            run.stdout.split(),
                            ["{0:08x}".format(magic), "".join(map(str, perm)), "1", "0", "0"],
                        )

    def test_malformed_value_stops_the_editor_before_any_pack(self) -> None:
        for cxx, exe in self.binaries.items():
            for value in MALFORMED:
                with self.subTest(compiler=cxx, value=value):
                    run = self._run(exe, value)
                    self.assertEqual(run.returncode, 2)
                    self.assertEqual(run.stdout, "")
                    self.assertIn(PACK_PARAMS_ENV + " is malformed", run.stderr)

    def test_cpp_and_python_parsers_accept_the_same_strings(self) -> None:
        good = [format_pack_params(derive_pack_magic(s, "4.6.2"), derive_index_perm(s, "4.6.2")) for s in _secrets(8)]
        cases = good + MALFORMED + ["1:{0:08x}:3210".format(0xFFFFFFFF), "1:00000001:1032"]
        expected = []
        for text in cases:
            try:
                parse_pack_params(text)
                expected.append("1")
            except ValueError:
                expected.append("0")
        for cxx, exe in self.binaries.items():
            with self.subTest(compiler=cxx):
                run = self._run(exe, None, "parse", stdin="".join(c + "\n" for c in cases))
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout.split(), expected)


class EditorHeaderContentTests(unittest.TestCase):
    def test_defines_every_name_the_patches_take_from_a_generated_header(self) -> None:
        generated = render_dialect_header(_secrets(1)[0], "4.6.2")
        names = set(re.findall(r"\b(FGD_[A-Z_]+)\b", generated))
        editor = HEADER.read_text(encoding="utf-8")
        # The editor is built without FORTRESSGD_OPCODE_MAP: packs carry tokens.
        for name in sorted(n for n in names if not n.startswith("FGD_OPCODE_")):
            with self.subTest(name=name):
                self.assertRegex(editor, r"(#define|uint8_t|uint32_t) +{0}\b".format(name))
        self.assertIn("#define FORTRESSGD_DIALECT_GEN_H", editor)

    def test_holds_no_project_values(self) -> None:
        code = "\n".join(
            line for line in HEADER.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith(("/*", "*"))
        )
        # The only numbers are the stock magic; the arrays are zero-initialised.
        self.assertEqual(re.findall(r"0x[0-9a-fA-F]+", code), ["0x43504447"])
        self.assertRegex(code, r"FGD_KEY_SHARDS\[4\]\[8\] = \{\};")
        self.assertRegex(code, r"FGD_KEY_MASKS\[4\]\[8\] = \{\};")
        self.assertRegex(code, r"FGD_PACK_PUBKEY\[32\] = \{\};")
        self.assertIn("FGD_REQUIRE_PACK_SIGNATURE = 0;", code)


def _entrypoint_env(tmp: Path, header: Path, *, target: str, platform: str = "linux") -> dict[str, str]:
    env = os.environ.copy()
    env.pop("FGD_SECRET_HASH", None)
    env.update({
        "GODOT_VERSION": "4.6.2-stable", "FGD_GODOT": "4.6.2", "FGD_PLATFORM": platform,
        "FGD_ARCH": "x86_64", "FGD_PATCHSET": patchset_for_tag("4.6.2"), "FGD_TARGET": target,
        "FORTRESSGD_SKIP_SCONS": "1", "PATCHES_DIR": str(PKG / "patches" / "4.6.2"),
        "DIALECT_HEADER": str(header), "OUT_DIR": str(tmp / "out"), "GODOT_SRC": str(tmp / "godot"),
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def _entrypoint(env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", str(PKG / "docker" / "entrypoint.sh")], capture_output=True, text=True, env=env, timeout=180)


class EditorEntrypointTests(unittest.TestCase):
    def test_editor_target_needs_no_secret_hash_and_installs_the_fixed_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            godot_src = seed_mini_godot_tree("4.6.2", tmp_path / "godot")
            run = _entrypoint(_entrypoint_env(tmp_path, HEADER, target="editor"))
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            name = editor_filename("4.6.2", "x86_64", patchset_for_tag("4.6.2"), editor_header_id())
            out = tmp_path / "out"
            self.assertTrue((out / name).is_file(), sorted(p.name for p in out.iterdir()))
            manifest = json.loads((out / (name + ".manifest.json")).read_text(encoding="utf-8"))
            self.assertEqual(manifest["target"], "editor")
            self.assertEqual(manifest["editor_header_id"], editor_header_id())
            self.assertEqual(manifest["patchset_id"], patchset_for_tag("4.6.2"))
            for key in ("secret_hash", "dialect_id", "key_epoch", "require_signature"):
                self.assertNotIn(key, manifest)
            self.assertEqual((godot_src / "core" / "dialect.gen.h").read_bytes(), HEADER.read_bytes())

    def test_editor_target_refuses_a_generated_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            header = write_dialect_header(tmp_path / "dialect.gen.h", _secrets(1)[0], "4.6.2")
            run = _entrypoint(_entrypoint_env(tmp_path, header, target="editor"))
            self.assertEqual(run.returncode, 3, run.stdout + run.stderr)
            self.assertIn("needs the fixed fortressgd_editor_dialect.h", run.stderr)

    def test_template_target_refuses_the_editor_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = _entrypoint_env(Path(tmp), HEADER, target="template_release")
            env["FGD_SECRET_HASH"] = "0123456789abcdef"
            run = _entrypoint(env)
            self.assertEqual(run.returncode, 3, run.stdout + run.stderr)
            self.assertIn("not the editor header", run.stderr)

    def test_editor_target_is_linux_only_and_target_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = _entrypoint(_entrypoint_env(Path(tmp), HEADER, target="editor", platform="windows"))
            self.assertEqual(run.returncode, 3)
            self.assertIn("linux only", run.stderr)
            run = _entrypoint(_entrypoint_env(Path(tmp), HEADER, target="template_debug"))
            self.assertEqual(run.returncode, 3)
            self.assertIn("FGD_TARGET must be", run.stderr)

    def test_editor_builds_without_lto_and_checks_its_defines(self) -> None:
        entry = (PKG / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
        code = "\n".join(line for line in entry.splitlines() if not line.lstrip().startswith("#"))
        editor_scons = next(line for line in code.splitlines() if "target=editor" in line)
        self.assertNotIn("production=yes", editor_scons)
        self.assertIn('FGD_DEFINES="FORTRESSGD_DIALECT"', code)
        self.assertIn('grep -aqF "FORTRESSGD_PACK_PARAMS" "$BIN"', code)


# Runs the shipped entrypoint on the host in place of `docker run`, with the
# mounts mapped to paths, so build_editor is exercised end to end.
FAKE_DOCKER = """#!{python}
import os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
if args[:2] == ["image", "inspect"]:
    sys.exit(0)
Path(os.environ["FAKE_DOCKER_ARGS"]).write_text("\\n".join(args), encoding="utf-8")
env, vols, i = dict(os.environ), {{}}, 1
while i < len(args):
    if args[i] in ("-e", "-v"):
        if args[i] == "-e":
            key, value = args[i + 1].split("=", 1)
            env[key] = value
        else:
            parts = args[i + 1].split(":")
            vols[parts[1]] = parts[0]
        i += 2
    else:
        i += 1
env.update({{
    "PATCHES_DIR": vols["/patches"], "DIALECT_HEADER": vols["/src/dialect.gen.h"],
    "OUT_DIR": vols["/out"], "GODOT_SRC": os.environ["FAKE_GODOT_SRC"],
}})
sys.exit(subprocess.run(["sh", {entry!r}], env=env).returncode)
"""


class BuildEditorTests(unittest.TestCase):
    def test_build_editor_caches_the_shared_editor_without_a_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bindir = tmp_path / "bin"
            bindir.mkdir()
            docker = bindir / "docker"
            docker.write_text(
                FAKE_DOCKER.format(python=sys.executable, entry=str(PKG / "docker" / "entrypoint.sh")),
                encoding="utf-8",
            )
            docker.chmod(docker.stat().st_mode | stat.S_IXUSR)
            godot_src = seed_mini_godot_tree("4.6.2", tmp_path / "godot")
            args_log = tmp_path / "docker-args.txt"
            env = {
                "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
                "FAKE_DOCKER_ARGS": str(args_log),
                "FAKE_GODOT_SRC": str(godot_src),
            }
            cache = tmp_path / "cache"
            with mock.patch.dict(os.environ, env):
                os.environ.pop("FORTRESSGD_SECRET", None)
                path = build_editor(godot="4.6.2", environ={}, cache_dir=cache, skip_scons=True)
            self.assertEqual(path, find_cached_editor(godot="4.6.2", cache_dir=cache))
            self.assertTrue(os.access(path, os.X_OK))
            self.assertEqual(json.loads(Path(str(path) + ".manifest.json").read_text())["target"], "editor")
            args = args_log.read_text(encoding="utf-8")
            self.assertIn("FGD_TARGET=editor", args)
            self.assertIn("{0}:/src/dialect.gen.h:ro".format(HEADER), args)
            self.assertNotIn("FGD_SECRET_HASH", args)
            self.assertNotIn("FORTRESSGD_SECRET", args)

    def test_cached_editor_name_follows_the_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            patches = Path(tmp) / "patches"
            shutil.copytree(PKG / "patches", patches)
            before = editor_header_id(patches)
            with (patches / "common" / HEADER.name).open("a", encoding="utf-8") as fh:
                fh.write("/* changed */\n")
            self.assertNotEqual(editor_header_id(patches), before)


class FindDialectEditorTests(unittest.TestCase):
    def _cache_editor(self, cache: Path) -> Path:
        name = editor_filename("4.6.2", "x86_64", patchset_for_tag("4.6.2"), editor_header_id())
        path = cache / "templates" / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b"\x7fELF shared editor")
        return path

    def test_order_is_fortressgd_editor_then_cached_then_godot(self) -> None:
        from fortressgd.core.export import find_dialect_editor

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            cached = self._cache_editor(cache)
            env = {"FORTRESSGD_GODOT": "/opt/official-godot", "PATH": ""}
            with mock.patch.object(sys, "platform", "linux"):
                self.assertEqual(find_dialect_editor("4.6.2", environ=env, cache_dir=cache), str(cached))
                env_editor = dict(env, FORTRESSGD_EDITOR="/opt/fgd-editor")
                self.assertEqual(find_dialect_editor("4.6.2", environ=env_editor, cache_dir=cache), "/opt/fgd-editor")
                # Another tag has no cached editor, so the Godot lookup is next.
                self.assertEqual(find_dialect_editor("4.7.2", environ=env, cache_dir=cache), "/opt/official-godot")

    def test_cached_linux_editor_is_skipped_on_other_hosts(self) -> None:
        from fortressgd.core.export import find_dialect_editor

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            self._cache_editor(cache)
            with mock.patch.object(sys, "platform", "darwin"):
                self.assertEqual(
                    find_dialect_editor("4.6.2", environ={"GODOT": "/opt/godot", "PATH": ""}, cache_dir=cache),
                    "/opt/godot",
                )

    def test_missing_editor_names_the_build_command(self) -> None:
        from fortressgd.core.errors import UserError
        from fortressgd.core.export import find_dialect_editor

        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(UserError) as caught:
            find_dialect_editor("4.6.2", environ={"PATH": tmp}, cache_dir=Path(tmp))
        self.assertIn("fortressgd templates build --editor --godot 4.6.2", caught.exception.format())


class CliEditorFlagTests(unittest.TestCase):
    def test_editor_flag_refuses_template_options(self) -> None:
        from tests.support import run_fortressgd

        with tempfile.TemporaryDirectory() as tmp:
            for extra in (["--platform", "linux"], ["--require-signature"], ["--key-epoch", "1"]):
                with self.subTest(extra=extra):
                    proc = run_fortressgd("templates", "build", "--editor", "--godot", "4.6.2", *extra, cwd=Path(tmp))
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertIn("--editor builds only the shared editor", proc.stderr)


class EditorCacheHomeTests(unittest.TestCase):
    """XDG_CACHE_HOME for the shared editor: one directory per editor binary."""

    def test_under_the_fortressgd_cache_and_named_after_the_editor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            editor = Path(tmp) / "godot-4.7.2-editor-linux-x86_64-fgdabc-p1234"
            editor.write_bytes(b"editor")
            home = editor_cache_home(editor, Path(tmp) / "cache")
            self.assertEqual(home.parent, Path(tmp) / "cache" / "editor-cache")
            self.assertRegex(home.name, r"^godot-4\.7\.2-editor-linux-x86_64-fgdabc-p1234-[0-9a-f]{12}$")
            self.assertEqual(home, editor_cache_home(editor, Path(tmp) / "cache"))

    def test_each_binary_gets_its_own_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a" / "godot"
            b = Path(tmp) / "b" / "godot"
            for path in (a, b):
                path.parent.mkdir()
                path.write_bytes(b"editor")
            self.assertNotEqual(editor_cache_home(a, tmp), editor_cache_home(b, tmp))

    def test_a_binary_rebuilt_in_place_gets_a_new_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            editor = Path(tmp) / "godot"
            editor.write_bytes(b"editor build 1")
            before = editor_cache_home(editor, tmp)
            editor.write_bytes(b"editor build 2, longer")
            self.assertNotEqual(before, editor_cache_home(editor, tmp))

    def test_a_missing_binary_still_gets_a_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = editor_cache_home(Path(tmp) / "nope" / "godot", tmp)
            self.assertEqual(home.parent, Path(tmp) / "editor-cache")


if __name__ == "__main__":
    unittest.main()

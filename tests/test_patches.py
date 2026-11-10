"""Patch series layout and git apply --check against Godot stable tags."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fortressgd.core.errors import ToolError
from fortressgd.core.patches import git_apply_check, git_apply_series, patch_files, require_series
from tests.support import PKG, ROOT, run_fortressgd, seed_mini_godot_tree, write_godot_stub

KEYDOT_ANCHOR = "Can't open encrypted pack directory."


class PatchTests(unittest.TestCase):
    def test_series_lists_key_derive_then_pack_hooks(self) -> None:
        for tag in ("4.6.2", "4.7.2"):
            tag_dir = PKG / "patches" / tag
            names = require_series(tag_dir)
            self.assertEqual(names[0], "0001-key-derive.patch")
            self.assertEqual(names[1], "0002-pack-hooks.patch")
            self.assertEqual(names[2], "0003-nameless-bytecode.patch")
            self.assertEqual(names[3], "0004-opcode-map.patch")
            self.assertEqual(names[4], "0005-pack-signatures.patch")
            self.assertEqual(names[5], "0006-signed-file-md5.patch")
            patch = tag_dir / "0001-key-derive.patch"
            text = patch.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("diff --git"), msg=tag)
            self.assertIn("fortressgd_derive_key", text)
            self.assertIn("+++ b/core/fortressgd_kdf.cpp", text)
            self.assertIn("FGD-KDF-1", text)
            hooks = (tag_dir / "0002-pack-hooks.patch").read_text(encoding="utf-8")
            self.assertTrue(hooks.startswith("diff --git"), msg=tag)
            self.assertIn("FGD_PACK_MAGIC", hooks)
            self.assertIn("FGD_INDEX_PERM", hooks)
            self.assertIn("FORTRESSGD_DIALECT", hooks)
            self.assertIn("file_access_pack.cpp", hooks)
            self.assertIn("pck_packer.cpp", hooks)
            self.assertIn("editor_export_platform.cpp", hooks)
            nameless = (tag_dir / "0003-nameless-bytecode.patch").read_text(encoding="utf-8")
            self.assertTrue(nameless.startswith("diff --git"), msg=tag)
            self.assertIn("FORTRESSGD_NAMELESS", nameless)
            self.assertIn("FGDN", nameless)
            self.assertIn("gdscript_tokenizer_buffer.cpp", nameless)
            opmap = (tag_dir / "0004-opcode-map.patch").read_text(encoding="utf-8")
            self.assertTrue(opmap.startswith("diff --git"), msg=tag)
            self.assertIn("FORTRESSGD_OPCODE_MAP", opmap)
            self.assertIn("FGD_OPCODE_MAP", opmap)
            self.assertIn("FGD_OPCODE_UNMAP", opmap)
            self.assertIn("gdscript_byte_codegen.h", opmap)
            self.assertIn("gdscript_vm.cpp", opmap)
            sig = (tag_dir / "0005-pack-signatures.patch").read_text(encoding="utf-8")
            self.assertTrue(sig.startswith("diff --git"), msg=tag)
            self.assertIn("FORTRESSGD_SIGN_PACKS", sig)
            self.assertIn("fortressgd_ed25519", sig)
            self.assertIn("FGD_PACK_PUBKEY", sig)

    def test_apply_check_on_upstream_tag(self) -> None:
        log_lines = []
        for tag in ("4.6.2", "4.7.2"):
            with tempfile.TemporaryDirectory() as tmp:
                work = seed_mini_godot_tree(tag, Path(tmp))
                pack = work / "core" / "io" / "file_access_pack.cpp"
                files = patch_files(PKG / "patches" / tag)
                git_apply_check(work, files)
                git_apply_series(work, files)
                patched = pack.read_text(encoding="utf-8")
                header = (work / "core" / "io" / "file_access_pack.h").read_text(encoding="utf-8")
                packer = (work / "core" / "io" / "pck_packer.cpp").read_text(encoding="utf-8")
                exporter = (work / "editor" / "export" / "editor_export_platform.cpp").read_text(
                    encoding="utf-8"
                )
                kdf = (work / "core" / "fortressgd_kdf.cpp").read_text(encoding="utf-8")
                self.assertIn("fortressgd_derive_key", patched)
                self.assertNotIn(KEYDOT_ANCHOR, patched)
                self.assertNotIn("memcpy(key.ptrw(), script_encryption_key, 32)", patched)
                self.assertNotIn("key.write[i] = script_encryption_key[i]", patched)
                self.assertIn("fortressgd_wipe", patched)
                # The template decodes the pack key with the per-build generated
                # fgd_derive_key() (generator v2); it never holds the project
                # secret, the salt or the v1 masked shards, and runs no KDF.
                self.assertIn("fgd_derive_key", kdf)
                for gone in (
                    "FGD_KEY_SHARDS", "FGD_KEY_MASKS", "FGD_SHARDS", "FGD_SHARD_MASKS",
                    "FGD_DIALECT_SALT", "hkdf", "secret[",
                ):
                    self.assertNotIn(gone, kdf)
                for blob in (header, patched, packer, exporter):
                    self.assertIn("FORTRESSGD_DIALECT", blob)
                self.assertIn("FGD_PACK_MAGIC", header)
                self.assertIn("FGD_INDEX_PERM", patched)
                self.assertIn("FGD_INDEX_PERM", packer)
                self.assertIn("FGD_INDEX_PERM", exporter)
                tok = (work / "modules" / "gdscript" / "gdscript_tokenizer_buffer.cpp").read_text(
                    encoding="utf-8"
                )
                codegen = (work / "modules" / "gdscript" / "gdscript_byte_codegen.h").read_text(
                    encoding="utf-8"
                )
                vm = (work / "modules" / "gdscript" / "gdscript_vm.cpp").read_text(encoding="utf-8")
                self.assertIn("FORTRESSGD_NAMELESS", tok)
                self.assertIn("FGDN", tok)
                fgdn_load = tok.find("FGDN runtime names must be loaded before _binary_to_token")
                binary_to_token = tok.find("Token token = _binary_to_token(b);")
                self.assertGreaterEqual(fgdn_load, 0, msg=tag)
                self.assertGreaterEqual(binary_to_token, 0, msg=tag)
                self.assertLess(fgdn_load, binary_to_token, msg=tag)
                write_fgdn = tok.find("contents.write[tpos + 0] = 'F';")
                append_tokens = tok.find("contents.append_array(token_buffer);")
                self.assertGreaterEqual(write_fgdn, 0, msg=tag)
                self.assertLess(write_fgdn, append_tokens, msg=tag)
                self.assertIn("FGD_OPCODE_MAP", codegen)
                self.assertIn("FGD_OPCODE_UNMAP", vm)
                self.assertIn("FORTRESSGD_SIGN_PACKS", patched)
                # #11: signatures are enforced, cover encrypted directories, and are
                # verified before any index entry is registered.
                sign_start = patched.index("struct FGDPackEntry")
                sign_block = patched[sign_start : patched.index("return true;", sign_start)]
                self.assertIn("FGD_REQUIRE_PACK_SIGNATURE", sign_block, msg=tag)
                self.assertIn('"Pack signature missing."', sign_block, msg=tag)
                self.assertNotIn("!enc_directory &&", sign_block, msg=tag)
                self.assertIn("fgd_dir_abs + 4 + 16 + 8 + 16", sign_block, msg=tag)
                verify_at = sign_block.index("fortressgd_ed25519_verify(")
                push_at = sign_block.index("fgd_entries.push_back(fgd_entry);")
                register_at = sign_block.index("for (const FGDPackEntry &fgd_e : fgd_entries)")
                self.assertLess(push_at, verify_at, msg=tag)
                self.assertLess(verify_at, register_at, msg=tag)
                self.assertEqual(
                    sign_block.count("PackedData::get_singleton()->add_path("),
                    2,  # the #else (no SIGN_PACKS) branch and the deferred one
                    msg=tag,
                )
                if tag == "4.7.2":
                    # The V4 sparse-bundle salt at offset 40 is read before, and instead
                    # of, the signature.
                    salt_at = patched.index("Vector<uint8_t> salt_data = f->get_buffer(32);")
                    sig_at = patched.index("f->get_buffer(fgd_sig, 64);")
                    self.assertLess(salt_at, sig_at)
                    self.assertIn("not supported for encrypted sparse bundles", patched)
                self.assertTrue((work / "core" / "fortressgd_ed25519.cpp").is_file())
                # 0006: a -sig template holds each opened file to its signed index MD5.
                pack_cpp = (work / "core" / "io" / "file_access_pack.cpp").read_text(encoding="utf-8")
                self.assertIn("does not match the signed index", pack_cpp)
                self.assertIn("memcmp(fgd_md5, pf.md5, 16)", pack_cpp)
                self.assertIn("f = Ref<FileAccess>();", pack_cpp)
                log_lines.append(
                    "{0}: git apply --check+apply ok; derive+wipe; dialect magic/perm; nameless; opcode map; sign".format(tag)
                )
        self._log = "\n".join(log_lines)

    def test_empty_series_templates_build_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            series_parent = root / "empty-patches"
            tag_dir = series_parent / "4.6.2"
            tag_dir.mkdir(parents=True)
            (tag_dir / "series").write_text("\n# nothing\n", encoding="utf-8")
            init = run_fortressgd("init", cwd=root)
            self.assertEqual(init.returncode, 0, init.stderr)
            gen = run_fortressgd("secret", "generate", cwd=root)
            self.assertEqual(gen.returncode, 0, gen.stderr)
            proc = run_fortressgd(
                "templates",
                "build",
                "--godot",
                "4.6.2",
                "--platform",
                "linux",
                "--patches-dir",
                str(series_parent),
                cwd=root,
            )
            self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
            combined = proc.stdout + proc.stderr
            self.assertIn("error:", combined)
            self.assertIn("Run:", combined)
            self.assertIn("empty", combined.lower())

    def test_require_series_raises_toolerror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tag_dir = Path(tmp) / "4.6.2"
            tag_dir.mkdir()
            (tag_dir / "series").write_text("", encoding="utf-8")
            with self.assertRaises(ToolError) as ctx:
                require_series(tag_dir)
            self.assertIn("empty", str(ctx.exception).lower())
            self.assertIn("error:", ctx.exception.format())
            self.assertIn("Run:", ctx.exception.format())


if __name__ == "__main__":
    unittest.main()

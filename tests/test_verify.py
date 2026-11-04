"""Subprocess tests against shipped `fortressgd verify`."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from core.config import default_toml_text
from core.gdc import (
    FGDN_MAGIC,
    GDSC_MAGIC,
    TOKENIZER_VERSION,
    encode_gdsc,
    encode_ident_entry,
    encode_identifier_token,
    parse_gdsc_engine_order,
)
from core.pack import PACK_DIR_ENCRYPTED, PACK_FILE_ENCRYPTED
from core.pack_dialect import (
    dialect_key_for_secret,
    dialect_params_for_secret,
    embed_exe_dialect,
    encode_dialect_index,
    encrypt_fae_directory,
    read_dialect_listing,
)
from core.pack_sign import apply_signature, public_key_for_secret, sign_index, verify_index
from core.secret import generate_secret_hex, read_secret_file, secret_bytes_from_hex
from tests.gdpc_fixture import embed_exe, make_gdpc
from tests.support import run_fortressgd, write_godot_stub

try:
    from compression import zstd as _zstd  # type: ignore[import-not-found]  # noqa: F401

    _HAVE_ZSTD = True
except ImportError:
    _HAVE_ZSTD = False


def _write_pck(directory: Path, name: str, paths: list[str], *, version: int = 3) -> Path:
    path = directory / name
    path.write_bytes(make_gdpc(paths, version=version))
    return path


class VerifyCliTests(unittest.TestCase):
    def test_clean_pck_and_exe_exit_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pck = _write_pck(root, "game.pck", ["main.tscn", "main.gdc", "icon.svg"])
            exe = root / "game.exe"
            exe.write_bytes(embed_exe(make_gdpc(["main.tscn", "main.gdc"])))
            for artifact in (pck, exe):
                proc = run_fortressgd("verify", str(artifact), cwd=root)
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("ok:", proc.stdout + proc.stderr)

    def test_each_leak_kind_exits_2_with_path(self) -> None:
        cases = [
            ("leaky.gd", "scripts/main.gd", "*.gd"),
            ("leaky.cs", "Net.cs", "*.cs"),
            ("leaky.blend", "hero.blend", "*.blend"),
            ("leaky.map", "out.fortressgd.map.json", "*.fortressgd.map.json"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, packed, pattern in cases:
                artifact = _write_pck(root, name + ".pck", ["main.tscn", packed])
                proc = run_fortressgd("verify", str(artifact), cwd=root)
                combined = proc.stdout + proc.stderr
                self.assertEqual(proc.returncode, 2, combined)
                self.assertIn("error:", combined)
                self.assertIn("Run:", combined)
                self.assertIn(packed, combined)
                self.assertIn(pattern, combined)

    def test_include_allowlist_exempts_gd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            text = default_toml_text().replace("include = []", 'include = ["*.gd"]')
            text = text.replace("dialect = true", "dialect = false")
            (root / ".fortressgd.toml").write_text(text, encoding="utf-8")
            pck = _write_pck(root, "mods.pck", ["main.tscn", "mods/hook.gd"])
            proc = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_custom_exclude_from_toml_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            text = default_toml_text().replace("dialect = true", "dialect = false")
            text = text.replace('  "*.tmp",\n', '  "*.tmp",\n  "design_docs/*",\n')
            self.assertIn("design_docs/*", text)
            (root / ".fortressgd.toml").write_text(text, encoding="utf-8")
            pck = _write_pck(root, "game.pck", ["main.tscn", "design_docs/notes.txt"])
            proc = run_fortressgd("verify", str(pck), cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertIn("design_docs/notes.txt", combined)
            self.assertIn("(design_docs/*)", combined)

    def test_pdb_in_pack_or_next_to_artifact_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inside = _write_pck(root, "inside.pck", ["main.tscn", "Game.pdb"])
            proc = run_fortressgd("verify", str(inside), cwd=root)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("Game.pdb", proc.stderr)
        for rel in ("Game.pdb", "data_Game_linuxbsd_x86_64/Game.pdb"):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                build = root / "build"
                build.mkdir()
                exe = build / "game.x86_64"
                exe.write_bytes(embed_exe(make_gdpc(["main.tscn"])))
                clean = run_fortressgd("verify", str(exe), cwd=root)
                self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
                pdb = build / rel
                pdb.parent.mkdir(parents=True, exist_ok=True)
                pdb.write_bytes(b"Microsoft C/C++ MSF 7.00")
                proc = run_fortressgd("verify", str(exe), cwd=root)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(rel, proc.stderr)
                self.assertIn("next to the artifact", proc.stderr)

    def test_missing_and_unreadable_exit_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = run_fortressgd("verify", str(root / "nope.pck"), cwd=root)
            combined = missing.stdout + missing.stderr
            self.assertEqual(missing.returncode, 1)
            self.assertIn("error:", combined)
            self.assertIn("Run:", combined)
            garbage = root / "garbage.pck"
            garbage.write_bytes(b"not-gdpc")
            bad = run_fortressgd("verify", str(garbage), cwd=root)
            bad_out = bad.stdout + bad.stderr
            self.assertEqual(bad.returncode, 1)
            self.assertIn("error:", bad_out)
            self.assertIn("Run:", bad_out)

    def test_verify_twice_is_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            clean = _write_pck(root, "clean.pck", ["main.tscn"])
            leak = _write_pck(root, "leak.pck", ["main.gd"])
            codes_clean = []
            codes_leak = []
            for _ in range(2):
                a = run_fortressgd("verify", str(clean), cwd=root)
                b = run_fortressgd("verify", str(leak), cwd=root)
                codes_clean.append(a.returncode)
                codes_leak.append(b.returncode)
                self.assertIn("ok:", a.stdout + a.stderr)
                self.assertIn("main.gd", b.stdout + b.stderr)
            self.assertEqual(codes_clean, [0, 0])
            self.assertEqual(codes_leak, [2, 2])

    def _derived_key_project(self, root: Path) -> bytes:
        """The README's derived-key flow: dialect = false, encrypted stock pack."""
        write_godot_stub(root)
        text = default_toml_text().replace("dialect = true", "dialect = false")
        (root / ".fortressgd.toml").write_text(text, encoding="utf-8")
        self.assertEqual(run_fortressgd("secret", "generate", cwd=root).returncode, 0)
        return secret_bytes_from_hex(read_secret_file(root / ".fortressgd.secret"))

    def test_stock_encrypted_directory_with_secret_lists_and_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._derived_key_project(root)
            pck = root / "game.pck"
            pck.write_bytes(
                make_gdpc(
                    ["main.tscn", "main.gdc", "icon.png"],
                    flags=PACK_DIR_ENCRYPTED,
                    aes_key=dialect_key_for_secret(secret, "4.6.2"),
                )
            )
            exe = root / "game.exe"
            exe.write_bytes(embed_exe(pck.read_bytes()))
            for artifact in (pck, exe):
                proc = run_fortressgd("verify", str(artifact), cwd=root)
                combined = proc.stdout + proc.stderr
                self.assertEqual(proc.returncode, 0, combined)
                self.assertIn("3 packed files", combined)
                self.assertNotIn(secret.hex(), combined)

    def test_stock_encrypted_directory_leak_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._derived_key_project(root)
            pck = root / "game.pck"
            pck.write_bytes(
                make_gdpc(
                    ["main.tscn", "main.gd"],
                    flags=PACK_DIR_ENCRYPTED,
                    aes_key=dialect_key_for_secret(secret, "4.6.2"),
                )
            )
            proc = run_fortressgd("verify", str(pck), cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertIn("main.gd", combined)

    def test_stock_encrypted_directory_without_secret_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._derived_key_project(root)
            pck = root / "game.pck"
            pck.write_bytes(
                make_gdpc(["main.tscn"], flags=PACK_DIR_ENCRYPTED, aes_key=dialect_key_for_secret(secret, "4.6.2"))
            )
            (root / ".fortressgd.secret").unlink()
            proc = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("FORTRESSGD_SECRET", proc.stderr)
            self.assertIn("encrypted pack directory", proc.stderr)

    def test_stock_encrypted_directory_wrong_secret_exits_1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._derived_key_project(root)
            other = secret_bytes_from_hex(generate_secret_hex())
            pck = root / "game.pck"
            pck.write_bytes(
                make_gdpc(["main.tscn"], flags=PACK_DIR_ENCRYPTED, aes_key=dialect_key_for_secret(other, "4.6.2"))
            )
            proc = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("invalid key", proc.stderr)

    def _dialect_project(self, root: Path) -> bytes:
        write_godot_stub(root)
        self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
        self.assertEqual(run_fortressgd("secret", "generate", cwd=root).returncode, 0)
        secret = secret_bytes_from_hex(read_secret_file(root / ".fortressgd.secret"))
        return secret

    def test_dialect_clean_and_leak_twice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._dialect_project(root)
            magic, perm, key = dialect_params_for_secret(secret, "4.6.2")
            clean = root / "clean-dialect.pck"
            leak = root / "leak-dialect.pck"
            clean.write_bytes(
                encode_dialect_index(
                    ["main.tscn", "main.gdc"],
                    magic=magic,
                    perm=perm,
                    flags=PACK_DIR_ENCRYPTED,
                    aes_key=key,
                )
            )
            leak.write_bytes(
                encode_dialect_index(
                    ["main.tscn", "scripts/main.gd"],
                    magic=magic,
                    perm=perm,
                    flags=PACK_DIR_ENCRYPTED,
                    aes_key=key,
                )
            )
            codes_clean = []
            codes_leak = []
            for _ in range(2):
                a = run_fortressgd("verify", str(clean), cwd=root)
                b = run_fortressgd("verify", str(leak), cwd=root)
                a_out = a.stdout + a.stderr
                b_out = b.stdout + b.stderr
                codes_clean.append(a.returncode)
                codes_leak.append(b.returncode)
                self.assertEqual(a.returncode, 0, a_out)
                self.assertIn("ok:", a_out)
                self.assertIn("2 packed files", a_out)
                self.assertEqual(b.returncode, 2, b_out)
                self.assertIn("error:", b_out)
                self.assertIn("Run:", b_out)
                self.assertIn("scripts/main.gd", b_out)
            self.assertEqual(codes_clean, [0, 0])
            self.assertEqual(codes_leak, [2, 2])

    def _enable_flags(self, root, *, nameless: bool = False, sign_packs: bool = False, dialect: bool | None = None) -> None:
        path = root / ".fortressgd.toml"
        text = path.read_text(encoding="utf-8") if path.is_file() else default_toml_text()
        if dialect is False:
            text = text.replace("dialect = true", "dialect = false")
        if dialect is True:
            text = text.replace("dialect = false", "dialect = true")
        if nameless:
            text = text.replace("nameless_bytecode = false", "nameless_bytecode = true")
        if sign_packs:
            text = text.replace("sign_packs = false", "sign_packs = true")
        path.write_text(text, encoding="utf-8")

    def test_nameless_identifier_tokens_require_fgdn_before_tokens(self) -> None:
        """Engine _binary_to_token looks up identifiers[] while walking tokens.

        A nameless blob with IDENTIFIER tokens must load FGDN first. The old
        trailer-after-tokens layout raises 'out of bounds' on the real lookup.
        """
        blob = encode_gdsc(["health", "attack"], nameless=True, token_count=2)
        names, resolved = parse_gdsc_engine_order(blob)
        self.assertEqual(names, ["health", "attack"])
        self.assertEqual(resolved, 2)

        tokens = encode_identifier_token(0) + encode_identifier_token(1)
        fgdn = FGDN_MAGIC + struct.pack("<I", 2)
        fgdn += encode_ident_entry("health") + encode_ident_entry("attack")
        # Buggy layout: tokens, then FGDN (what 0003 did before the fix).
        contents = struct.pack("<IIII", 0, 0, 0, 2) + tokens + fgdn
        buggy = GDSC_MAGIC + struct.pack("<II", TOKENIZER_VERSION, 0) + contents
        with self.assertRaises(ValueError) as ctx:
            parse_gdsc_engine_order(buggy)
        self.assertIn("out of bounds", str(ctx.exception).lower())

    def test_nameless_bytecode_verify_on_and_off(self) -> None:
        named = encode_gdsc(["health", "my_attack"], nameless=False)
        nameless = encode_gdsc(["health", "my_attack"], nameless=True)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
            self._enable_flags(root, nameless=False, dialect=False)
            named_pck = root / "named.pck"
            nameless_pck = root / "nameless.pck"
            named_pck.write_bytes(make_gdpc(["main.tscn", "main.gdc"], contents={"main.gdc": named}))
            nameless_pck.write_bytes(
                make_gdpc(["main.tscn", "main.gdc"], contents={"main.gdc": nameless})
            )
            off_named = run_fortressgd("verify", str(named_pck), cwd=root)
            off_nameless = run_fortressgd("verify", str(nameless_pck), cwd=root)
            self.assertEqual(off_named.returncode, 0, off_named.stdout + off_named.stderr)
            self.assertEqual(off_nameless.returncode, 0, off_nameless.stdout + off_nameless.stderr)
            self._enable_flags(root, nameless=True, dialect=False)
            on_named = run_fortressgd("verify", str(named_pck), cwd=root)
            on_nameless = run_fortressgd("verify", str(nameless_pck), cwd=root)
            named_out = on_named.stdout + on_named.stderr
            nameless_out = on_nameless.stdout + on_nameless.stderr
            self.assertEqual(on_named.returncode, 2, named_out)
            self.assertIn("error:", named_out)
            self.assertIn("main.gdc", named_out)
            self.assertEqual(on_nameless.returncode, 0, nameless_out)
            self.assertIn("ok:", nameless_out)

    def _nameless_encrypted_pack(self, root: Path, body: bytes, *, key: bytes | None) -> Path:
        """dialect = false, nameless on; main.gdc body encrypted with the derived key."""
        pck = root / "game.pck"
        enc = encrypt_fae_directory(body, key, bytes(range(16, 32))) if key else body
        pck.write_bytes(
            make_gdpc(
                ["main.tscn", "main.gdc"],
                contents={"main.gdc": enc},
                file_flags={"main.gdc": PACK_FILE_ENCRYPTED},
            )
        )
        return pck

    def _nameless_project(self, root: Path) -> bytes:
        secret = self._derived_key_project(root)
        self._enable_flags(root, nameless=True, dialect=False)
        return secret

    def test_nameless_encrypted_named_gdc_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._nameless_project(root)
            key = dialect_key_for_secret(secret, "4.6.2")
            named = encode_gdsc(["health", "speed"], nameless=False, token_line_count=1)
            pck = self._nameless_encrypted_pack(root, named, key=key)
            self.assertNotIn(b"GDSC", pck.read_bytes())
            proc = run_fortressgd("verify", str(pck), cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertIn("main.gdc", combined)
            self.assertIn("debug name tables", combined)

    def test_nameless_encrypted_nameless_gdc_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._nameless_project(root)
            key = dialect_key_for_secret(secret, "4.6.2")
            pck = self._nameless_encrypted_pack(root, encode_gdsc(["health"], nameless=True), key=key)
            proc = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_nameless_encrypted_without_secret_exits_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._nameless_project(root)
            key = dialect_key_for_secret(secret, "4.6.2")
            pck = self._nameless_encrypted_pack(root, encode_gdsc(["health"], nameless=True), key=key)
            (root / ".fortressgd.secret").unlink()
            proc = run_fortressgd("verify", str(pck), cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertIn("project secret", combined)
            self.assertIn("encrypted .gdc", combined)

    def _compressed_gdsc(self, contents: bytes, frame: bytes | None = None) -> bytes:
        body = frame if frame is not None else b"\x28\xb5\x2f\xfd" + b"\x00" * 8
        return GDSC_MAGIC + struct.pack("<II", TOKENIZER_VERSION, len(contents)) + body

    @unittest.skipIf(_HAVE_ZSTD, "zstd available; compressed .gdc decodes instead")
    def test_nameless_compressed_gdc_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
            self._enable_flags(root, nameless=True, dialect=False)
            blob = self._compressed_gdsc(b"\x00" * 32)
            pck = root / "game.pck"
            pck.write_bytes(make_gdpc(["main.tscn", "main.gdc"], contents={"main.gdc": blob}))
            proc = run_fortressgd("verify", str(pck), cwd=root)
            combined = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 2, combined)
            self.assertIn("Binary tokens", combined)
            self.assertIn("Python 3.14", combined)
            self.assertIn("main.gdc", combined)

    @unittest.skipUnless(_HAVE_ZSTD, "needs compression.zstd (Python 3.14+)")
    def test_nameless_compressed_gdc_decodes(self) -> None:
        from compression import zstd  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
            self._enable_flags(root, nameless=True, dialect=False)
            for name, nameless, expected in (("named", False, 2), ("nameless", True, 0)):
                contents = encode_gdsc(["health"], nameless=nameless, token_line_count=1)[12:]
                blob = self._compressed_gdsc(contents, zstd.compress(contents))
                pck = root / (name + ".pck")
                pck.write_bytes(make_gdpc(["main.tscn", "main.gdc"], contents={"main.gdc": blob}))
                proc = run_fortressgd("verify", str(pck), cwd=root)
                self.assertEqual(proc.returncode, expected, name + ": " + proc.stdout + proc.stderr)

    def test_sign_packs_encrypted_dialect_index_range(self) -> None:
        secret = bytes(range(1, 33))
        magic, perm, key = dialect_params_for_secret(secret, "4.6.2")
        body = b"B" * 37
        pck = encode_dialect_index(
            ["main.tscn", "main.gdc"], magic=magic, perm=perm, flags=PACK_DIR_ENCRYPTED,
            aes_key=key, contents={"main.gdc": body},
        )
        exe = embed_exe_dialect(pck, magic)
        for data in (pck, exe):
            listing = read_dialect_listing(data, magic=magic, perm=perm, aes_key=key)
            index = listing.index_bytes(data)
            # Engine formula (0005-pack-signatures.patch): dir_abs + 4 + 16 + 8 + 16 + padded(length).
            length = struct.unpack_from("<Q", data, listing.dir_abs + 4 + 16)[0]
            engine_end = listing.dir_abs + 4 + 16 + 8 + 16 + length + (16 - length % 16) % 16
            self.assertEqual(listing.dir_end, engine_end)
            self.assertEqual(index, data[listing.dir_abs : engine_end])
            # The range ends at the end of the encrypted blob, not at EOF / the bodies.
            self.assertLess(listing.dir_end, len(data))
            self.assertNotIn(body, index)
            self.assertNotIn(b"GDPC", index[-12:])

    def test_sign_packs_encrypted_stock_index_range(self) -> None:
        key = bytes(range(32))
        data = make_gdpc(["main.tscn", "main.gdc"], flags=PACK_DIR_ENCRYPTED, aes_key=key, contents={"main.gdc": b"C" * 21})
        from core.pack_dialect import STOCK_INDEX_PERM, STOCK_PACK_MAGIC, read_dialect_listing_at

        listing = read_dialect_listing_at(data, 0, magic=STOCK_PACK_MAGIC, perm=STOCK_INDEX_PERM, aes_key=key)
        self.assertEqual(listing.dir_end, listing.file_base)
        self.assertEqual(listing.index_bytes(data), data[listing.dir_abs : listing.file_base])

    def test_sign_packs_valid_missing_and_wrong(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = self._dialect_project(root)
            self._enable_flags(root, sign_packs=True, dialect=True)
            magic, perm, key = dialect_params_for_secret(secret, "4.6.2")
            unsigned = root / "unsigned.pck"
            unsigned.write_bytes(
                encode_dialect_index(
                    ["main.tscn", "main.gdc"],
                    magic=magic,
                    perm=perm,
                    flags=PACK_DIR_ENCRYPTED,
                    aes_key=key,
                    contents={"main.gdc": encode_gdsc(["x"], nameless=True)},
                )
            )
            from core.pack_dialect import read_dialect_listing

            data = unsigned.read_bytes()
            listing = read_dialect_listing(
                data, magic=magic, perm=perm, aes_key=key, source=str(unsigned)
            )
            index = listing.index_bytes(data)
            good_sig = sign_index(index, secret, "4.6.2")
            pubkey = public_key_for_secret(secret, "4.6.2")
            self.assertTrue(verify_index(index, good_sig, pubkey))
            other = bytes((b + 3) % 256 for b in secret)
            self.assertFalse(verify_index(index, sign_index(index, other, "4.6.2"), pubkey))
            signed = root / "signed.pck"
            signed.write_bytes(apply_signature(data, good_sig, listing.pck_start, listing.version))
            wrong = root / "wrong.pck"
            wrong.write_bytes(
                apply_signature(
                    data, sign_index(index, other, "4.6.2"), listing.pck_start, listing.version
                )
            )
            ok = run_fortressgd("verify", str(signed), cwd=root)
            missing = run_fortressgd("verify", str(unsigned), cwd=root)
            bad = run_fortressgd("verify", str(wrong), cwd=root)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertIn("ok:", ok.stdout + ok.stderr)
            self.assertEqual(missing.returncode, 2, missing.stdout + missing.stderr)
            self.assertIn("signature", (missing.stdout + missing.stderr).lower())
            self.assertEqual(bad.returncode, 2, bad.stdout + bad.stderr)

    def test_sign_packs_off_accepts_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_godot_stub(root)
            self.assertEqual(run_fortressgd("init", cwd=root).returncode, 0)
            self._enable_flags(root, sign_packs=False, dialect=False)
            pck = root / "plain.pck"
            pck.write_bytes(make_gdpc(["main.tscn"]))
            proc = run_fortressgd("verify", str(pck), cwd=root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()

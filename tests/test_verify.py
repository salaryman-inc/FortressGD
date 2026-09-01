"""Subprocess tests against shipped `fortressgd verify`."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.config import default_toml_text
from core.gdc import encode_gdsc
from core.pack import PACK_DIR_ENCRYPTED
from core.pack_dialect import dialect_params_for_secret, encode_dialect_index
from core.pack_sign import apply_signature, public_key_for_secret, sign_index, verify_index
from core.secret import read_secret_file, secret_bytes_from_hex
from tests.gdpc_fixture import embed_exe, make_gdpc
from tests.support import run_fortressgd, write_godot_stub


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

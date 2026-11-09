"""Optional OpenSSL AES (cryptography package) vs the pure-Python fallback."""

from __future__ import annotations

import os
import time
import unittest
from unittest import mock

from fortressgd.core import aes_cfb
from fortressgd.core.pack_dialect import decrypt_fae_blob, encrypt_fae_directory

HAVE_OPENSSL = aes_cfb.aes_backend() == "openssl"


class AesBackendTests(unittest.TestCase):
    @unittest.skipUnless(HAVE_OPENSSL, "cryptography not installed (pip install fortressgd[fast])")
    def test_openssl_and_pure_produce_identical_bytes(self) -> None:
        for size in (0, 16, 32, 48, 4096, 16 * 1000):
            key, iv, data = os.urandom(32), os.urandom(16), os.urandom(size)
            for encrypt in (True, False):
                with self.subTest(size=size, encrypt=encrypt):
                    self.assertEqual(
                        aes_cfb.aes256_cfb128(key, iv, data, encrypt=encrypt),
                        aes_cfb.aes256_cfb128_pure(key, iv, data, encrypt=encrypt),
                    )

    @unittest.skipUnless(HAVE_OPENSSL, "cryptography not installed (pip install fortressgd[fast])")
    def test_openssl_path_is_fast(self) -> None:
        key, iv = os.urandom(32), os.urandom(16)
        blob = encrypt_fae_directory(os.urandom(8 * 1024 * 1024), key, iv)
        start = time.monotonic()
        decrypt_fae_blob(blob, key)
        self.assertLess(time.monotonic() - start, 2.0)

    def test_pure_fallback_when_cryptography_is_missing(self) -> None:
        key, iv = os.urandom(32), os.urandom(16)
        plaintext = os.urandom(100)
        with mock.patch.object(aes_cfb, "_OPENSSL_CFB", None):
            self.assertEqual(aes_cfb.aes_backend(), "pure-python")
            blob = encrypt_fae_directory(plaintext, key, iv)
            self.assertEqual(decrypt_fae_blob(blob, key), plaintext)

    def test_loader_returns_none_without_cryptography(self) -> None:
        with mock.patch.dict("sys.modules", {"cryptography": None, "cryptography.hazmat.primitives.ciphers": None}):
            self.assertIsNone(aes_cfb._load_openssl_cfb())

    def test_loader_returns_none_when_cryptography_panics_on_import(self) -> None:
        # A distro `cryptography` without `_cffi_backend` raises pyo3's
        # PanicException, a BaseException subclass, from its Rust bindings.
        class PanicException(BaseException):
            pass

        real_import = __import__

        def panicking_import(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise PanicException("Python API call failed")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=panicking_import):
            self.assertIsNone(aes_cfb._load_openssl_cfb())

    def test_loader_lets_keyboard_interrupt_through(self) -> None:
        real_import = __import__

        def interrupted_import(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise KeyboardInterrupt
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=interrupted_import):
            with self.assertRaises(KeyboardInterrupt):
                aes_cfb._load_openssl_cfb()

    def test_arguments_are_validated_on_both_paths(self) -> None:
        for fn in (aes_cfb.aes256_cfb128, aes_cfb.aes256_cfb128_pure):
            with self.assertRaises(ValueError):
                fn(b"k" * 31, b"i" * 16, b"", encrypt=True)
            with self.assertRaises(ValueError):
                fn(b"k" * 32, b"i" * 15, b"", encrypt=True)
            with self.assertRaises(ValueError):
                fn(b"k" * 32, b"i" * 16, b"x" * 17, encrypt=True)


if __name__ == "__main__":
    unittest.main()

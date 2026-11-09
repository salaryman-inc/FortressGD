"""FGD-KDF-1, secret_hash, and shard round-trips against an independent RFC 5869 HKDF."""

from __future__ import annotations

import hashlib
import hmac
import unittest

from fortressgd.core.kdf import (
    FGD_KDF_INFO,
    FGD_KDF_LEN,
    SALT_LEN,
    aes_key_hex,
    fgd_kdf_1,
    secret_hash,
)
from fortressgd.core.secret import SECRET_BYTES
from fortressgd.core.shards import decode_shards, encode_shards, split_pieces
from fortressgd.generator.dialect import derive_dialect_salt
from fortressgd.generator.key_shards import derive_masks, encode_secret


def independent_hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 extract-then-expand via hmac+SHA256. Must not call core.kdf."""
    hash_len = hashlib.sha256().digest_size
    if not salt:
        salt = b"\x00" * hash_len
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


class KdfTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = bytes(range(SECRET_BYTES))
        self.salt = bytes(range(16, 16 + SALT_LEN))

    def test_info_and_length_are_normative(self) -> None:
        self.assertEqual(FGD_KDF_INFO, b"fortressgd.pck.aes.v1")
        self.assertEqual(FGD_KDF_LEN, 32)
        self.assertEqual(SALT_LEN, 16)

    def test_fgd_kdf_1_matches_independent_rfc5869(self) -> None:
        shipped = fgd_kdf_1(self.secret, self.salt)
        independent = independent_hkdf_sha256(
            self.secret, self.salt, b"fortressgd.pck.aes.v1", 32
        )
        self.assertEqual(len(shipped), 32)
        self.assertEqual(shipped, independent)
        self.assertEqual(aes_key_hex(self.secret, self.salt), shipped.hex())
        self.assertNotEqual(shipped, self.secret)

    def test_secret_hash_is_first_16_hex_of_prefixed_sha256(self) -> None:
        expected = hashlib.sha256(b"fortressgd-v1|" + self.secret).hexdigest()[:16]
        self.assertEqual(secret_hash(self.secret), expected)
        self.assertEqual(len(secret_hash(self.secret)), 16)

    def test_different_salt_yields_different_aes_key(self) -> None:
        other = bytes((b + 1) % 256 for b in self.salt)
        self.assertNotEqual(self.salt, other)
        self.assertNotEqual(fgd_kdf_1(self.secret, self.salt), fgd_kdf_1(self.secret, other))

    def test_shard_encode_decode_round_trip_masks_separate(self) -> None:
        masks = derive_masks(self.secret, hashlib.sha256(b"mask-salt").digest())
        shards = encode_shards(self.secret, masks)
        self.assertEqual(len(masks), 32)
        self.assertEqual(len(shards), 32)
        self.assertNotEqual(shards, self.secret)
        self.assertNotEqual(shards, masks)
        self.assertEqual(decode_shards(shards, masks), self.secret)
        self.assertEqual(encode_secret(self.secret, masks), shards)
        self.assertEqual(len(split_pieces(shards)), 4)
        for piece in split_pieces(shards):
            self.assertEqual(len(piece), 8)

    def test_generator_salt_feeds_kdf(self) -> None:
        salt = derive_dialect_salt(self.secret, "4.6.2")
        self.assertEqual(len(salt), 16)
        key = fgd_kdf_1(self.secret, salt)
        again = independent_hkdf_sha256(self.secret, salt, FGD_KDF_INFO, FGD_KDF_LEN)
        self.assertEqual(key, again)


if __name__ == "__main__":
    unittest.main()

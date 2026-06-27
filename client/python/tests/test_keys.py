"""Tests for key generation, loading, and derivation."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest

import cc_me
from cc_me import (
    SEED_BYTES,
    _b64u_decode,
    _b64u_encode,
    _public_key_bytes,
    _public_key_string,
    _seed_bytes,
    private_key,
)

from .helpers import KNOWN_SEED, known_public_b64u


class InMemoryKeyTests(unittest.TestCase):
    def test_generates_32_byte_seed(self) -> None:
        key = private_key()
        seed = _b64u_decode(key)
        self.assertEqual(len(seed), SEED_BYTES)
        self.assertEqual(len(seed), 32)

    def test_no_padding_in_generated_key(self) -> None:
        self.assertNotIn("=", private_key())

    def test_keys_are_random(self) -> None:
        self.assertNotEqual(private_key(), private_key())


class KeyFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "test.key")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_creates_file_with_trailing_newline(self) -> None:
        key = private_key(self.path)
        with open(self.path, "r", encoding="utf-8") as handle:
            contents = handle.read()
        self.assertEqual(contents, f"{key}\n")

    def test_creates_file_mode_0600(self) -> None:
        private_key(self.path)
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_reuses_existing_key(self) -> None:
        first = private_key(self.path)
        second = private_key(self.path)
        self.assertEqual(first, second)

    def test_reuse_does_not_rewrite(self) -> None:
        private_key(self.path)
        mtime = os.stat(self.path).st_mtime_ns
        # Reading an existing key must not recreate the file.
        private_key(self.path)
        # Content stays identical; file still has exactly one trailing newline.
        with open(self.path, "r", encoding="utf-8") as handle:
            self.assertTrue(handle.read().endswith("\n"))
        # mtime unchanged (open in read mode + chmod only).
        self.assertEqual(os.stat(self.path).st_mtime_ns, mtime)

    def test_resecures_loose_permissions(self) -> None:
        key = private_key(self.path)
        os.chmod(self.path, 0o644)
        private_key(self.path)
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_strips_whitespace_on_load(self) -> None:
        key = private_key(self.path)
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(f"  {key}\n\n")
        # Should still validate and return the trimmed key.
        self.assertEqual(private_key(self.path), key)

    def test_rejects_malformed_contents(self) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("!!!not base64!!!\n")
        with self.assertRaises(Exception):
            private_key(self.path)

    def test_rejects_wrong_length(self) -> None:
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(_b64u_encode(b"\x01\x02\x03") + "\n")
        with self.assertRaises(ValueError):
            private_key(self.path)


class SeedBytesTests(unittest.TestCase):
    def test_accepts_bytes(self) -> None:
        self.assertEqual(_seed_bytes(KNOWN_SEED), KNOWN_SEED)

    def test_accepts_bytearray(self) -> None:
        self.assertEqual(_seed_bytes(bytearray(KNOWN_SEED)), KNOWN_SEED)

    def test_accepts_b64u_string(self) -> None:
        self.assertEqual(_seed_bytes(_b64u_encode(KNOWN_SEED)), KNOWN_SEED)

    def test_rejects_short_bytes(self) -> None:
        with self.assertRaises(ValueError):
            _seed_bytes(b"\x00" * 31)

    def test_rejects_long_bytes(self) -> None:
        with self.assertRaises(ValueError):
            _seed_bytes(b"\x00" * 33)


class PublicKeyDerivationTests(unittest.TestCase):
    def test_public_key_deterministic_for_known_seed(self) -> None:
        pub = _public_key_bytes(KNOWN_SEED)
        self.assertEqual(len(pub), 32)
        self.assertEqual(_b64u_encode(pub), known_public_b64u())

    def test_public_key_from_b64u_seed_matches(self) -> None:
        from_bytes = _public_key_bytes(KNOWN_SEED)
        from_str = _public_key_bytes(_b64u_encode(KNOWN_SEED))
        self.assertEqual(from_bytes, from_str)

    def test_public_key_string_passthrough(self) -> None:
        # A str is treated as an already-encoded public key.
        self.assertEqual(_public_key_string("abc"), "abc")

    def test_public_key_string_encodes_bytes(self) -> None:
        self.assertEqual(
            _public_key_string(KNOWN_SEED), _b64u_encode(KNOWN_SEED)
        )

    def test_inbox_url_deterministic_for_known_seed(self) -> None:
        client = cc_me.CcMeClient(_b64u_encode(KNOWN_SEED))
        self.assertEqual(
            client.inbox_url(),
            f"https://cc.me/i/{known_public_b64u()}",
        )


if __name__ == "__main__":
    unittest.main()

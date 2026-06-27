"""Tests for the base64url (no padding) helpers."""

from __future__ import annotations

import base64
import hashlib
import os
import unittest

from cc_me import _b64u_decode, _b64u_encode, _sha256_b64u


class B64uEncodeTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_b64u_encode(b""), "")

    def test_no_padding(self) -> None:
        # 1 byte normally needs 2 '=' of padding; must be stripped.
        self.assertNotIn("=", _b64u_encode(b"\x00"))
        self.assertNotIn("=", _b64u_encode(b"\xff\xff"))
        self.assertNotIn("=", _b64u_encode(b"any odd length!"))

    def test_url_safe_alphabet(self) -> None:
        # 0xFB 0xFF encodes to bytes that use '-'/'_' in url-safe alphabet.
        encoded = _b64u_encode(b"\xfb\xff\xbf")
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)
        self.assertTrue(set(encoded) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        ))

    def test_matches_stdlib_minus_padding(self) -> None:
        data = b"\x00\x01\x02\x10\xfe\xff"
        expected = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        self.assertEqual(_b64u_encode(data), expected)


class B64uDecodeTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_b64u_decode(""), b"")

    def test_tolerant_of_existing_padding(self) -> None:
        # Standard library produces padding; decode must accept it.
        # A 1-byte input needs two '=' of padding (and 2 bytes needs one).
        padded1 = base64.urlsafe_b64encode(b"\x01").decode()
        padded2 = base64.urlsafe_b64encode(b"\x01\x02").decode()
        self.assertIn("=", padded1)
        self.assertIn("=", padded2)
        self.assertEqual(_b64u_decode(padded1), b"\x01")
        self.assertEqual(_b64u_decode(padded2), b"\x01\x02")

    def test_handles_minus_and_underscore(self) -> None:
        data = b"\xfb\xff\xbf\xfe"
        encoded = _b64u_encode(data)
        # Make sure we actually exercise - and/or _.
        self.assertTrue("-" in encoded or "_" in encoded)
        self.assertEqual(_b64u_decode(encoded), data)


class B64uRoundTripTests(unittest.TestCase):
    def test_round_trip_all_lengths(self) -> None:
        for length in range(0, 40):
            data = os.urandom(length)
            self.assertEqual(
                _b64u_decode(_b64u_encode(data)),
                data,
                msg=f"round-trip failed at length {length}",
            )

    def test_round_trip_high_bytes(self) -> None:
        data = bytes(range(256))
        self.assertEqual(_b64u_decode(_b64u_encode(data)), data)


class Sha256B64uTests(unittest.TestCase):
    def test_empty_body(self) -> None:
        expected = _b64u_encode(hashlib.sha256(b"").digest())
        self.assertEqual(_sha256_b64u(b""), expected)

    def test_known_value(self) -> None:
        digest = hashlib.sha256(b"hello").digest()
        self.assertEqual(_sha256_b64u(b"hello"), _b64u_encode(digest))

    def test_no_padding(self) -> None:
        self.assertNotIn("=", _sha256_b64u(b"some body"))


if __name__ == "__main__":
    unittest.main()

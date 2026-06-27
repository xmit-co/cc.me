"""Tests for owner-authentication signing."""

from __future__ import annotations

import hashlib
import unittest
from unittest import mock

import cc_me
from cc_me import (
    AUTH_SIGNATURE_HEADER,
    AUTH_TIMESTAMP_HEADER,
    AUTH_VERSION,
    _b64u_decode,
    _b64u_encode,
)

from nacl.signing import VerifyKey

from .helpers import KNOWN_SEED, known_signing_key


def _client() -> cc_me.CcMeClient:
    return cc_me.CcMeClient(_b64u_encode(KNOWN_SEED))


def _canonical(method: str, path: str, ts: int, body: bytes) -> bytes:
    digest = _b64u_encode(hashlib.sha256(body).digest())
    return f"{AUTH_VERSION}\n{method}\n{path}\n{ts}\n{digest}".encode("utf-8")


class CanonicalStringTests(unittest.TestCase):
    def test_canonical_string_exact_format(self) -> None:
        client = _client()
        with mock.patch("cc_me.time.time", return_value=1700000000.9):
            headers = client._sign(
                "POST", "https://cc.me/i/KEY/claim", b"body"
            )
        # Timestamp is integer seconds (truncated).
        self.assertEqual(headers[AUTH_TIMESTAMP_HEADER], "1700000000")
        # Verify the signature against the exact canonical string.
        expected = _canonical("POST", "/i/KEY/claim", 1700000000, b"body")
        verify_key: VerifyKey = known_signing_key().verify_key
        signature = _b64u_decode(headers[AUTH_SIGNATURE_HEADER])
        # Raises BadSignatureError if message doesn't match.
        verify_key.verify(expected, signature)

    def test_path_includes_query(self) -> None:
        client = _client()
        with mock.patch("cc_me.time.time", return_value=42):
            headers = client._sign("GET", "https://cc.me/i/KEY?l=10&p=", b"")
        expected = _canonical("GET", "/i/KEY?l=10&p=", 42, b"")
        known_signing_key().verify_key.verify(
            expected, _b64u_decode(headers[AUTH_SIGNATURE_HEADER])
        )

    def test_poll_renders_empty_value_in_signed_path(self) -> None:
        client = _client()
        with mock.patch("cc_me.time.time", return_value=42):
            headers = client._sign("GET", "https://cc.me/i/KEY?p=", b"")
        expected = _canonical("GET", "/i/KEY?p=", 42, b"")
        known_signing_key().verify_key.verify(
            expected, _b64u_decode(headers[AUTH_SIGNATURE_HEADER])
        )


class EmptyBodyHashTests(unittest.TestCase):
    def test_empty_body_hashes_empty_byte_string(self) -> None:
        client = _client()
        with mock.patch("cc_me.time.time", return_value=1):
            headers = client._sign("GET", "https://cc.me/i/KEY", b"")
        empty_digest = _b64u_encode(hashlib.sha256(b"").digest())
        expected = (
            f"{AUTH_VERSION}\nGET\n/i/KEY\n1\n{empty_digest}".encode("utf-8")
        )
        known_signing_key().verify_key.verify(
            expected, _b64u_decode(headers[AUTH_SIGNATURE_HEADER])
        )


class SignatureHeaderTests(unittest.TestCase):
    def test_both_headers_present(self) -> None:
        headers = _client()._sign("GET", "https://cc.me/i/KEY", b"")
        self.assertIn(AUTH_TIMESTAMP_HEADER, headers)
        self.assertIn(AUTH_SIGNATURE_HEADER, headers)

    def test_signature_no_padding(self) -> None:
        headers = _client()._sign("GET", "https://cc.me/i/KEY", b"")
        self.assertNotIn("=", headers[AUTH_SIGNATURE_HEADER])

    def test_signature_is_64_bytes(self) -> None:
        headers = _client()._sign("GET", "https://cc.me/i/KEY", b"")
        self.assertEqual(len(_b64u_decode(headers[AUTH_SIGNATURE_HEADER])), 64)

    def test_wrong_body_fails_verification(self) -> None:
        client = _client()
        with mock.patch("cc_me.time.time", return_value=5):
            headers = client._sign("POST", "https://cc.me/x", b"correct")
        wrong = _canonical("POST", "/x", 5, b"WRONG")
        from nacl.exceptions import BadSignatureError

        with self.assertRaises(BadSignatureError):
            known_signing_key().verify_key.verify(
                wrong, _b64u_decode(headers[AUTH_SIGNATURE_HEADER])
            )


if __name__ == "__main__":
    unittest.main()

"""Tests for sealed-box decryption of captured requests."""

from __future__ import annotations

import unittest

import cc_me
from cc_me import _b64u_encode

from .helpers import KNOWN_SEED, known_signing_key, make_captured_payload, seal_for


def _client() -> cc_me.CcMeClient:
    return cc_me.CcMeClient(_b64u_encode(KNOWN_SEED))


def _envelope(plaintext: bytes, id: str = "m_test") -> dict:
    return {"id": id, "sealed": seal_for(known_signing_key(), plaintext)}


class DecryptRoundTripTests(unittest.TestCase):
    def test_full_round_trip_fields(self) -> None:
        payload = make_captured_payload(
            id="m_abc",
            received_at_unix_ms=1781337600000,
            method="POST",
            path="/i/KEY",
            query="a=1&b=2",
            headers=[
                (b"content-type", b"application/json"),
                (b"x-custom", b"\xff\xfe"),  # non-utf8 value bytes
            ],
            body=b'{"hello":"world"}',
        )
        req = _client()._decrypt_envelope(_envelope(payload, "m_abc"))
        self.assertEqual(req.id, "m_abc")
        self.assertEqual(req.received_at_unix_ms, 1781337600000)
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.path, "/i/KEY")
        self.assertEqual(req.query, "a=1&b=2")
        self.assertEqual(req.body_bytes, b'{"hello":"world"}')

    def test_header_value_and_value_bytes(self) -> None:
        payload = make_captured_payload(
            headers=[(b"content-type", b"text/plain")], body=b""
        )
        req = _client()._decrypt_envelope(_envelope(payload))
        h = req.headers[0]
        self.assertEqual(h.name, "content-type")
        self.assertEqual(h.value, "text/plain")
        self.assertEqual(h.value_bytes, b"text/plain")

    def test_header_non_utf8_value_bytes_preserved(self) -> None:
        payload = make_captured_payload(
            headers=[(b"x-raw", b"\xff\xfe\x00")], body=b""
        )
        req = _client()._decrypt_envelope(_envelope(payload))
        self.assertEqual(req.headers[0].value_bytes, b"\xff\xfe\x00")
        # value uses errors="replace" so it does not raise.
        self.assertIsInstance(req.headers[0].value, str)

    def test_query_none(self) -> None:
        payload = make_captured_payload(query=None, body=b"")
        req = _client()._decrypt_envelope(_envelope(payload))
        self.assertIsNone(req.query)

    def test_text_helper(self) -> None:
        payload = make_captured_payload(body="héllo".encode("utf-8"))
        req = _client()._decrypt_envelope(_envelope(payload))
        self.assertEqual(req.text(), "héllo")

    def test_json_helper(self) -> None:
        payload = make_captured_payload(body=b'{"n": 42, "ok": true}')
        req = _client()._decrypt_envelope(_envelope(payload))
        self.assertEqual(req.json(), {"n": 42, "ok": True})

    def test_empty_body(self) -> None:
        payload = make_captured_payload(body=b"")
        req = _client()._decrypt_envelope(_envelope(payload))
        self.assertEqual(req.body_bytes, b"")

    def test_empty_headers_list(self) -> None:
        payload = make_captured_payload(headers=[], body=b"")
        req = _client()._decrypt_envelope(_envelope(payload))
        self.assertEqual(req.headers, [])


class DecryptErrorTests(unittest.TestCase):
    def test_id_mismatch_raises(self) -> None:
        payload = make_captured_payload(id="m_inner")
        env = _envelope(payload, id="m_outer")
        with self.assertRaises(RuntimeError) as ctx:
            _client()._decrypt_envelope(env)
        self.assertIn("mismatch", str(ctx.exception))

    def test_too_short_ciphertext_raises(self) -> None:
        env = {"id": "m_x", "sealed": _b64u_encode(b"short")}
        with self.assertRaises(RuntimeError) as ctx:
            _client()._decrypt_envelope(env)
        self.assertIn("decrypt", str(ctx.exception))

    def test_garbage_ciphertext_raises(self) -> None:
        env = {"id": "m_x", "sealed": _b64u_encode(b"\x00" * 80)}
        with self.assertRaises(RuntimeError):
            _client()._decrypt_envelope(env)

    def test_wrong_recipient_cannot_decrypt(self) -> None:
        # Seal for a different identity; this client must fail to open.
        from nacl.signing import SigningKey

        other = SigningKey(bytes([7]) * 32)
        payload = make_captured_payload(id="m_x")
        env = {"id": "m_x", "sealed": seal_for(other, payload)}
        with self.assertRaises(RuntimeError):
            _client()._decrypt_envelope(env)


if __name__ == "__main__":
    unittest.main()

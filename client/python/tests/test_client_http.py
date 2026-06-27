"""Tests for CcMeClient methods against a local mock HTTP server."""

from __future__ import annotations

import unittest

import cc_me
from cc_me import (
    AUTH_SIGNATURE_HEADER,
    AUTH_TIMESTAMP_HEADER,
    _b64u_encode,
    create_alias,
)

from .helpers import (
    KNOWN_SEED,
    MockServer,
    known_public_b64u,
    known_signing_key,
    make_captured_payload,
    seal_for,
)

PUB = known_public_b64u()


def _client(base_url: str) -> cc_me.CcMeClient:
    return cc_me.CcMeClient(_b64u_encode(KNOWN_SEED), base_url=base_url)


def _sealed_item(id: str, **kwargs) -> dict:
    payload = make_captured_payload(id=id, **kwargs)
    return {"id": id, "sealed": seal_for(known_signing_key(), payload)}


class PeekTests(unittest.TestCase):
    def test_peek_issues_get_with_auth_headers(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"count": 0, "items": [], "cursor": None})
            client = _client(server.base_url)
            client.peek()
            rec = server.requests[0]
            self.assertEqual(rec.method, "GET")
            self.assertTrue(rec.path.startswith(f"/i/{PUB}"))
            self.assertIn(AUTH_TIMESTAMP_HEADER, rec.headers)
            self.assertIn(AUTH_SIGNATURE_HEADER, rec.headers)

    def test_peek_query_params(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"count": 0, "items": [], "cursor": None})
            _client(server.base_url).peek(limit=5, cursor="c1", poll=True)
            self.assertEqual(server.requests[0].query, "l=5&c=c1&p=")

    def test_peek_decrypts_items(self) -> None:
        with MockServer() as server:
            item = _sealed_item("m_1", body=b"hi", query="x=1")
            server.json_responder(
                200, {"count": 1, "items": [item], "cursor": "next"}
            )
            res = _client(server.base_url).peek()
            self.assertEqual(res.count, 1)
            self.assertEqual(res.cursor, "next")
            self.assertEqual(len(res.requests), 1)
            self.assertEqual(res.requests[0].id, "m_1")
            self.assertEqual(res.requests[0].body_bytes, b"hi")

    def test_peek_decrypt_false_returns_raw(self) -> None:
        with MockServer() as server:
            item = _sealed_item("m_1")
            server.json_responder(200, {"count": 1, "items": [item]})
            res = _client(server.base_url).peek(decrypt=False)
            self.assertEqual(res.requests, [])
            self.assertEqual(res.items, [item])


class ClaimTests(unittest.TestCase):
    def test_claim_posts_json_with_auth(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"count": 0, "items": []})
            _client(server.base_url).claim(limit=3, poll=True)
            rec = server.requests[0]
            self.assertEqual(rec.method, "POST")
            self.assertEqual(rec.path, f"/i/{PUB}/claim")
            self.assertEqual(rec.headers.get("content-type"), "application/json")
            self.assertIn(AUTH_TIMESTAMP_HEADER, rec.headers)
            self.assertIn(AUTH_SIGNATURE_HEADER, rec.headers)
            self.assertEqual(rec.json(), {"poll": True, "limit": 3})

    def test_claim_without_limit_omits_limit(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"count": 0, "items": []})
            _client(server.base_url).claim()
            self.assertEqual(server.requests[0].json(), {"poll": False})

    def test_claim_decrypts(self) -> None:
        with MockServer() as server:
            item = _sealed_item("m_2", method="PUT", body=b"data")
            server.json_responder(200, {"count": 1, "items": [item]})
            res = _client(server.base_url).claim()
            self.assertEqual(res.requests[0].method, "PUT")
            self.assertEqual(res.requests[0].body_bytes, b"data")

    def test_signed_path_equals_sent_path(self) -> None:
        # The signature must cover the exact path+query sent on the wire.
        from nacl.signing import VerifyKey
        import hashlib

        with MockServer() as server:
            server.json_responder(200, {"count": 0, "items": []})
            _client(server.base_url).claim(limit=7, poll=True)
            rec = server.requests[0]
            ts = int(rec.headers[AUTH_TIMESTAMP_HEADER])
            digest = _b64u_encode(hashlib.sha256(rec.body).digest())
            msg = f"cc-me-v1\nPOST\n{rec.path}\n{ts}\n{digest}".encode("utf-8")
            sig = cc_me._b64u_decode(rec.headers[AUTH_SIGNATURE_HEADER])
            # Raises if signature doesn't match.
            known_signing_key().verify_key.verify(msg, sig)


class AckReleaseTests(unittest.TestCase):
    def test_ack_single_id(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"acked": 1, "missing": []})
            res = _client(server.base_url).ack("m_1")
            rec = server.requests[0]
            self.assertEqual(rec.method, "POST")
            self.assertEqual(rec.path, f"/i/{PUB}/ack")
            self.assertEqual(rec.json(), {"ids": ["m_1"]})
            self.assertEqual(res, {"acked": 1, "missing": []})

    def test_ack_multiple_ids(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"acked": 2, "missing": []})
            _client(server.base_url).ack(["m_1", "m_2"])
            self.assertEqual(server.requests[0].json(), {"ids": ["m_1", "m_2"]})

    def test_release_single_id(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"released": 1, "missing": []})
            _client(server.base_url).release("m_3")
            rec = server.requests[0]
            self.assertEqual(rec.path, f"/i/{PUB}/release")
            self.assertEqual(rec.json(), {"ids": ["m_3"]})

    def test_release_iterable(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"released": 2, "missing": []})
            _client(server.base_url).release(iter(["a", "b"]))
            self.assertEqual(server.requests[0].json(), {"ids": ["a", "b"]})

    def test_ack_and_release_signed(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {})
            _client(server.base_url).ack("m_1")
            rec = server.requests[0]
            self.assertIn(AUTH_TIMESTAMP_HEADER, rec.headers)
            self.assertIn(AUTH_SIGNATURE_HEADER, rec.headers)


class ErrorSurfacingTests(unittest.TestCase):
    def test_non_2xx_surfaces_error_message(self) -> None:
        with MockServer() as server:
            server.json_responder(403, {"error": "forbidden, mate"})
            with self.assertRaises(RuntimeError) as ctx:
                _client(server.base_url).peek()
            self.assertEqual(str(ctx.exception), "forbidden, mate")

    def test_non_2xx_without_error_field_falls_back(self) -> None:
        with MockServer() as server:
            server.json_responder(500, {"something": "else"})
            with self.assertRaises(RuntimeError) as ctx:
                _client(server.base_url).ack("m_1")
            self.assertIn("500", str(ctx.exception))

    def test_non_2xx_non_json_body(self) -> None:
        with MockServer() as server:

            def respond(_rec):
                return 502, b"<html>bad gateway</html>", "text/html"

            server.responder = respond
            with self.assertRaises(RuntimeError) as ctx:
                _client(server.base_url).peek()
            self.assertIn("502", str(ctx.exception))


class CreateAliasTests(unittest.TestCase):
    def test_create_alias_posts_at(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"url": "https://cc.me/a/xyz"})
            res = create_alias(
                "https://example.com/target", base_url=server.base_url
            )
            rec = server.requests[0]
            self.assertEqual(rec.method, "POST")
            self.assertEqual(rec.path, "/c")
            self.assertEqual(rec.json(), {"at": "https://example.com/target"})
            self.assertEqual(res.url, "https://cc.me/a/xyz")

    def test_create_alias_no_auth_headers(self) -> None:
        with MockServer() as server:
            server.json_responder(200, {"url": "https://cc.me/a/xyz"})
            create_alias("t", base_url=server.base_url)
            rec = server.requests[0]
            self.assertNotIn(AUTH_SIGNATURE_HEADER, rec.headers)
            self.assertNotIn(AUTH_TIMESTAMP_HEADER, rec.headers)

    def test_create_alias_error(self) -> None:
        with MockServer() as server:
            server.json_responder(400, {"error": "bad target"})
            with self.assertRaises(RuntimeError) as ctx:
                create_alias("t", base_url=server.base_url)
            self.assertEqual(str(ctx.exception), "bad target")


class ConstructorTests(unittest.TestCase):
    def test_requires_private_key(self) -> None:
        with self.assertRaises(ValueError):
            cc_me.CcMeClient("")


if __name__ == "__main__":
    unittest.main()

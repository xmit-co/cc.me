"""Tests for the cc-me forward CLI."""

from __future__ import annotations

import threading
import unittest
from unittest import mock

import cc_me
from cc_me import _b64u_encode
from cc_me import forward as fwd

from .helpers import (
    KNOWN_SEED,
    MockServer,
    RecordedRequest,
    known_public_b64u,
    known_signing_key,
    make_captured_payload,
    seal_for,
)

PUB = known_public_b64u()
KEY_STR = _b64u_encode(KNOWN_SEED)


def _captured(method: str, query, body: bytes) -> cc_me.CapturedRequest:
    payload = make_captured_payload(
        id="m_x", method=method, path="/i/KEY", query=query, body=body,
        headers=[(b"content-type", b"application/json"), (b"x-keep", b"v")],
    )
    return cc_me._decode_captured_request(payload)


# --- argument parsing ------------------------------------------------------


class ParseArgsTests(unittest.TestCase):
    def setUp(self) -> None:
        # Ensure CC_ME_KEY does not leak in from the environment.
        self._env = mock.patch.dict("os.environ", {}, clear=False)
        self._env.start()
        import os

        os.environ.pop("CC_ME_KEY", None)

    def tearDown(self) -> None:
        self._env.stop()

    def test_target_only(self) -> None:
        key, target = fwd._parse_args(["http://localhost:1234/"])
        self.assertEqual(target, "http://localhost:1234/")
        self.assertEqual(key, fwd.DEFAULT_KEY_FILE)

    def test_key_space_value(self) -> None:
        key, target = fwd._parse_args(["--key", "/tmp/k.key", "http://t/"])
        self.assertEqual(key, "/tmp/k.key")
        self.assertEqual(target, "http://t/")

    def test_key_equals_value(self) -> None:
        key, target = fwd._parse_args(["--key=/tmp/k.key", "http://t/"])
        self.assertEqual(key, "/tmp/k.key")
        self.assertEqual(target, "http://t/")

    def test_key_missing_value_raises(self) -> None:
        with self.assertRaises(ValueError):
            fwd._parse_args(["--key"])

    def test_key_equals_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            fwd._parse_args(["--key="])

    def test_unknown_option_raises(self) -> None:
        with self.assertRaises(ValueError):
            fwd._parse_args(["--bogus", "http://t/"])

    def test_too_many_positionals_raises(self) -> None:
        with self.assertRaises(ValueError):
            fwd._parse_args(["http://a/", "http://b/"])

    def test_no_target_returns_none(self) -> None:
        key, target = fwd._parse_args([])
        self.assertIsNone(target)

    def test_env_key_default(self) -> None:
        import os

        os.environ["CC_ME_KEY"] = "/env/key"
        try:
            key, _ = fwd._parse_args(["http://t/"])
            self.assertEqual(key, "/env/key")
        finally:
            os.environ.pop("CC_ME_KEY", None)

    def test_help_exits_zero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            fwd._parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_short_help_exits_zero(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            fwd._parse_args(["-h"])
        self.assertEqual(ctx.exception.code, 0)


# --- main() exit codes -----------------------------------------------------


class MainExitCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        import os

        os.environ.pop("CC_ME_KEY", None)

    def test_missing_target_exit_64(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            fwd.main([])
        self.assertEqual(ctx.exception.code, 64)

    def test_unknown_option_exit_1(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            fwd.main(["--bogus", "http://t/"])
        self.assertEqual(ctx.exception.code, 1)

    def test_help_exit_0(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            fwd.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


# --- header stripping & url merge ------------------------------------------


class HeaderListTests(unittest.TestCase):
    def test_strips_hop_by_hop(self) -> None:
        payload = make_captured_payload(
            headers=[
                (b"content-type", b"application/json"),
                (b"Connection", b"keep-alive"),
                (b"Host", b"evil"),
                (b"Transfer-Encoding", b"chunked"),
                (b"x-keep", b"yes"),
            ],
            body=b"",
        )
        req = cc_me._decode_captured_request(payload)
        names = [n for n, _ in fwd._header_list(req)]
        self.assertIn("content-type", names)
        self.assertIn("x-keep", names)
        self.assertNotIn("Connection", names)
        self.assertNotIn("Host", names)
        self.assertNotIn("Transfer-Encoding", names)

    def test_case_insensitive_stripping(self) -> None:
        payload = make_captured_payload(
            headers=[(b"CONTENT-LENGTH", b"5"), (b"keep", b"v")], body=b""
        )
        req = cc_me._decode_captured_request(payload)
        names = [n for n, _ in fwd._header_list(req)]
        self.assertNotIn("CONTENT-LENGTH", names)
        self.assertIn("keep", names)


class ForwardUrlTests(unittest.TestCase):
    def test_no_query_on_either(self) -> None:
        req = _captured("GET", None, b"")
        self.assertEqual(
            fwd._forward_url("http://t/path", req), "http://t/path"
        )

    def test_request_query_only(self) -> None:
        req = _captured("GET", "a=1&b=2", b"")
        self.assertEqual(
            fwd._forward_url("http://t/path", req), "http://t/path?a=1&b=2"
        )

    def test_merge_base_and_request_query(self) -> None:
        req = _captured("GET", "a=1", b"")
        self.assertEqual(
            fwd._forward_url("http://t/path?base=0", req),
            "http://t/path?base=0&a=1",
        )

    def test_base_query_only(self) -> None:
        req = _captured("GET", None, b"")
        self.assertEqual(
            fwd._forward_url("http://t/?base=0", req), "http://t/?base=0"
        )


# --- end-to-end forwarding -------------------------------------------------


class _Sequencer:
    """Serves a scripted list of (status, json) responses, in order.

    Once the script is exhausted, repeats the last entry.
    """

    def __init__(self, script):
        self.script = script
        self.i = 0
        self.lock = threading.Lock()

    def __call__(self, _rec: RecordedRequest):
        import json as _json

        with self.lock:
            idx = min(self.i, len(self.script) - 1)
            self.i += 1
            status, obj = self.script[idx]
        return status, _json.dumps(obj).encode(), "application/json"


def _sealed(id, method="POST", query="a=1", body=b'{"k":1}', headers=None):
    if headers is None:
        headers = [
            (b"content-type", b"application/json"),
            (b"x-keep", b"keepme"),
            (b"Host", b"original-host"),
        ]
    payload = make_captured_payload(
        id=id, method=method, path="/i/KEY", query=query, body=body,
        headers=headers,
    )
    return {"id": id, "sealed": seal_for(known_signing_key(), payload)}


class EndToEndForwardTests(unittest.TestCase):
    def setUp(self) -> None:
        import os
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.key_file = os.path.join(self._dir.name, "test.key")
        # Write the known seed so the forward client uses the deterministic
        # identity that our sealed deliveries target.
        with open(self.key_file, "w", encoding="utf-8") as handle:
            handle.write(f"{KEY_STR}\n")

    def tearDown(self) -> None:
        self._dir.cleanup()

    def _run_loop(self, cc_server: MockServer, target: str):
        """Run _forward_loop with CC_ME_URL pointed at cc_server."""
        env = {"CC_ME_URL": cc_server.base_url, "CC_ME_LIMIT": "10"}
        with mock.patch.dict("os.environ", env):
            with mock.patch("sys.stderr"):
                # The loop is infinite; we break it by making the *second*
                # claim return a non-2xx, which raises and exits the loop.
                try:
                    fwd._forward_loop(self.key_file, target)
                except RuntimeError:
                    pass

    def test_success_path_query_merge_and_ack(self) -> None:
        # Target server: succeeds, records the forwarded request.
        with MockServer() as target, MockServer() as cc:
            target.json_responder(200, {"ok": True})

            item = _sealed("m_1", method="POST", query="a=1&b=2",
                           body=b'{"k":1}')
            cc.responder = _Sequencer([
                # first claim -> one delivery
                (200, {"count": 1, "items": [item]}),
                # ack -> ok
                (200, {"acked": 1, "missing": []}),
                # second claim -> error to break the loop
                (500, {"error": "stop"}),
            ])

            self._run_loop(cc, target.base_url + "hook?base=0")

            # Target received the forwarded request with merged query.
            tgt = target.requests[0]
            self.assertEqual(tgt.method, "POST")
            self.assertEqual(tgt.path_only, "/hook")
            self.assertEqual(tgt.query, "base=0&a=1&b=2")
            self.assertEqual(tgt.body, b'{"k":1}')
            # Passthrough header kept; hop-by-hop Host stripped (not original).
            self.assertEqual(tgt.headers.get("x-keep"), "keepme")
            self.assertNotEqual(tgt.headers.get("host"), "original-host")

            # cc.me saw: claim (POST .../claim), ack (POST .../ack), claim.
            cc_paths = [r.path for r in cc.requests]
            self.assertEqual(cc_paths[0], f"/i/{PUB}/claim")
            self.assertEqual(cc_paths[1], f"/i/{PUB}/ack")
            ack_req = cc.requests[1]
            self.assertEqual(ack_req.json(), {"ids": ["m_1"]})

    def test_get_delivery_has_no_body(self) -> None:
        with MockServer() as target, MockServer() as cc:
            target.json_responder(200, {})
            item = _sealed("m_g", method="GET", query="q=1", body=b"ignored")
            cc.responder = _Sequencer([
                (200, {"count": 1, "items": [item]}),
                (200, {"acked": 1}),
                (500, {"error": "stop"}),
            ])
            self._run_loop(cc, target.base_url + "g")
            self.assertEqual(target.requests[0].method, "GET")
            self.assertEqual(target.requests[0].body, b"")

    def test_target_failure_acks_handled_releases_remainder(self) -> None:
        # Two deliveries: first succeeds at target, second fails (target 500).
        # Expect: ack [m_1], release [m_2], loop exits non-zero.
        ok_calls = {"n": 0}

        with MockServer() as target, MockServer() as cc:

            def target_responder(_rec):
                ok_calls["n"] += 1
                if ok_calls["n"] == 1:
                    return 200, b"{}", "application/json"
                return 500, b'{"error":"boom"}', "application/json"

            target.responder = target_responder

            item1 = _sealed("m_1", body=b"one")
            item2 = _sealed("m_2", body=b"two")
            cc.responder = _Sequencer([
                (200, {"count": 2, "items": [item1, item2]}),
                # ack [m_1]
                (200, {"acked": 1, "missing": []}),
                # release [m_2]
                (200, {"released": 1, "missing": []}),
            ])

            import os

            with mock.patch.dict(
                "os.environ", {"CC_ME_URL": cc.base_url}
            ), mock.patch("sys.stderr"):
                with self.assertRaises(RuntimeError):
                    fwd._forward_loop(self.key_file, target.base_url + "hook")

            # cc.me request order: claim, ack, release.
            paths = [r.path for r in cc.requests]
            self.assertEqual(paths[0], f"/i/{PUB}/claim")
            self.assertEqual(paths[1], f"/i/{PUB}/ack")
            self.assertEqual(paths[2], f"/i/{PUB}/release")
            self.assertEqual(cc.requests[1].json(), {"ids": ["m_1"]})
            self.assertEqual(cc.requests[2].json(), {"ids": ["m_2"]})

    def test_first_delivery_failure_releases_all_no_ack(self) -> None:
        with MockServer() as target, MockServer() as cc:
            target.json_responder(500, {"error": "down"})
            item1 = _sealed("m_1")
            item2 = _sealed("m_2")
            cc.responder = _Sequencer([
                (200, {"count": 2, "items": [item1, item2]}),
                # release [m_1, m_2]
                (200, {"released": 2, "missing": []}),
            ])
            import os

            with mock.patch.dict(
                "os.environ", {"CC_ME_URL": cc.base_url}
            ), mock.patch("sys.stderr"):
                with self.assertRaises(RuntimeError):
                    fwd._forward_loop(self.key_file, target.base_url + "hook")

            paths = [r.path for r in cc.requests]
            # No ack since nothing succeeded; release covers both.
            self.assertEqual(paths[0], f"/i/{PUB}/claim")
            self.assertEqual(paths[1], f"/i/{PUB}/release")
            self.assertEqual(cc.requests[1].json(), {"ids": ["m_1", "m_2"]})


if __name__ == "__main__":
    unittest.main()

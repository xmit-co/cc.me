"""Tests for URL builders."""

from __future__ import annotations

import unittest
import urllib.parse

import cc_me
from cc_me import _b64u_encode, trampoline_url

from .helpers import KNOWN_SEED, known_public_b64u


def _client(base_url=None) -> cc_me.CcMeClient:
    return cc_me.CcMeClient(_b64u_encode(KNOWN_SEED), base_url=base_url)


PUB = known_public_b64u()


class TrampolineUrlTests(unittest.TestCase):
    def test_basic(self) -> None:
        url = trampoline_url("https://example.com/cb")
        parts = urllib.parse.urlsplit(url)
        self.assertEqual(parts.scheme, "https")
        self.assertEqual(parts.netloc, "cc.me")
        self.assertEqual(parts.path, "/")
        qs = urllib.parse.parse_qs(parts.query)
        self.assertEqual(qs["at"], ["https://example.com/cb"])

    def test_at_is_url_encoded(self) -> None:
        url = trampoline_url("https://example.com/a b?x=1&y=2")
        # The raw query must percent-encode the target so it round-trips.
        parts = urllib.parse.urlsplit(url)
        qs = urllib.parse.parse_qs(parts.query)
        self.assertEqual(qs["at"], ["https://example.com/a b?x=1&y=2"])
        # ampersand within the target must not leak as a separate param.
        self.assertNotIn("y", qs)

    def test_extra_params(self) -> None:
        url = trampoline_url(
            "https://example.com/cb", params={"state": "abc", "n": 5}
        )
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(qs["state"], ["abc"])
        self.assertEqual(qs["n"], ["5"])

    def test_at_comes_first(self) -> None:
        url = trampoline_url("T", params={"state": "abc"})
        query = urllib.parse.urlsplit(url).query
        self.assertTrue(query.startswith("at="))

    def test_none_params_skipped(self) -> None:
        url = trampoline_url("T", params={"state": None, "keep": "1"})
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertNotIn("state", qs)
        self.assertEqual(qs["keep"], ["1"])

    def test_base_url_override(self) -> None:
        url = trampoline_url("T", base_url="https://alt.example/")
        self.assertEqual(urllib.parse.urlsplit(url).netloc, "alt.example")


class InboxUrlTests(unittest.TestCase):
    def test_plain(self) -> None:
        self.assertEqual(_client().inbox_url(), f"https://cc.me/i/{PUB}")

    def test_limit_only(self) -> None:
        self.assertEqual(
            _client().inbox_url(limit=10), f"https://cc.me/i/{PUB}?l=10"
        )

    def test_cursor_only(self) -> None:
        self.assertEqual(
            _client().inbox_url(cursor="c1"), f"https://cc.me/i/{PUB}?c=c1"
        )

    def test_poll_renders_empty_value(self) -> None:
        self.assertEqual(
            _client().inbox_url(poll=True), f"https://cc.me/i/{PUB}?p="
        )

    def test_param_order_l_c_p(self) -> None:
        url = _client().inbox_url(limit=10, cursor="c1", poll=True)
        self.assertEqual(url, f"https://cc.me/i/{PUB}?l=10&c=c1&p=")

    def test_poll_false_omits_p(self) -> None:
        url = _client().inbox_url(limit=5, poll=False)
        self.assertEqual(url, f"https://cc.me/i/{PUB}?l=5")

    def test_base_url_override(self) -> None:
        url = _client(base_url="https://alt.example/").inbox_url()
        self.assertEqual(url, f"https://alt.example/i/{PUB}")


class ProtocolUrlTests(unittest.TestCase):
    def test_webmention(self) -> None:
        self.assertEqual(
            _client().webmention_url(), f"https://cc.me/i/{PUB}/webmention"
        )

    def test_websub(self) -> None:
        self.assertEqual(
            _client().websub_url(), f"https://cc.me/i/{PUB}/websub"
        )

    def test_slack(self) -> None:
        self.assertEqual(_client().slack_url(), f"https://cc.me/i/{PUB}/slack")

    def test_pingback(self) -> None:
        self.assertEqual(
            _client().pingback_url(), f"https://cc.me/i/{PUB}/pingback"
        )

    def test_cloudevents(self) -> None:
        self.assertEqual(
            _client().cloudevents_url(), f"https://cc.me/i/{PUB}/cloudevents"
        )

    def test_meta_without_token(self) -> None:
        self.assertEqual(_client().meta_url(), f"https://cc.me/i/{PUB}/meta")

    def test_meta_with_token(self) -> None:
        self.assertEqual(
            _client().meta_url("tok123"),
            f"https://cc.me/i/{PUB}/meta?v=tok123",
        )

    def test_meta_empty_token_still_appended(self) -> None:
        # verify_token of "" is not None, so v= is appended.
        self.assertEqual(
            _client().meta_url(""), f"https://cc.me/i/{PUB}/meta?v="
        )

    def test_protocol_base_url_override(self) -> None:
        url = _client(base_url="https://alt.example/").slack_url()
        self.assertEqual(url, f"https://alt.example/i/{PUB}/slack")


class DiscordUrlTests(unittest.TestCase):
    def test_path(self) -> None:
        self.assertEqual(
            _client().discord_url("APPKEY"),
            f"https://cc.me/i/{PUB}/discord/APPKEY",
        )

    def test_app_key_url_encoded(self) -> None:
        url = _client().discord_url("a/b")
        self.assertEqual(url, f"https://cc.me/i/{PUB}/discord/a%2Fb")

    def test_requires_app_key(self) -> None:
        with self.assertRaises(ValueError):
            _client().discord_url("")


if __name__ == "__main__":
    unittest.main()

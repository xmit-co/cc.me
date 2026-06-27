"""cc.me client library.

Mirrors the canonical JavaScript implementation in ``client/js/index.js``.
See ``client/PROTOCOL.md`` for the wire protocol.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence, Union

from nacl.exceptions import CryptoError
from nacl.public import SealedBox
from nacl.signing import SigningKey, VerifyKey

__all__ = [
    "CapturedHeader",
    "CapturedRequest",
    "CcMeClient",
    "DeliveryResponse",
    "create_alias",
    "private_key",
    "trampoline_url",
]

DEFAULT_BASE_URL = "https://cc.me/"
AUTH_VERSION = "cc-me-v1"
AUTH_TIMESTAMP_HEADER = "x-cc-me-timestamp"
AUTH_SIGNATURE_HEADER = "x-cc-me-signature"
SEED_BYTES = 32

KeyLike = Union[str, bytes, bytearray]


# --- base64url helpers (no padding) ---------------------------------------


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sha256_b64u(data: bytes) -> str:
    return _b64u_encode(hashlib.sha256(data).digest())


# --- key handling ----------------------------------------------------------


def _seed_bytes(value: KeyLike) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        seed = bytes(value)
    else:
        seed = _b64u_decode(value)
    if len(seed) != SEED_BYTES:
        raise ValueError("privateKey must be 32 bytes of base64url")
    return seed


def _signing_key(value: KeyLike) -> SigningKey:
    return SigningKey(_seed_bytes(value))


def _public_key_bytes(value: KeyLike) -> bytes:
    return bytes(_signing_key(value).verify_key)


def _public_key_string(value: KeyLike) -> str:
    if isinstance(value, str):
        return value
    return _b64u_encode(bytes(value))


def _generate_private_key() -> str:
    return _b64u_encode(bytes(SigningKey.generate()._seed))


def private_key(path: Optional[Union[str, os.PathLike]] = None) -> str:
    """Load or create a base64url Ed25519 seed.

    With no ``path`` an in-memory key is generated. With a ``path`` the file is
    reused if present (and re-secured to mode 0600), otherwise created with mode
    0600 containing the base64url seed followed by a newline.
    """
    if path is None:
        return _generate_private_key()

    try:
        with open(path, "r", encoding="utf-8") as handle:
            key = handle.read().strip()
        _seed_bytes(key)  # validate
        _secure_key_file(path)
        return key
    except FileNotFoundError:
        pass

    key = _generate_private_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(f"{key}\n")
    _secure_key_file(path)
    return key


def _secure_key_file(path: Union[str, os.PathLike]) -> None:
    if os.name == "nt":
        return
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# --- URL builders ----------------------------------------------------------


def _join_base(base_url: Optional[str], path: str) -> str:
    return urllib.parse.urljoin(base_url or DEFAULT_BASE_URL, path)


def _with_query(url: str, params: Sequence[tuple[str, str]]) -> str:
    parts = urllib.parse.urlsplit(url)
    existing = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + list(params)
    query = urllib.parse.urlencode(merged)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
    )


def _normalize_params(
    params: Optional[Mapping[str, Any]]
) -> list[tuple[str, str]]:
    if not params:
        return []
    out: list[tuple[str, str]] = []
    for key, value in params.items():
        if value is None:
            continue
        out.append((key, str(value)))
    return out


def trampoline_url(
    target: Any,
    base_url: Optional[str] = None,
    params: Optional[Mapping[str, Any]] = None,
) -> str:
    """Build a trampoline URL: ``{base}/?at={target}`` plus extra params."""
    url = _join_base(base_url, "/")
    return _with_query(url, [("at", str(target))] + _normalize_params(params))


def _inbox_path(public_key: KeyLike) -> str:
    return f"/i/{urllib.parse.quote(_public_key_string(public_key), safe='')}"


def _inbox_url(
    public_key: KeyLike,
    base_url: Optional[str] = None,
    limit: Optional[int] = None,
    cursor: Optional[str] = None,
    poll: bool = False,
) -> str:
    url = _join_base(base_url, _inbox_path(public_key))
    params: list[tuple[str, str]] = []
    if limit is not None:
        params.append(("l", str(limit)))
    if cursor is not None:
        params.append(("c", str(cursor)))
    if poll:
        params.append(("p", ""))
    if params:
        url = _with_query(url, params)
    return url


def _protocol_url(
    public_key: KeyLike, protocol: str, base_url: Optional[str] = None
) -> str:
    return _join_base(base_url, f"{_inbox_path(public_key)}/{protocol}")


# --- alias -----------------------------------------------------------------


@dataclass
class _AliasResponse:
    url: str


def create_alias(target: Any, base_url: Optional[str] = None) -> _AliasResponse:
    """POST ``{base}/c`` with ``{"at": target}`` → alias URL. Idempotent."""
    url = _join_base(base_url, "/c")
    body = json.dumps({"at": str(target)}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json"},
    )
    response = _send_json(request)
    return _AliasResponse(url=response["url"])


# --- HTTP helpers ----------------------------------------------------------


def _send_json(request: urllib.request.Request) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body = json.loads(raw) if raw else {}
        except (ValueError, json.JSONDecodeError):
            body = {}
        message = body.get("error") or f"cc.me request failed with {error.code}"
        raise RuntimeError(message) from None


# --- captured requests -----------------------------------------------------


@dataclass
class CapturedHeader:
    name: str
    value: str
    value_bytes: bytes


@dataclass
class CapturedRequest:
    id: str
    received_at_unix_ms: int
    method: str
    path: str
    query: Optional[str]
    headers: list[CapturedHeader]
    body_bytes: bytes

    def text(self) -> str:
        return self.body_bytes.decode("utf-8")

    def json(self) -> Any:
        return json.loads(self.body_bytes.decode("utf-8"))


@dataclass
class DeliveryResponse:
    count: int
    items: list[dict[str, Any]]
    cursor: Optional[str]
    requests: list[CapturedRequest]


def _decode_captured_request(plaintext: bytes) -> CapturedRequest:
    parsed = json.loads(plaintext.decode("utf-8"))
    body_bytes = _b64u_decode(parsed["body_b64u"])
    headers = []
    for header in parsed["headers"]:
        value_bytes = _b64u_decode(header["value_b64u"])
        headers.append(
            CapturedHeader(
                name=header["name"],
                value=value_bytes.decode("utf-8", errors="replace"),
                value_bytes=value_bytes,
            )
        )
    return CapturedRequest(
        id=parsed["id"],
        received_at_unix_ms=parsed["received_at_unix_ms"],
        method=parsed["method"],
        path=parsed["path"],
        query=parsed.get("query"),
        headers=headers,
        body_bytes=body_bytes,
    )


# --- client ----------------------------------------------------------------


class CcMeClient:
    def __init__(
        self,
        private_key: KeyLike,
        base_url: Optional[str] = None,
    ) -> None:
        if not private_key:
            raise ValueError("private_key is required")
        self._private_key = private_key
        self._base_url = base_url or DEFAULT_BASE_URL
        self._signing_key = _signing_key(private_key)
        self._public_key = _public_key_bytes(private_key)
        self._sealed_box = SealedBox(self._signing_key.to_curve25519_private_key())

    # -- URL helpers --

    def inbox_url(
        self,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        poll: bool = False,
    ) -> str:
        return _inbox_url(
            self._public_key,
            base_url=self._base_url,
            limit=limit,
            cursor=cursor,
            poll=poll,
        )

    def webmention_url(self) -> str:
        return _protocol_url(self._public_key, "webmention", self._base_url)

    def websub_url(self) -> str:
        return _protocol_url(self._public_key, "websub", self._base_url)

    def slack_url(self) -> str:
        return _protocol_url(self._public_key, "slack", self._base_url)

    def pingback_url(self) -> str:
        return _protocol_url(self._public_key, "pingback", self._base_url)

    def meta_url(self, verify_token: Optional[str] = None) -> str:
        url = _protocol_url(self._public_key, "meta", self._base_url)
        if verify_token is not None:
            url = _with_query(url, [("v", str(verify_token))])
        return url

    def cloudevents_url(self) -> str:
        return _protocol_url(self._public_key, "cloudevents", self._base_url)

    def discord_url(self, app_public_key: str) -> str:
        if not app_public_key:
            raise ValueError("app_public_key is required")
        return _join_base(
            self._base_url,
            f"{_inbox_path(self._public_key)}/discord/"
            f"{urllib.parse.quote(str(app_public_key), safe='')}",
        )

    # -- signing --

    def _sign(self, method: str, url: str, body: bytes) -> dict[str, str]:
        timestamp = int(time.time())
        parts = urllib.parse.urlsplit(url)
        path = parts.path
        if parts.query:
            path = f"{path}?{parts.query}"
        message = (
            f"{AUTH_VERSION}\n{method}\n{path}\n{timestamp}\n"
            f"{_sha256_b64u(body)}"
        ).encode("utf-8")
        signature = self._signing_key.sign(message).signature
        return {
            AUTH_TIMESTAMP_HEADER: str(timestamp),
            AUTH_SIGNATURE_HEADER: _b64u_encode(signature),
        }

    # -- decryption --

    def _decrypt_envelope(self, envelope: Mapping[str, Any]) -> CapturedRequest:
        sealed = _b64u_decode(envelope["sealed"])
        try:
            plaintext = self._sealed_box.decrypt(sealed)
        except CryptoError as error:
            raise RuntimeError("failed to decrypt delivery") from error
        request = _decode_captured_request(plaintext)
        if request.id != envelope["id"]:
            raise RuntimeError("delivery id mismatch")
        return request

    def _decrypt_response(
        self, body: Mapping[str, Any], decrypt: bool
    ) -> DeliveryResponse:
        items = body.get("items", [])
        requests = (
            [self._decrypt_envelope(item) for item in items] if decrypt else []
        )
        return DeliveryResponse(
            count=body.get("count", len(items)),
            items=list(items),
            cursor=body.get("cursor"),
            requests=requests,
        )

    # -- requests --

    def _action_url(self, action: str) -> str:
        base = self.inbox_url().rstrip("/")
        return f"{base}/{action}"

    def _get(self, url: str, decrypt: bool) -> DeliveryResponse:
        headers = self._sign("GET", url, b"")
        request = urllib.request.Request(url, method="GET", headers=headers)
        return self._decrypt_response(_send_json(request), decrypt)

    def _post(
        self, url: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = {"content-type": "application/json"}
        headers.update(self._sign("POST", url, body))
        request = urllib.request.Request(
            url, data=body, method="POST", headers=headers
        )
        return _send_json(request)

    def peek(
        self,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        poll: bool = False,
        decrypt: bool = True,
    ) -> DeliveryResponse:
        url = self.inbox_url(limit=limit, cursor=cursor, poll=poll)
        return self._get(url, decrypt)

    def claim(
        self,
        limit: Optional[int] = None,
        poll: bool = False,
        decrypt: bool = True,
    ) -> DeliveryResponse:
        url = self._action_url("claim")
        payload: dict[str, Any] = {"poll": poll}
        if limit is not None:
            payload["limit"] = limit
        body = json.dumps(payload).encode("utf-8")
        headers = {"content-type": "application/json"}
        headers.update(self._sign("POST", url, body))
        request = urllib.request.Request(
            url, data=body, method="POST", headers=headers
        )
        return self._decrypt_response(_send_json(request), decrypt)

    def ack(self, ids: Union[str, Iterable[str]]) -> dict[str, Any]:
        return self._post(self._action_url("ack"), {"ids": _to_ids(ids)})

    def release(self, ids: Union[str, Iterable[str]]) -> dict[str, Any]:
        return self._post(self._action_url("release"), {"ids": _to_ids(ids)})


def _to_ids(ids: Union[str, Iterable[str]]) -> list[str]:
    if isinstance(ids, str):
        return [ids]
    return list(ids)

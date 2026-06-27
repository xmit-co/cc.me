"""Shared test helpers for the cc-me Python client test suite."""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

from nacl.signing import SigningKey

# A fixed, known seed so derived public keys / inbox URLs are deterministic.
KNOWN_SEED = bytes(range(32))


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def known_signing_key() -> SigningKey:
    return SigningKey(KNOWN_SEED)


def known_public_b64u() -> str:
    return b64u_encode(bytes(known_signing_key().verify_key))


def seal_for(signing_key: SigningKey, plaintext: bytes) -> str:
    """Seal ``plaintext`` for the recipient identified by ``signing_key``.

    Returns the base64url-no-pad sealed box, exactly as a server would put it
    in the ``sealed`` envelope field.
    """
    from nacl.public import SealedBox

    box = SealedBox(signing_key.verify_key.to_curve25519_public_key())
    return b64u_encode(box.encrypt(plaintext))


def make_captured_payload(
    *,
    id: str = "m_test",
    received_at_unix_ms: int = 1781337600000,
    method: str = "POST",
    path: str = "/i/KEY",
    query: Optional[str] = "a=1&b=2",
    headers: Optional[list[tuple[str, bytes]]] = None,
    body: bytes = b"",
) -> bytes:
    """Build a captured-request JSON payload as the protocol describes."""
    if headers is None:
        headers = [(b"content-type", b"application/json")]
    payload: dict[str, Any] = {
        "id": id,
        "received_at_unix_ms": received_at_unix_ms,
        "method": method,
        "path": path,
        "query": query,
        "headers": [
            {"name": name.decode() if isinstance(name, bytes) else name,
             "value_b64u": b64u_encode(value)}
            for name, value in headers
        ],
        "body_b64u": b64u_encode(body),
    }
    return json.dumps(payload).encode("utf-8")


class RecordedRequest:
    def __init__(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> None:
        self.method = method
        self.path = path  # raw request target, including query
        self.headers = headers  # lower-cased names
        self.body = body

    @property
    def query(self) -> str:
        _, _, q = self.path.partition("?")
        return q

    @property
    def path_only(self) -> str:
        return self.path.partition("?")[0]

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8")) if self.body else None


# A response is (status, body_bytes, content_type).
Responder = Callable[[RecordedRequest], "tuple[int, bytes, str]"]


class MockServer:
    """A threaded HTTP server that records requests and replies via a handler.

    Use as a context manager. ``server.base_url`` is the http://host:port/ root.
    ``server.responder`` may be reassigned at any time; ``server.requests`` is
    the ordered list of received :class:`RecordedRequest` objects.
    """

    def __init__(self, responder: Optional[Responder] = None) -> None:
        self.requests: list[RecordedRequest] = []
        self.responder: Responder = responder or self._default_responder

        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # silence
                pass

            def _handle(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                headers = {k.lower(): v for k, v in self.headers.items()}
                rec = RecordedRequest(self.command, self.path, headers, body)
                recorder.requests.append(rec)
                status, payload, content_type = recorder.responder(rec)
                self.send_response(status)
                self.send_header("content-type", content_type)
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_DELETE = _handle
            do_PATCH = _handle
            do_HEAD = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )

    @staticmethod
    def _default_responder(rec: RecordedRequest) -> "tuple[int, bytes, str]":
        return 200, b"{}", "application/json"

    def json_responder(self, status: int, obj: Any) -> None:
        payload = json.dumps(obj).encode("utf-8")

        def respond(_rec: RecordedRequest) -> "tuple[int, bytes, str]":
            return status, payload, "application/json"

        self.responder = respond

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    def __enter__(self) -> "MockServer":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

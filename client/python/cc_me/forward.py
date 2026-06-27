"""cc-me forward CLI.

Ports the ``<forward-url>`` command from ``client/js/forward.js``. The
``inspect`` subcommand is intentionally not ported.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from . import CcMeClient, CapturedRequest, private_key

DEFAULT_KEY_FILE = os.path.join(os.path.expanduser("~"), ".cc-me.key")
DEFAULT_LIMIT = 10

HOP_BY_HOP = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def _usage() -> None:
    print("usage:\n  cc-me [--key <path>] <forward-url>", file=sys.stderr)


def _parse_args(args: list[str]) -> tuple[str, str | None]:
    key_file = os.environ.get("CC_ME_KEY") or DEFAULT_KEY_FILE
    positionals: list[str] = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--help", "-h"):
            _usage()
            sys.exit(0)
        if arg == "--key":
            i += 1
            if i >= len(args) or not args[i]:
                raise ValueError("--key needs a value")
            key_file = args[i]
            i += 1
            continue
        if arg.startswith("--key="):
            value = arg.split("=", 1)[1]
            if not value:
                raise ValueError("--key needs a value")
            key_file = value
            i += 1
            continue
        if arg.startswith("-"):
            raise ValueError(f"unknown option: {arg}")
        positionals.append(arg)
        i += 1

    if len(positionals) > 1:
        raise ValueError("only one forward URL is supported")

    target = positionals[0] if positionals else None
    return key_file, target


def _header_list(request: CapturedRequest) -> list[tuple[str, str]]:
    return [
        (header.name, header.value)
        for header in request.headers
        if header.name.lower() not in HOP_BY_HOP
    ]


def _forward_url(base: str, request: CapturedRequest) -> str:
    parts = urllib.parse.urlsplit(base)
    if request.query:
        query = (
            f"{parts.query}&{request.query}" if parts.query else request.query
        )
    else:
        query = parts.query
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
    )


def _forward_request(target: str, request: CapturedRequest) -> None:
    has_body = (
        request.method not in ("GET", "HEAD") and len(request.body_bytes) > 0
    )
    url = _forward_url(target, request)
    http_request = urllib.request.Request(
        url,
        data=request.body_bytes if has_body else None,
        method=request.method,
    )
    for name, value in _header_list(request):
        http_request.add_header(name, value)

    try:
        with urllib.request.urlopen(http_request) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"forward failed with {error.code}") from None

    if not (200 <= status < 300):
        raise RuntimeError(f"forward failed with {status}")


def _new_client(key_file: str) -> CcMeClient:
    key = private_key(key_file)
    return CcMeClient(private_key=key, base_url=os.environ.get("CC_ME_URL"))


def _forward_loop(key_file: str, target: str | None) -> None:
    if not target:
        _usage()
        sys.exit(64)

    cc = _new_client(key_file)

    print(f"cc.me inbox: {cc.inbox_url()}", file=sys.stderr)
    print(f"forwarding to: {target}", file=sys.stderr)

    limit = int(os.environ.get("CC_ME_LIMIT") or DEFAULT_LIMIT)

    while True:
        result = cc.claim(limit=limit, poll=True)
        requests = result.requests

        acked: list[str] = []
        for index, request in enumerate(requests):
            try:
                _forward_request(target, request)
                acked.append(request.id)
                query = f"?{request.query}" if request.query else ""
                print(f"{request.method} {request.path}{query}", file=sys.stderr)
            except Exception:
                release_ids = [item.id for item in requests[index:]]
                if acked:
                    try:
                        cc.ack(acked)
                    except Exception:
                        pass
                if release_ids:
                    try:
                        cc.release(release_ids)
                    except Exception:
                        pass
                raise
        if acked:
            cc.ack(acked)


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        key_file, target = _parse_args(args)
        _forward_loop(key_file, target)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - mirror JS top-level handler
        print(str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

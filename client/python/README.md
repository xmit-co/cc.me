# cc-me

Python client for [cc.me](https://cc.me/). The library builds trampoline and
inbox URLs and decrypts deliveries; the CLI forwards Safe inbox deliveries to a
local endpoint. Mirrors the canonical JavaScript client.

Requires Python 3.10+ and [PyNaCl](https://pypi.org/project/PyNaCl/).

```sh
pip install cc-me
```

Forward an inbox to a local endpoint:

```sh
cc-me http://example.local:8080/webhook
```

The CLI prints the inbox URL to register with the provider. It uses
`~/.cc-me.key` by default, creating it if needed and reusing it later. The key
is an Ed25519 seed; the URL shows the derived Ed25519 public key. Use `--key`
to choose a specific path:

```sh
cc-me --key ~/hooks.key http://example.local:8080/webhook
```

You can also set `CC_ME_KEY`, `CC_ME_URL`, and `CC_ME_LIMIT`.

```python
from cc_me import CcMeClient, create_alias, private_key

alias = create_alias("http://example.local/auth/callback")
print(f"OAuth callback URL: {alias.url}")

key = private_key("~/.cc-me.key".replace("~", __import__("os").path.expanduser("~")))
cc = CcMeClient(private_key=key)

print(f"Webhook URL: {cc.inbox_url()}")
print(f"Webmention URL: {cc.webmention_url()}")
print(f"WebSub URL: {cc.websub_url()}")
print(f"Slack URL: {cc.slack_url()}")
print(f"Pingback URL: {cc.pingback_url()}")
print(f"Meta URL: {cc.meta_url('shared-verify-token')}")
print(f"CloudEvents URL: {cc.cloudevents_url()}")
print(f"Discord URL: {cc.discord_url('discord-app-public-key')}")

result = cc.claim(limit=10, poll=True)

handled = []
for request in result.requests:
    print(request.method, request.path, request.text())
    handled.append(request.id)
cc.ack(handled)
```

`create_alias` is idempotent: calling it again with the same target returns the
same URL.

Protocol URL helpers return provider-ready receiver URLs. Webmention, WebSub,
Slack Events API, Pingback, Meta-style webhooks, CloudEvents, and Discord
Interactions deliveries arrive in the same Safe inbox and are read with `peek`
or `claim`.

`meta_url(token)` adds an optional verify token for Meta-style handshakes.
`cloudevents_url()` accepts binary, structured, and batched JSON CloudEvents.
`discord_url(app_public_key)` verifies Discord signatures and answers
interaction PINGs before storing non-PING interactions.

`limit` is optional. Omit it to use the service default:

```python
result = cc.claim(poll=True)
```

`peek` returns a cursor for live inspectors and dashboards:

```python
page = cc.peek(poll=True)
nxt = cc.peek(cursor=page.cursor, poll=True)
```

Call `private_key()` with no argument to create an in-memory key, or pass your
own stored base64url seed string to `CcMeClient(private_key=...)`.
`private_key(path)` creates and reuses a key file, keeping it private to the
user (mode 0600) on Unix-like systems.

# cc.me client protocol

Reference for the cc.me client libraries. The JavaScript implementation in
`client/js/` is the canonical port; the Go module at the repository root
(library in `ccme/`, CLI at the module root) and the `client/python/`,
`client/rust/`, and `client/ruby/` ports mirror it. The Rust server in
`src/main.rs` is the source of truth for the wire format.

## Keys

- A private key is a **32-byte Ed25519 seed**, stored as **base64url without
  padding**.
- The inbox is addressed by the **Ed25519 public key** derived from that seed,
  also base64url without padding.
- Key file: default `~/.cc-me.key` (override with `--key` or `CC_ME_KEY`).
  Created with mode `0600` if missing, reused otherwise. File contains the
  base64url seed followed by a newline.

## Base URL

Default `https://cc.me/`. The CLI honours `CC_ME_URL`.

## URL builders

- **Trampoline:** `GET {base}/?at={target}` plus any extra query params. Used
  for OAuth callbacks.
- **Alias:** `POST {base}/c` with JSON `{"at": target}` → `{"url": "..."}`.
  Idempotent (same target → same URL). No auth.
- **Inbox:** `{base}/i/{publicKeyB64u}`. Optional query: `l` (limit), `c`
  (cursor), `p` (poll; present with empty value when enabled). Param order when
  building: `l`, `c`, then `p`.
- **Protocol receivers:** `{inbox}/{protocol}` for `webmention`, `websub`,
  `slack`, `pingback`, `meta`, `cloudevents`. `meta` takes an optional verify
  token appended as `?v={token}`. Discord is `{inbox}/discord/{appPublicKey}`.

## Owner authentication

`GET` (peek), and `POST .../claim|ack|release` must be signed. Add two headers:

- `x-cc-me-timestamp`: current Unix time in **seconds**.
- `x-cc-me-signature`: base64url-no-pad Ed25519 detached signature over the
  canonical string below.

Canonical string (LF-separated, no trailing newline):

```
cc-me-v1
{METHOD}
{path-and-query}
{timestamp}
{base64url-no-pad(SHA256(body))}
```

- `{METHOD}` is the HTTP method, e.g. `GET`, `POST`.
- `{path-and-query}` is exactly the request target sent on the wire
  (`/i/KEY/claim`, or `/i/KEY?l=10&p=` for a poll). **The bytes you sign must
  equal the bytes you send** — build the path+query once and use it for both.
- `body` is the raw request body bytes (empty for GET → SHA256 of zero bytes).
  The server hashes whatever body bytes arrive, so the JSON formatting is free
  as long as the signed body equals the sent body.

## Client methods

All inbox responses are JSON.

- **peek** `GET /i/KEY?l=&c=&p` → `{count, items: [{id, sealed}], cursor}`.
- **claim** `POST /i/KEY/claim` body `{limit?, poll?}` →
  `{count, items: [{id, sealed}]}`. Reserves deliveries until ack/release.
- **ack** `POST /i/KEY/ack` body `{ids: [...]}` → `{acked, missing: [...]}`.
- **release** `POST /i/KEY/release` body `{ids: [...]}` →
  `{released, missing: [...]}`.

Non-2xx responses carry `{"error": "..."}`; surface that message.

## Decrypting a delivery (`sealed`)

Each `sealed` value is base64url-no-pad of a **libsodium sealed box**
(`crypto_box_seal`) targeting the recipient's X25519 key, which is derived from
the Ed25519 identity:

1. `sealedBytes = base64url_decode(sealed)`.
2. `ephemeralPublicKey = sealedBytes[0:32]`, `box = sealedBytes[32:]`.
3. Recipient X25519 **public** key = Montgomery form of the Ed25519 public key.
4. Recipient X25519 **secret** key = libsodium
   `crypto_sign_ed25519_sk_to_curve25519` of the Ed25519 secret (i.e. the first
   32 bytes of `SHA512(seed)`, then standard X25519 clamping).
5. `nonce = BLAKE2b(ephemeralPublicKey || recipientPublicKey, digest = 24 bytes,
   no key)`.
6. `plaintext = crypto_box_open(box, nonce, ephemeralPublicKey, recipientSecret)`
   (X25519 + XSalsa20-Poly1305).

Most libraries expose this as a single "sealed box open" call given the
recipient X25519 keypair, which performs steps 2, 5, and 6 for you.

### Decrypted payload (JSON)

```json
{
  "id": "m_...",
  "received_at_unix_ms": 1781337600000,
  "method": "POST",
  "path": "/i/...",
  "query": "a=1&b=2",
  "headers": [{ "name": "content-type", "value_b64u": "..." }],
  "body_b64u": "..."
}
```

Header values and the body are base64url-no-pad. The delivery `id` inside the
plaintext must equal the envelope `id`.

## Forward CLI

`cc-me [--key <path>] <forward-url>`:

1. Load/create the key, print the inbox URL and the forward target.
2. Loop: `claim({limit: CC_ME_LIMIT||10, poll: true})`.
3. For each delivery in order, replay it to `<forward-url>`: same method, same
   headers (minus hop-by-hop: `connection`, `content-length`, `host`,
   `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`,
   `transfer-encoding`, `upgrade`), body for non-GET/HEAD, and merge the
   delivery `query` into the target URL's query.
4. On success collect the id. On failure: `ack` the ones already handled,
   `release` the current and remaining ids, then exit non-zero.
5. After the batch, `ack` all handled ids.

`inspect` is intentionally **not** ported (JS only).

Env: `CC_ME_KEY`, `CC_ME_URL`, `CC_ME_LIMIT`.

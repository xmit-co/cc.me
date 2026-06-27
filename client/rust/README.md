# cc.me — Rust client

A Rust port of the [cc.me](https://cc.me/) client library and the `cc-me`
forward CLI. It mirrors the canonical JavaScript implementation in
`../js/index.js` and follows the wire protocol in `../PROTOCOL.md`. The Rust
server (`../../src/main.rs`) is the source of truth for the wire format; the
crypto crates here are pinned to the same versions the server locks so the
sealed-box decrypt path interoperates with the server's `PublicKey::seal`.

Published on [crates.io](https://crates.io/crates/cc-me).

## Install

```sh
cargo install cc-me   # the cc-me forward CLI
cargo add cc-me       # the library
```

## Library

```rust
use cc_me::{CcMeClient, ListOptions, private_key};
use std::path::Path;

// Load or create a 32-byte Ed25519 seed (base64url, mode 0600 on unix).
let key = private_key(Some(Path::new("~/.cc-me.key")))?;
let client = CcMeClient::new(key, None)?; // None => https://cc.me/

// Addressable URLs.
println!("{}", client.inbox_url(&ListOptions::default()));
println!("{}", client.slack_url());
println!("{}", client.meta_url(Some("verify-token")));
println!("{}", client.discord_url("APP_PUBLIC_KEY"));

// Claim, forward, ack.
let batch = client.claim(&ListOptions { limit: Some(10), poll: true, ..Default::default() })?;
for delivery in &batch.requests {
    println!("{} {} {:?}", delivery.method, delivery.path, delivery.text());
}
client.ack(&batch.requests.iter().map(|d| d.id.clone()).collect::<Vec<_>>())?;
```

Free functions: `private_key`, `trampoline_url`, `create_alias`.

`CcMeClient` methods: `inbox_url`, `webmention_url`, `websub_url`, `slack_url`,
`pingback_url`, `meta_url`, `cloud_events_url`, `discord_url`, `peek`, `claim`,
`ack`, `release`.

Each decrypted `Delivery` exposes `id`, `received_at_unix_ms`, `method`,
`path`, `query`, `headers` (`name`, `value`, `value_bytes`), `body_bytes`, and
`text()` / `json()` helpers. The decrypted `id` is verified against the
envelope `id`.

## CLI

```
cc-me [--key <path>] <forward-url>
```

Claims deliveries in a poll loop and replays each one to `<forward-url>`:
same method, same headers (minus hop-by-hop headers), body for non-GET/HEAD,
and the delivery's query string merged into the target URL. Successfully
forwarded deliveries are acked; on a forward failure the already-handled ids
are acked, the current and remaining ids are released, and the process exits
non-zero.

Environment:

- `CC_ME_KEY` — key file path (default `~/.cc-me.key`).
- `CC_ME_URL` — base URL (default `https://cc.me/`).
- `CC_ME_LIMIT` — claim batch size (default `10`).

The `inspect` subcommand from the JS CLI is intentionally not ported.

## Crypto

- **Signing:** `ed25519-dalek` `SigningKey::sign` over the canonical
  `cc-me-v1` string; signature base64url-no-pad.
- **Decryption:** `crypto_box`'s libsodium sealed-box `unseal`. The recipient
  X25519 secret is derived from the Ed25519 seed as the first 32 bytes of
  `SHA512(seed)` (X25519 clamping applied by `SecretKey::from_bytes`), matching
  libsodium's `crypto_sign_ed25519_sk_to_curve25519`.

## Build & test

```
cargo fmt
cargo build
cargo test
```

The test suite includes an interop test that seals a payload via the server's
exact Ed25519→X25519 derivation and `PublicKey::seal`, then decrypts it through
the client.

Note: `ureq` and `getrandom` are not in the server's `Cargo.lock`, so the first
build fetches them from crates.io (network required).

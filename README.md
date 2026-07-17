# cc.me

Small Axum service for OAuth callbacks and encrypted webhook inboxes:

- `GET /?at=<url>&code=...&state=...` redirects to `at`, appending every query
  parameter except `at`.
- `POST /c` creates or returns the short OAuth callback alias for a target.
- `POST /i/<ed25519-public-key>` captures a webhook request, encrypts it for
  that public key, and stores it for later handling.
- `POST /i/<key-a>.<key-b>` fans out one encrypted copy per recipient.
- `/i/<key>/webmention`, `/websub`, `/slack`, `/pingback`, `/meta`,
  `/cloudevents`, and `/discord/<app-public-key>` add small protocol handling
  before storing deliveries in the same inbox.
- `GET /i/<key>` looks ahead without removing deliveries.
- `POST /i/<key>/claim` reserves deliveries for handling.
- `POST /i/<key>/ack` removes handled deliveries in batches.
- `POST /i/<key>/release` makes claimed deliveries ready again.

The inbox URL contains an Ed25519 public key. Deliveries are encrypted with the
X25519 key derived from it. `GET`, `claim`, `ack`, and `release` must include a
valid `x-cc-me-timestamp` and `x-cc-me-signature` header signed by the
corresponding Ed25519 private key.

Requests are only stored when captured method, path, query, headers, and body
fit within 64 KiB. GET and claim responses return only as many items as fit
within 1 MiB. If an inbox is full, new captures are rejected and existing
deliveries are not removed.

## Run

```sh
process-compose up
```

That starts Postgres and the app. The service listens on `0.0.0.0:3000` by
default.

To run the packaged service binary directly:

```sh
nix run github:xmit-co/cc.me
```

## Configuration

| Variable                  |                              Default | Meaning                                                 |
| ------------------------- | -----------------------------------: | ------------------------------------------------------- |
| `BIND_ADDR`               |                     `127.0.0.1:3000` | HTTP bind address                                       |
| `DATABASE_URL`            | `postgres://127.0.0.1:5432/postgres` | Postgres connection URL                                 |
| `INBOX_MAX_REQUESTS`      |                                `100` | Stored encrypted requests per public key                |
| `INBOX_DEFAULT_GET_LIMIT` |                                  `1` | Default GET/claim batch size when a limit is omitted    |
| `INBOX_MAX_GET_LIMIT`     |                               `1000` | Cap for requested batch sizes                           |
| `INBOX_LONG_POLL_SECONDS` |                                 `25` | Long-poll wait used by `?p` and `claim({ poll: true })` |
| `SHOT_CHROME_BIN`         |                           `chromium` | Chromium binary managed for `/shot` screenshots         |
| `SHOT_CHROME_ARGS`        |                              _empty_ | Extra whitespace-separated Chromium flags               |
| `SHOT_POW_LEVEL`          |                                 `22` | Proof-of-work level required by `/shot`                 |
| `SHOT_TS_WINDOW_SECONDS`  |                                `300` | Accepted `ts` skew in `/shot` documents                 |
| `SHOT_NAV_TIMEOUT_SECONDS`|                                 `10` | Page-load timeout per screenshot                        |
| `SHOT_CACHE_SECONDS`      |                               `3600` | Screenshot cache lifetime                               |
| `SHOT_CHROME_MAX_RENDERS` |                                 `64` | Renders before the managed Chrome is recycled           |

Chrome's memory is bounded in layers: renderers are limited to one per
concurrent render with a capped V8 heap, the browser is respawned every
`SHOT_CHROME_MAX_RENDERS` renders, and deployments should add a hard ceiling
around the service (e.g. systemd `MemoryMax=2G`, `MemorySwapMax=0`) — under
cgroup OOM the kernel kills the fattest process, a Chrome renderer, and the
service respawns the browser on the next request.

`GET /pow` documents a JWT-shaped proof-of-work token format with an in-browser
solver and verifier; reference CPU (Node) and GPU (Metal, OpenCL) solvers live
in `pow/`. `GET /shot` renders screenshots in a managed headless Chrome —
disposable incognito-style contexts, up to 2048×2048 with Chrome-side
downscaling, cached for an hour — gated by proof-of-work tokens; the
required level and other expectations are served at `GET /shot/config`.

Static docs live in `docs/`. The Go client is the module at the repository root
(`go install cc.me@latest` for the CLI, `import "cc.me/ccme"` for the library;
the server answers the `go-import` handshake on `?go-get=1`). The other clients
live under `client/`: the JavaScript package in `client/js/`, plus ports in
`client/python/`, `client/rust/`, and `client/ruby/`.

The client CLI can forward or inspect inbox deliveries:

```sh
npx cc-me http://example.local:8080/webhook
npx cc-me inspect
```

By [xmit dev team](https://xmit.dev/). We respect privacy: HTTP deliveries are
encrypted for your key and we don't inspect your emails.

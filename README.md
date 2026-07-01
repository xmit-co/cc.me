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

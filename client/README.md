# cc-me

ESM client for browsers, Node.js, Bun, and Deno. The library can build
trampoline URLs; the CLI forwards or inspects Safe inbox deliveries.

Package: <https://www.npmjs.com/package/cc-me>

```sh
npm install cc-me
```

Forward an inbox to a local endpoint:

```sh
npx cc-me http://example.local:8080/webhook
pnpx cc-me http://example.local:8080/webhook
bunx cc-me http://example.local:8080/webhook
deno run -A npm:cc-me http://example.local:8080/webhook
```

Inspect a Safe inbox locally before acknowledging deliveries:

```sh
npx cc-me inspect
pnpx cc-me inspect
bunx cc-me inspect
deno run -A npm:cc-me inspect
```

The CLI prints the inbox URL to register with the provider. It uses
`~/.cc-me.key` by default, creating it if needed and reusing it later. The key
is an Ed25519 seed; the URL shows the derived Ed25519 public key. Use `--key`
to choose a specific path:

```sh
npx cc-me --key ~/hooks.key http://example.local:8080/webhook
```

You can also set `CC_ME_KEY`.

```js
import { homedir } from "node:os";
import { CcMeClient, createAlias, privateKey } from "cc-me";

const alias = await createAlias("http://example.local/auth/callback");
console.log(`OAuth callback URL: ${alias.url}`);

const key = await privateKey(`${homedir()}/.cc-me.key`);
const cc = new CcMeClient({ privateKey: key });

console.log(`Webhook URL: ${await cc.inboxUrl()}`);
console.log(`Webmention URL: ${await cc.webmentionUrl()}`);
console.log(`WebSub URL: ${await cc.websubUrl()}`);
console.log(`Slack URL: ${await cc.slackUrl()}`);
console.log(`Pingback URL: ${await cc.pingbackUrl()}`);
console.log(`Meta URL: ${await cc.metaUrl("shared-verify-token")}`);
console.log(`CloudEvents URL: ${await cc.cloudEventsUrl()}`);
console.log(`Discord URL: ${await cc.discordUrl("discord-app-public-key")}`);
const { requests } = await cc.claim({ limit: 10, poll: true });

const handled = [];
for (const request of requests) {
  console.log(request.method, request.path, request.text());
  handled.push(request.id);
}
await cc.ack(handled);
```

`createAlias` is idempotent: calling it again with the same target returns the same URL.

Protocol URL helpers return provider-ready receiver URLs. Webmention, WebSub, Slack Events API,
Pingback, Meta-style webhooks, CloudEvents, and Discord Interactions deliveries arrive in the same
Safe inbox and are read with `peek` or `claim`.

`metaUrl(token)` adds an optional verify token for Meta-style handshakes.
`cloudEventsUrl()` accepts binary, structured, and batched JSON CloudEvents.
`discordUrl(appPublicKey)` verifies Discord signatures and answers interaction
PINGs before storing non-PING interactions.

`limit` is optional. Omit it to use the service default:

```js
const { requests } = await cc.claim({ poll: true });
```

`peek` returns a cursor for live inspectors and dashboards:

```js
const page = await cc.peek({ poll: true });
const next = await cc.peek({ cursor: page.cursor, poll: true });
```

Browser code can import the same ESM package. In browsers, call `privateKey()`
to create an in-memory key or provide your own stored key string to
`new CcMeClient({ privateKey })`. `privateKey(path)` creates and reuses a key
file on Node.js, Bun, and Deno, keeping it private to the user on Unix-like
systems.

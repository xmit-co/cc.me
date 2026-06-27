import { assertEquals, assertMatch, assertNotEquals, assertRejects, assertThrows } from "jsr:@std/assert";
import nacl from "tweetnacl";
import ed2curve from "ed2curve";

import {
  CcMeClient,
  createAlias,
  privateKey,
  trampolineUrl,
} from "./index.js";
import {
  b64uToBytes,
  bytesToB64u,
  ed25519PublicKey,
  KNOWN_SEED_B64U,
  KNOWN_SEED_BYTES,
  recipientX25519Public,
  sealedDelivery,
  sealForSeed,
  startServer,
} from "./test_helpers.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// --- Internals that are not exported are exercised through public surface.
// base64url has no direct export, so we round-trip it via privateKey() (which
// returns a base64url seed) and via the decryption path. We additionally test
// base64url decode tolerance directly through the alphabet of a known key.

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

Deno.test("base64url: in-memory privateKey is base64url with no padding", async () => {
  const key = await privateKey();
  assertEquals(typeof key, "string");
  assertEquals(key.includes("="), false);
  assertEquals(key.includes("+"), false);
  assertEquals(key.includes("/"), false);
  assertMatch(key, /^[A-Za-z0-9_-]+$/);
});

Deno.test("base64url: privateKey decodes back to exactly 32 bytes", async () => {
  for (let i = 0; i < 25; i += 1) {
    const key = await privateKey();
    const bytes = b64uToBytes(key);
    assertEquals(bytes.length, 32);
  }
});

Deno.test("base64url: round-trips arbitrary byte values", () => {
  for (let len = 0; len < 40; len += 1) {
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i += 1) {
      bytes[i] = (i * 37 + len * 11) & 0xff;
    }
    const encoded = bytesToB64u(bytes);
    assertEquals([...b64uToBytes(encoded)], [...bytes]);
  }
});

Deno.test("base64url: encoded output never contains + / or =", () => {
  const bytes = new Uint8Array([0xfb, 0xff, 0xbf, 0xfe, 0xff]); // forces +/ in std b64
  const encoded = bytesToB64u(bytes);
  assertEquals(/[+/=]/.test(encoded), false);
  assertMatch(encoded, /[-_]/); // uses url-safe alphabet
});

Deno.test("base64url: decode tolerates - and _ and missing padding", () => {
  const bytes = new Uint8Array([0xfb, 0xef, 0xbe]);
  const std = bytesToB64u(bytes); // url-safe, unpadded
  // Add padding back; decoder must accept both forms via Buffer base64url.
  assertEquals([...b64uToBytes(std)], [...bytes]);
  // A value containing both - and _.
  const mixed = bytesToB64u(new Uint8Array([0xff, 0xe0, 0xff]));
  assertMatch(mixed, /[-_]/);
  assertEquals([...b64uToBytes(mixed)], [255, 224, 255]);
});

// ---------------------------------------------------------------------------
// Key handling: privateKey()
// ---------------------------------------------------------------------------

Deno.test("privateKey(): generates unique 32-byte seeds", async () => {
  const a = await privateKey();
  const b = await privateKey();
  assertNotEquals(a, b);
  assertEquals(b64uToBytes(a).length, 32);
});

Deno.test("privateKey(path): creates file with mode 0600 and trailing newline", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/cc-me.key`;
  const key = await privateKey(path);

  const contents = await Deno.readTextFile(path);
  assertEquals(contents, `${key}\n`);
  assertEquals(contents.endsWith("\n"), true);
  assertEquals(b64uToBytes(key).length, 32);

  if (Deno.build.os !== "windows") {
    const info = await Deno.stat(path);
    assertEquals(info.mode & 0o777, 0o600);
  }
  await Deno.remove(dir, { recursive: true });
});

Deno.test("privateKey(path): reuses the same key on a second call", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/cc-me.key`;
  const first = await privateKey(path);
  const second = await privateKey(path);
  assertEquals(first, second);
  await Deno.remove(dir, { recursive: true });
});

Deno.test("privateKey(path): trims surrounding whitespace when reusing", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/cc-me.key`;
  const seed = bytesToB64u(KNOWN_SEED_BYTES);
  await Deno.writeTextFile(path, `  ${seed}\n\n`);
  const key = await privateKey(path);
  assertEquals(key, seed);
  await Deno.remove(dir, { recursive: true });
});

Deno.test("privateKey(path): rejects a too-short key", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/cc-me.key`;
  await Deno.writeTextFile(path, bytesToB64u(new Uint8Array(16)));
  await assertRejects(() => privateKey(path), TypeError, "32 bytes");
  await Deno.remove(dir, { recursive: true });
});

Deno.test("privateKey(path): rejects a too-long key", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/cc-me.key`;
  await Deno.writeTextFile(path, bytesToB64u(new Uint8Array(64)));
  await assertRejects(() => privateKey(path), TypeError, "32 bytes");
  await Deno.remove(dir, { recursive: true });
});

Deno.test("privateKey(path): malformed base64url still decodes to wrong length and rejects", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/cc-me.key`;
  await Deno.writeTextFile(path, "not-a-valid-32-byte-key");
  await assertRejects(() => privateKey(path), TypeError);
  await Deno.remove(dir, { recursive: true });
});

// ---------------------------------------------------------------------------
// Public key + inbox URL derivation determinism
// ---------------------------------------------------------------------------

const KNOWN_PUB_B64U = bytesToB64u(ed25519PublicKey(KNOWN_SEED_BYTES));

Deno.test("derivation: inbox URL is deterministic for a known seed", async () => {
  const a = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  const b = new CcMeClient({ privateKey: KNOWN_SEED_BYTES, fetch: () => {} });
  const urlA = await a.inboxUrl();
  const urlB = await b.inboxUrl();
  assertEquals(urlA, urlB);
  assertEquals(urlA, `https://cc.me/i/${KNOWN_PUB_B64U}`);
});

Deno.test("derivation: public key matches tweetnacl directly", () => {
  const pub = nacl.sign.keyPair.fromSeed(KNOWN_SEED_BYTES).publicKey;
  assertEquals(bytesToB64u(pub), KNOWN_PUB_B64U);
});

// ---------------------------------------------------------------------------
// Signing (canonical string + signature verification) via a capturing fetch
// ---------------------------------------------------------------------------

function capture() {
  const calls = [];
  const fetch = (url, init = {}) => {
    const headers = new Headers(init.headers);
    calls.push({ url: String(url), method: init.method ?? "GET", headers, body: init.body });
    return Promise.resolve(
      new Response(JSON.stringify({ count: 0, items: [], cursor: null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  };
  return { calls, fetch };
}

async function sha256B64u(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToB64u(new Uint8Array(digest));
}

function verifySignature(call, seed, method, expectedPath, expectedBody) {
  const ts = call.headers.get("x-cc-me-timestamp");
  const sig = call.headers.get("x-cc-me-signature");
  const bodyBytes = encoder.encode(expectedBody ?? "");
  return sha256B64u(bodyBytes).then((hash) => {
    const canonical = `cc-me-v1\n${method}\n${expectedPath}\n${ts}\n${hash}`;
    const pub = ed25519PublicKey(seed);
    return nacl.sign.detached.verify(
      encoder.encode(canonical),
      b64uToBytes(sig),
      pub,
    );
  });
}

Deno.test("signing: peek (GET) sends both auth headers", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.peek();
  assertEquals(calls.length, 1);
  assertEquals(calls[0].method, "GET");
  assertMatch(calls[0].headers.get("x-cc-me-timestamp"), /^\d+$/);
  assertMatch(calls[0].headers.get("x-cc-me-signature"), /^[A-Za-z0-9_-]+$/);
});

Deno.test("signing: GET signature verifies against derived public key", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.peek({ limit: 10, poll: true });
  const path = `/i/${KNOWN_PUB_B64U}?l=10&p=`;
  assertEquals(await verifySignature(calls[0], KNOWN_SEED_BYTES, "GET", path, ""), true);
});

Deno.test("signing: GET empty-body hash equals sha256 of zero bytes", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.peek();
  const ts = calls[0].headers.get("x-cc-me-timestamp");
  const emptyHash = await sha256B64u(new Uint8Array(0));
  const path = `/i/${KNOWN_PUB_B64U}`;
  const canonical = `cc-me-v1\nGET\n${path}\n${ts}\n${emptyHash}`;
  const ok = nacl.sign.detached.verify(
    encoder.encode(canonical),
    b64uToBytes(calls[0].headers.get("x-cc-me-signature")),
    ed25519PublicKey(KNOWN_SEED_BYTES),
  );
  assertEquals(ok, true);
});

Deno.test("signing: signed path equals the requested path+query", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.peek({ limit: 5, cursor: "abc", poll: true });
  const requested = new URL(calls[0].url);
  const path = `${requested.pathname}${requested.search}`;
  assertEquals(path, `/i/${KNOWN_PUB_B64U}?l=5&c=abc&p=`);
  assertEquals(await verifySignature(calls[0], KNOWN_SEED_BYTES, "GET", path, ""), true);
});

Deno.test("signing: claim (POST) signs the JSON body hash", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.claim({ limit: 3, poll: true });
  const body = calls[0].body;
  assertEquals(body, JSON.stringify({ limit: 3, poll: true }));
  const path = `/i/${KNOWN_PUB_B64U}/claim`;
  assertEquals(calls[0].method, "POST");
  assertEquals(await verifySignature(calls[0], KNOWN_SEED_BYTES, "POST", path, body), true);
  assertEquals(calls[0].headers.get("content-type"), "application/json");
});

Deno.test("signing: ack/release sign their id bodies and verify", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.ack("m_1");
  await cc.release(["m_2", "m_3"]);
  assertEquals(calls[0].body, JSON.stringify({ ids: ["m_1"] }));
  assertEquals(calls[1].body, JSON.stringify({ ids: ["m_2", "m_3"] }));
  const ackPath = `/i/${KNOWN_PUB_B64U}/ack`;
  const relPath = `/i/${KNOWN_PUB_B64U}/release`;
  assertEquals(await verifySignature(calls[0], KNOWN_SEED_BYTES, "POST", ackPath, calls[0].body), true);
  assertEquals(await verifySignature(calls[1], KNOWN_SEED_BYTES, "POST", relPath, calls[1].body), true);
});

Deno.test("signing: a tampered body fails verification", async () => {
  const { calls, fetch } = capture();
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.claim({ limit: 1 });
  const path = `/i/${KNOWN_PUB_B64U}/claim`;
  assertEquals(await verifySignature(calls[0], KNOWN_SEED_BYTES, "POST", path, "{}"), false);
});

// ---------------------------------------------------------------------------
// URL builders
// ---------------------------------------------------------------------------

Deno.test("trampolineUrl: encodes target into the at param", () => {
  const url = trampolineUrl("https://example.com/cb?x=1");
  const parsed = new URL(url);
  assertEquals(parsed.origin, "https://cc.me");
  assertEquals(parsed.pathname, "/");
  assertEquals(parsed.searchParams.get("at"), "https://example.com/cb?x=1");
});

Deno.test("trampolineUrl: merges extra params and honours baseUrl", () => {
  const url = trampolineUrl("https://t.example/cb", {
    baseUrl: "https://relay.test/",
    params: { state: "xyz", code: "1" },
  });
  const parsed = new URL(url);
  assertEquals(parsed.origin, "https://relay.test");
  assertEquals(parsed.searchParams.get("at"), "https://t.example/cb");
  assertEquals(parsed.searchParams.get("state"), "xyz");
  assertEquals(parsed.searchParams.get("code"), "1");
});

Deno.test("trampolineUrl: accepts URLSearchParams as params", () => {
  const url = trampolineUrl("https://t.example/cb", {
    params: new URLSearchParams({ a: "1", b: "2" }),
  });
  const parsed = new URL(url);
  assertEquals(parsed.searchParams.get("a"), "1");
  assertEquals(parsed.searchParams.get("b"), "2");
});

Deno.test("inboxUrl: param order is l, c, then p", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  const url = await cc.inboxUrl({ limit: 10, cursor: "cur", poll: true });
  assertEquals(url, `https://cc.me/i/${KNOWN_PUB_B64U}?l=10&c=cur&p=`);
});

Deno.test("inboxUrl: poll renders as bare p= with empty value", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  const url = await cc.inboxUrl({ poll: true });
  assertEquals(url, `https://cc.me/i/${KNOWN_PUB_B64U}?p=`);
});

Deno.test("inboxUrl: omits absent optional params", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  assertEquals(await cc.inboxUrl(), `https://cc.me/i/${KNOWN_PUB_B64U}`);
  assertEquals(await cc.inboxUrl({ limit: 5 }), `https://cc.me/i/${KNOWN_PUB_B64U}?l=5`);
  assertEquals(await cc.inboxUrl({ cursor: "z" }), `https://cc.me/i/${KNOWN_PUB_B64U}?c=z`);
});

Deno.test("inboxUrl: respects a custom baseUrl", async () => {
  const cc = new CcMeClient({
    privateKey: KNOWN_SEED_B64U,
    fetch: () => {},
    baseUrl: "https://relay.test/",
  });
  assertEquals(await cc.inboxUrl(), `https://relay.test/i/${KNOWN_PUB_B64U}`);
});

Deno.test("protocol URLs: webmention/websub/slack/pingback/cloudevents", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  const base = `https://cc.me/i/${KNOWN_PUB_B64U}`;
  assertEquals(await cc.webmentionUrl(), `${base}/webmention`);
  assertEquals(await cc.websubUrl(), `${base}/websub`);
  assertEquals(await cc.slackUrl(), `${base}/slack`);
  assertEquals(await cc.pingbackUrl(), `${base}/pingback`);
  assertEquals(await cc.cloudEventsUrl(), `${base}/cloudevents`);
});

Deno.test("metaUrl: without a verify token", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  assertEquals(await cc.metaUrl(), `https://cc.me/i/${KNOWN_PUB_B64U}/meta`);
});

Deno.test("metaUrl: with a verify token appended as ?v=", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  assertEquals(await cc.metaUrl("tok 123"), `https://cc.me/i/${KNOWN_PUB_B64U}/meta?v=tok+123`);
});

Deno.test("discordUrl: path includes the app public key", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  assertEquals(
    await cc.discordUrl("APPKEY"),
    `https://cc.me/i/${KNOWN_PUB_B64U}/discord/APPKEY`,
  );
});

Deno.test("discordUrl: requires a discord public key", async () => {
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: () => {} });
  await assertRejects(() => cc.discordUrl(), TypeError, "discordPublicKey is required");
});

// ---------------------------------------------------------------------------
// Constructor guards
// ---------------------------------------------------------------------------

Deno.test("constructor: requires a private key", () => {
  assertThrows(() => new CcMeClient({ fetch: () => {} }), TypeError, "privateKey is required");
});

Deno.test("constructor: requires fetch when none global", () => {
  const saved = globalThis.fetch;
  try {
    globalThis.fetch = undefined;
    assertThrows(() => new CcMeClient({ privateKey: KNOWN_SEED_B64U }), TypeError, "fetch is required");
  } finally {
    globalThis.fetch = saved;
  }
});

// ---------------------------------------------------------------------------
// Sealed-box decryption round-trip
// ---------------------------------------------------------------------------

Deno.test("decrypt: round-trips a full captured request", async () => {
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, {
    count: 1,
    items: [
      sealedDelivery(KNOWN_SEED_BYTES, {
        id: "m_abc",
        method: "POST",
        path: `/i/${KNOWN_PUB_B64U}`,
        query: "a=1&b=2",
        headers: [
          { name: "content-type", value: "application/json" },
          { name: "x-bin", value: new Uint8Array([0, 1, 2, 255]) },
        ],
        body: JSON.stringify({ hello: "world" }),
      }),
    ],
    cursor: "c1",
  });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.peek();
  assertEquals(res.count, 1);
  assertEquals(res.cursor, "c1");
  const req = res.requests[0];
  assertEquals(req.id, "m_abc");
  assertEquals(req.method, "POST");
  assertEquals(req.path, `/i/${KNOWN_PUB_B64U}`);
  assertEquals(req.query, "a=1&b=2");
  assertEquals(req.headers[0].name, "content-type");
  assertEquals(req.headers[0].value, "application/json");
  assertEquals([...req.headers[1].valueBytes], [0, 1, 2, 255]);
  assertEquals(req.text(), JSON.stringify({ hello: "world" }));
  assertEquals(req.json(), { hello: "world" });
});

Deno.test("decrypt: null query stays null", async () => {
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, {
    count: 1,
    items: [sealedDelivery(KNOWN_SEED_BYTES, { id: "m_q", query: null, body: "" })],
    cursor: null,
  });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.peek();
  assertEquals(res.requests[0].query, null);
});

Deno.test("decrypt: empty body produces empty bodyBytes", async () => {
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, {
    count: 1,
    items: [sealedDelivery(KNOWN_SEED_BYTES, { id: "m_e", method: "GET", body: "" })],
    cursor: null,
  });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.peek();
  assertEquals(res.requests[0].bodyBytes.length, 0);
  assertEquals(res.requests[0].text(), "");
});

Deno.test("decrypt: id mismatch between envelope and plaintext throws", async () => {
  const sealed = sealedDelivery(KNOWN_SEED_BYTES, { id: "inner", body: "" });
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, {
    count: 1,
    items: [{ id: "envelope", sealed: sealed.sealed }],
    cursor: null,
  });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await assertRejects(() => cc.peek(), Error, "delivery id mismatch");
});

Deno.test("decrypt: too-short ciphertext throws", async () => {
  const tiny = bytesToB64u(new Uint8Array(10));
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, {
    count: 1,
    items: [{ id: "m_short", sealed: tiny }],
    cursor: null,
  });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await assertRejects(() => cc.peek(), Error, "too short");
});

Deno.test("decrypt: corrupt ciphertext (wrong recipient) fails to decrypt", async () => {
  const otherSeed = new Uint8Array(32).fill(9);
  const sealed = sealForSeed(otherSeed, encoder.encode(JSON.stringify({ id: "x" })));
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, {
    count: 1,
    items: [{ id: "x", sealed }],
    cursor: null,
  });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await assertRejects(() => cc.peek(), Error, "failed to decrypt");
});

Deno.test("decrypt: recipient X25519 public matches ed2curve of identity", () => {
  const x = recipientX25519Public(KNOWN_SEED_BYTES);
  const direct = ed2curve.convertPublicKey(nacl.sign.keyPair.fromSeed(KNOWN_SEED_BYTES).publicKey);
  assertEquals([...x], [...direct]);
});

function sealingFetch(seed, responseBody, status = 200) {
  const calls = [];
  const fetch = (url, init = {}) => {
    calls.push({ url: String(url), init });
    return Promise.resolve(
      new Response(JSON.stringify(responseBody), {
        status,
        headers: { "content-type": "application/json" },
      }),
    );
  };
  return { calls, fetch };
}

// ---------------------------------------------------------------------------
// Client methods over a mock fetch
// ---------------------------------------------------------------------------

Deno.test("peek: decrypt:false returns the raw response", async () => {
  const sealed = sealedDelivery(KNOWN_SEED_BYTES, { id: "m_raw", body: "hi" });
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, { count: 1, items: [sealed], cursor: null });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.peek({ decrypt: false });
  assertEquals(res.requests, undefined);
  assertEquals(res.items[0].id, "m_raw");
  assertEquals(res.items[0].sealed, sealed.sealed);
});

Deno.test("claim: decrypts and reserves deliveries", async () => {
  const sealed = sealedDelivery(KNOWN_SEED_BYTES, { id: "m_c", method: "POST", body: "{}" });
  const { calls, fetch } = sealingFetch(KNOWN_SEED_BYTES, { count: 1, items: [sealed] });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.claim({ limit: 2, poll: true });
  assertEquals(res.requests[0].id, "m_c");
  assertMatch(calls[0].url, /\/claim$/);
  assertEquals(calls[0].init.method, "POST");
});

Deno.test("ack: posts JSON ids body and returns server response", async () => {
  const { calls, fetch } = sealingFetch(KNOWN_SEED_BYTES, { acked: 2, missing: [] });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.ack(["m_1", "m_2"]);
  assertEquals(res, { acked: 2, missing: [] });
  assertEquals(calls[0].init.body, JSON.stringify({ ids: ["m_1", "m_2"] }));
  assertMatch(calls[0].url, /\/ack$/);
});

Deno.test("ack: wraps a single id into an array", async () => {
  const { calls, fetch } = sealingFetch(KNOWN_SEED_BYTES, { acked: 1, missing: [] });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await cc.ack("m_solo");
  assertEquals(calls[0].init.body, JSON.stringify({ ids: ["m_solo"] }));
});

Deno.test("release: posts ids and returns released/missing", async () => {
  const { calls, fetch } = sealingFetch(KNOWN_SEED_BYTES, { released: 1, missing: ["m_x"] });
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  const res = await cc.release("m_y");
  assertEquals(res, { released: 1, missing: ["m_x"] });
  assertMatch(calls[0].url, /\/release$/);
});

Deno.test("methods: non-2xx surfaces the error message", async () => {
  const { fetch } = sealingFetch(KNOWN_SEED_BYTES, { error: "bad signature" }, 401);
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await assertRejects(() => cc.peek(), Error, "bad signature");
});

Deno.test("methods: non-2xx without error body uses status fallback", async () => {
  const calls = [];
  const fetch = (url, init = {}) => {
    calls.push({ url, init });
    return Promise.resolve(new Response("nope", { status: 503 }));
  };
  const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch });
  await assertRejects(() => cc.peek(), Error, "503");
});

// ---------------------------------------------------------------------------
// createAlias
// ---------------------------------------------------------------------------

Deno.test("createAlias: posts {at} and returns {url}", async () => {
  const calls = [];
  const fetch = (url, init = {}) => {
    calls.push({ url: String(url), init });
    return Promise.resolve(
      new Response(JSON.stringify({ url: "https://cc.me/a/xyz" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  };
  const res = await createAlias("https://example.com/x", { fetch });
  assertEquals(res, { url: "https://cc.me/a/xyz" });
  assertEquals(calls[0].url, "https://cc.me/c");
  assertEquals(calls[0].init.method, "POST");
  assertEquals(calls[0].init.body, JSON.stringify({ at: "https://example.com/x" }));
  assertEquals(new Headers(calls[0].init.headers).get("content-type"), "application/json");
});

Deno.test("createAlias: honours baseUrl override", async () => {
  const calls = [];
  const fetch = (url, init = {}) => {
    calls.push({ url: String(url), init });
    return Promise.resolve(
      new Response(JSON.stringify({ url: "u" }), { status: 200, headers: { "content-type": "application/json" } }),
    );
  };
  await createAlias("t", { fetch, baseUrl: "https://relay.test/" });
  assertEquals(calls[0].url, "https://relay.test/c");
});

Deno.test("createAlias: surfaces server error", async () => {
  const fetch = () =>
    Promise.resolve(
      new Response(JSON.stringify({ error: "invalid target" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }),
    );
  await assertRejects(() => createAlias("bad", { fetch }), Error, "invalid target");
});

// ---------------------------------------------------------------------------
// End-to-end against a local node:http server (real fetch path)
// ---------------------------------------------------------------------------

Deno.test("e2e: peek hits a real local server with both auth headers", async () => {
  const sealed = sealedDelivery(KNOWN_SEED_BYTES, { id: "m_live", method: "GET", body: "" });
  const seen = {};
  const server = await startServer((req, res) => {
    seen.method = req.method;
    seen.url = req.url;
    seen.ts = req.headers["x-cc-me-timestamp"];
    seen.sig = req.headers["x-cc-me-signature"];
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ count: 1, items: [sealed], cursor: null }));
  });
  try {
    const cc = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: globalThis.fetch, baseUrl: server.url });
    const res = await cc.peek({ limit: 4 });
    assertEquals(res.requests[0].id, "m_live");
    assertEquals(seen.method, "GET");
    assertEquals(seen.url, `/i/${KNOWN_PUB_B64U}?l=4`);
    assertMatch(seen.ts, /^\d+$/);
    assertMatch(seen.sig, /^[A-Za-z0-9_-]+$/);
  } finally {
    await server.close();
  }
});

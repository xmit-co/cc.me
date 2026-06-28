import { assertEquals, assertMatch } from "jsr:@std/assert";

import {
  UsageError,
  forwardLoop,
  forwardRequest,
  forwardUrl,
  headerList,
  hopByHopHeader,
  parseArgs,
  usage,
} from "./forward.js";
import { readBody, startServer } from "./test_helpers.js";

const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

Deno.test("parseArgs: help is a command", () => {
  assertEquals(parseArgs(["-h"]), { command: "help" });
  assertEquals(parseArgs(["--help"]), { command: "help" });
});

Deno.test("parseArgs: parses forward URL and key", () => {
  const options = parseArgs(["--key", "/tmp/k", "http://localhost:5100/slackorwhatever"]);
  assertEquals(options.command, "forward");
  assertEquals(options.keyFile, "/tmp/k");
  assertEquals(options.target, "http://localhost:5100/slackorwhatever");
});

Deno.test("parseArgs: parses inspect port", () => {
  const options = parseArgs(["inspect", "--port=9999"]);
  assertEquals(options.command, "inspect");
  assertEquals(options.port, 9999);
});

Deno.test("forwardLoop: missing URL is a usage error", async () => {
  let error;
  try {
    await forwardLoop({ keyFile: "/tmp/k" });
  } catch (err) {
    error = err;
  }
  assertEquals(error instanceof UsageError, true);
  assertEquals(error.message, "missing forward URL");
});

Deno.test("usage: includes forward and inspect forms", () => {
  assertMatch(usage(), /cc-me .*<forward-url>/);
  assertMatch(usage(), /cc-me inspect/);
});

// ---------------------------------------------------------------------------
// hop-by-hop header classification
// ---------------------------------------------------------------------------

const HOP_BY_HOP = [
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
];

Deno.test("hopByHopHeader: recognises the full RFC list", () => {
  for (const name of HOP_BY_HOP) {
    assertEquals(hopByHopHeader(name), true, name);
  }
});

Deno.test("hopByHopHeader: is case-insensitive", () => {
  assertEquals(hopByHopHeader("Connection"), true);
  assertEquals(hopByHopHeader("Transfer-Encoding"), true);
  assertEquals(hopByHopHeader("CONTENT-LENGTH"), true);
});

Deno.test("hopByHopHeader: passes through normal headers", () => {
  for (const name of ["content-type", "authorization", "x-custom", "accept", "user-agent"]) {
    assertEquals(hopByHopHeader(name), false, name);
  }
});

// ---------------------------------------------------------------------------
// headerList stripping
// ---------------------------------------------------------------------------

Deno.test("headerList: strips hop-by-hop and keeps the rest in order", () => {
  const headers = [
    { name: "host", value: "cc.me" },
    { name: "content-type", value: "application/json" },
    { name: "connection", value: "keep-alive" },
    { name: "x-custom", value: "v" },
    { name: "transfer-encoding", value: "chunked" },
    { name: "authorization", value: "Bearer t" },
  ];
  assertEquals(headerList(headers), [
    ["content-type", "application/json"],
    ["x-custom", "v"],
    ["authorization", "Bearer t"],
  ]);
});

Deno.test("headerList: empty input yields empty list", () => {
  assertEquals(headerList([]), []);
});

Deno.test("headerList: strips uppercase hop-by-hop names too", () => {
  const out = headerList([
    { name: "Host", value: "x" },
    { name: "Content-Length", value: "5" },
    { name: "X-Keep", value: "yes" },
  ]);
  assertEquals(out, [["X-Keep", "yes"]]);
});

// ---------------------------------------------------------------------------
// forwardUrl query merge
// ---------------------------------------------------------------------------

Deno.test("forwardUrl: no delivery query keeps the base unchanged", () => {
  const url = forwardUrl("http://target.test/path", { query: null });
  assertEquals(url.toString(), "http://target.test/path");
});

Deno.test("forwardUrl: merges delivery query onto a query-less base", () => {
  const url = forwardUrl("http://target.test/path", { query: "a=1&b=2" });
  assertEquals(url.toString(), "http://target.test/path?a=1&b=2");
});

Deno.test("forwardUrl: appends delivery query after an existing base query", () => {
  const url = forwardUrl("http://target.test/path?base=1", { query: "a=2" });
  assertEquals(`${url.pathname}${url.search}`, "/path?base=1&a=2");
});

Deno.test("forwardUrl: empty-string query leaves base untouched", () => {
  const url = forwardUrl("http://target.test/p?x=1", { query: "" });
  assertEquals(url.toString(), "http://target.test/p?x=1");
});

Deno.test("forwardUrl: preserves the path and host", () => {
  const url = forwardUrl("http://target.test:9000/deep/path", { query: "k=v" });
  assertEquals(url.host, "target.test:9000");
  assertEquals(url.pathname, "/deep/path");
  assertEquals(url.searchParams.get("k"), "v");
});

// ---------------------------------------------------------------------------
// forwardRequest against a real local target
// ---------------------------------------------------------------------------

function delivery(overrides = {}) {
  return {
    id: "m_1",
    method: "POST",
    path: "/i/x",
    query: null,
    headers: [],
    bodyBytes: new Uint8Array(),
    text() {
      return new TextDecoder().decode(this.bodyBytes);
    },
    ...overrides,
  };
}

Deno.test("forwardRequest: replays method, merged query, body and headers; strips hop-by-hop", async () => {
  const seen = {};
  const target = await startServer(async (req, res) => {
    seen.method = req.method;
    seen.url = req.url;
    seen.headers = req.headers;
    seen.body = (await readBody(req)).toString("utf8");
    res.writeHead(200);
    res.end("ok");
  });
  try {
    await forwardRequest(new URL(target.url), delivery({
      method: "POST",
      query: "a=1&b=2",
      headers: [
        { name: "content-type", value: "application/json" },
        { name: "host", value: "should-be-stripped" },
        { name: "x-custom", value: "kept" },
        { name: "connection", value: "keep-alive" },
      ],
      bodyBytes: encoder.encode(JSON.stringify({ ok: true })),
    }));
    assertEquals(seen.method, "POST");
    assertEquals(seen.url, "/?a=1&b=2");
    assertEquals(seen.body, JSON.stringify({ ok: true }));
    assertEquals(seen.headers["content-type"], "application/json");
    assertEquals(seen.headers["x-custom"], "kept");
    // host is set by the HTTP client to the target, never the stripped value.
    assertNotEqualsLoose(seen.headers["host"], "should-be-stripped");
  } finally {
    await target.close();
  }
});

function assertNotEqualsLoose(actual, forbidden) {
  if (actual === forbidden) {
    throw new Error(`expected ${actual} not to equal ${forbidden}`);
  }
}

Deno.test("forwardRequest: GET sends no body even if bodyBytes present", async () => {
  const seen = {};
  const target = await startServer(async (req, res) => {
    seen.method = req.method;
    seen.body = (await readBody(req)).toString("utf8");
    res.writeHead(200);
    res.end("ok");
  });
  try {
    await forwardRequest(new URL(target.url), delivery({
      method: "GET",
      bodyBytes: encoder.encode("should not be sent"),
    }));
    assertEquals(seen.method, "GET");
    assertEquals(seen.body, "");
  } finally {
    await target.close();
  }
});

Deno.test("forwardRequest: throws on a non-2xx target response", async () => {
  const target = await startServer((req, res) => {
    res.writeHead(500);
    res.end("boom");
  });
  try {
    let threw = false;
    try {
      await forwardRequest(new URL(target.url), delivery({ method: "GET" }));
    } catch (error) {
      threw = true;
      assertMatch(error.message, /forward failed with 500/);
    }
    assertEquals(threw, true);
  } finally {
    await target.close();
  }
});

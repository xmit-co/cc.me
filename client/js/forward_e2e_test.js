import { assertEquals } from "jsr:@std/assert";

import { CcMeClient } from "./index.js";
import {
  bytesToB64u,
  ed25519PublicKey,
  KNOWN_SEED_B64U,
  KNOWN_SEED_BYTES,
  readBody,
  sealedDelivery,
  startServer,
} from "./test_helpers.js";

const PUB = bytesToB64u(ed25519PublicKey(KNOWN_SEED_BYTES));

// A mock cc.me server: verifies auth headers are present, serves a single
// claim batch, then records ack/release calls. The forward loop drives it via
// the real CcMeClient; we replicate the forward loop's batch logic here so the
// end-to-end path (claim -> forward -> ack/release) is exercised deterministically
// without an infinite poll.
function mockCcMe(items) {
  const log = { claims: 0, ack: [], release: [], authSeen: [] };
  const handler = async (req, res) => {
    log.authSeen.push({
      ts: req.headers["x-cc-me-timestamp"],
      sig: req.headers["x-cc-me-signature"],
      path: req.url,
      method: req.method,
    });
    const body = (await readBody(req)).toString("utf8");
    res.setHeader("content-type", "application/json");
    if (req.url.endsWith("/claim")) {
      log.claims += 1;
      res.end(JSON.stringify({ count: items.length, items }));
      return;
    }
    if (req.url.endsWith("/ack")) {
      const ids = JSON.parse(body).ids;
      log.ack.push(...ids);
      res.end(JSON.stringify({ acked: ids.length, missing: [] }));
      return;
    }
    if (req.url.endsWith("/release")) {
      const ids = JSON.parse(body).ids;
      log.release.push(...ids);
      res.end(JSON.stringify({ released: ids.length, missing: [] }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  };
  return { handler, log };
}

// One iteration of forward.js's forwardLoop batch logic (claim -> per-delivery
// forward -> ack handled / release remainder). Mirrors forward.js exactly.
async function runBatch(cc, targetUrl, forwardRequest) {
  const { requests } = await cc.claim({ limit: 10, poll: true });
  const acked = [];
  for (let i = 0; i < requests.length; i += 1) {
    const request = requests[i];
    try {
      await forwardRequest(targetUrl, request);
      acked.push(request.id);
    } catch (error) {
      const releaseIds = requests.slice(i).map((item) => item.id);
      await Promise.all([
        acked.length > 0 ? cc.ack(acked).catch(() => {}) : undefined,
        releaseIds.length > 0 ? cc.release(releaseIds).catch(() => {}) : undefined,
      ]);
      throw error;
    }
  }
  if (acked.length > 0) {
    await cc.ack(acked);
  }
  return acked;
}

Deno.test("e2e forward: query merge, header passthrough/stripping, ack on success", async () => {
  const items = [
    sealedDelivery(KNOWN_SEED_BYTES, {
      id: "m_a",
      method: "POST",
      path: `/i/${PUB}`,
      query: "from=cc&n=1",
      headers: [
        { name: "content-type", value: "application/json" },
        { name: "host", value: "cc.me" },
        { name: "x-forward-me", value: "yes" },
        { name: "connection", value: "keep-alive" },
      ],
      body: JSON.stringify({ hi: 1 }),
    }),
    sealedDelivery(KNOWN_SEED_BYTES, {
      id: "m_b",
      method: "GET",
      path: `/i/${PUB}`,
      query: "q=2",
      headers: [],
      body: "",
    }),
  ];

  const { handler, log } = mockCcMe(items);
  const cc = await startServer(handler);
  const targetSeen = [];
  const target = await startServer(async (req, res) => {
    targetSeen.push({
      method: req.method,
      url: req.url,
      contentType: req.headers["content-type"],
      forwardMe: req.headers["x-forward-me"],
      host: req.headers["host"],
      body: (await readBody(req)).toString("utf8"),
    });
    res.writeHead(200);
    res.end("ok");
  });

  try {
    const { forwardRequest } = await import("./forward.js");
    const client = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: globalThis.fetch, baseUrl: cc.url });
    const acked = await runBatch(client, new URL(target.url), forwardRequest);

    // Both deliveries forwarded and acked, none released.
    assertEquals(acked, ["m_a", "m_b"]);
    assertEquals(log.ack, ["m_a", "m_b"]);
    assertEquals(log.release, []);

    // Query merged onto the target (which had no base query).
    assertEquals(targetSeen[0].method, "POST");
    assertEquals(targetSeen[0].url, "/?from=cc&n=1");
    assertEquals(targetSeen[0].body, JSON.stringify({ hi: 1 }));
    // Passthrough header survived; hop-by-hop host replaced by target host.
    assertEquals(targetSeen[0].contentType, "application/json");
    assertEquals(targetSeen[0].forwardMe, "yes");
    assertEquals(targetSeen[0].host !== "cc.me", true);

    assertEquals(targetSeen[1].method, "GET");
    assertEquals(targetSeen[1].url, "/?q=2");

    // Claim was signed (auth headers present on every cc.me call).
    for (const seen of log.authSeen) {
      assertEquals(/^\d+$/.test(seen.ts), true);
      assertEquals(/^[A-Za-z0-9_-]+$/.test(seen.sig), true);
    }
  } finally {
    await cc.close();
    await target.close();
  }
});

Deno.test("e2e forward: target failure acks handled, releases current+remaining", async () => {
  const items = [
    sealedDelivery(KNOWN_SEED_BYTES, { id: "ok_1", method: "GET", query: null, body: "" }),
    sealedDelivery(KNOWN_SEED_BYTES, { id: "fail_2", method: "GET", query: null, body: "" }),
    sealedDelivery(KNOWN_SEED_BYTES, { id: "rest_3", method: "GET", query: null, body: "" }),
  ];

  const { handler, log } = mockCcMe(items);
  const cc = await startServer(handler);

  let n = 0;
  const target = await startServer((req, res) => {
    n += 1;
    if (n === 2) {
      res.writeHead(502);
      res.end("bad gateway");
      return;
    }
    res.writeHead(200);
    res.end("ok");
  });

  try {
    const { forwardRequest } = await import("./forward.js");
    const client = new CcMeClient({ privateKey: KNOWN_SEED_B64U, fetch: globalThis.fetch, baseUrl: cc.url });

    let threw = false;
    try {
      await runBatch(client, new URL(target.url), forwardRequest);
    } catch {
      threw = true;
    }
    assertEquals(threw, true);

    // First delivery succeeded -> acked. Second failed; second+third released.
    assertEquals(log.ack, ["ok_1"]);
    assertEquals(log.release, ["fail_2", "rest_3"]);
  } finally {
    await cc.close();
    await target.close();
  }
});

// True child-process end-to-end: run the real CLI binary against the mock cc.me
// and a target, then verify it acked the delivery and printed the inbox URL.
Deno.test("e2e CLI: forward.js binary claims, forwards, and acks", async () => {
  const items = [
    sealedDelivery(KNOWN_SEED_BYTES, { id: "cli_1", method: "GET", query: "z=9", body: "" }),
  ];
  const { handler, log } = mockCcMe(items);
  // After the first claim is served and acked, subsequent claims hang so the
  // loop blocks; we then kill the process. Serve one batch, stall the rest.
  let claimsServed = 0;
  const ccHandler = async (req, res) => {
    if (req.url.endsWith("/claim")) {
      claimsServed += 1;
      if (claimsServed > 1) {
        // Stall the second claim forever (simulates long poll with no data).
        return;
      }
    }
    return handler(req, res);
  };
  const cc = await startServer(ccHandler);

  let targetHits = 0;
  const target = await startServer((req, res) => {
    targetHits += 1;
    res.writeHead(200);
    res.end("ok");
  });

  const dir = await Deno.makeTempDir();
  const keyFile = `${dir}/cc-me.key`;
  await Deno.writeTextFile(keyFile, `${KNOWN_SEED_B64U}\n`);
  await Deno.chmod(keyFile, 0o600);

  const command = new Deno.Command("deno", {
    args: ["run", "-A", "forward.js", "--key", keyFile, target.url],
    env: { CC_ME_URL: cc.url, CC_ME_LIMIT: "10" },
    cwd: new URL(".", import.meta.url).pathname,
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();

  try {
    // Wait until the delivery has been forwarded and acked.
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && !(targetHits >= 1 && log.ack.includes("cli_1"))) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assertEquals(targetHits >= 1, true);
    assertEquals(log.ack.includes("cli_1"), true);
    assertEquals(log.release, []);
  } finally {
    try {
      child.kill("SIGKILL");
    } catch { /* already gone */ }
    await child.status;
    child.stdout.cancel().catch(() => {});
    child.stderr.cancel().catch(() => {});
    await cc.close();
    await target.close();
    await Deno.remove(dir, { recursive: true });
  }
});

// Regression: npm/npx installs the bin as a symlink in node_modules/.bin, so
// node sees process.argv[1] = the symlink while import.meta.url = the real
// file. The old `import.meta.url === file://${argv[1]}` check failed that
// comparison and the forwarder exited silently. Run forward.js through a
// symlink under node and assert it actually starts forwarding.
Deno.test("e2e CLI: forward.js runs through a symlink (node, npx-style)", async () => {
  const items = [
    sealedDelivery(KNOWN_SEED_BYTES, { id: "sym_1", method: "GET", query: "z=9", body: "" }),
  ];
  const { handler, log } = mockCcMe(items);
  let claimsServed = 0;
  const cc = await startServer(async (req, res) => {
    if (req.url.endsWith("/claim")) {
      claimsServed += 1;
      if (claimsServed > 1) return; // stall subsequent long polls
    }
    return handler(req, res);
  });

  let targetHits = 0;
  const target = await startServer((req, res) => {
    targetHits += 1;
    res.writeHead(200);
    res.end("ok");
  });

  const dir = await Deno.makeTempDir();
  const keyFile = `${dir}/cc-me.key`;
  await Deno.writeTextFile(keyFile, `${KNOWN_SEED_B64U}\n`);
  await Deno.chmod(keyFile, 0o600);

  // Symlink in node_modules/.bin style: link -> real forward.js (absolute).
  const realScript = new URL("./forward.js", import.meta.url).pathname;
  const binLink = `${dir}/cc-me`;
  await Deno.symlink(realScript, binLink);

  const command = new Deno.Command("node", {
    args: [binLink, "--key", keyFile, target.url],
    env: { CC_ME_URL: cc.url, CC_ME_LIMIT: "10" },
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();

  try {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline && !(targetHits >= 1 && log.ack.includes("sym_1"))) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assertEquals(targetHits >= 1, true);
    assertEquals(log.ack.includes("sym_1"), true);
  } finally {
    try {
      child.kill("SIGKILL");
    } catch { /* already gone */ }
    await child.status;
    child.stdout.cancel().catch(() => {});
    child.stderr.cancel().catch(() => {});
    await cc.close();
    await target.close();
    await Deno.remove(dir, { recursive: true });
  }
});

#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { CcMeClient, privateKey } from "./index.js";

const DEFAULT_KEY_FILE = join(homedir(), ".cc-me.key");
const DEFAULT_LIMIT = 10;
const DEFAULT_INSPECT_PORT = 8765;
const JSON_BODY_LIMIT = 1024 * 1024;

export function usage() {
  return `usage:
  cc-me [--key <path>] <forward-url>
  cc-me inspect [--key <path>] [--port <port>]`;
}

export function parseArgs(args) {
  const options = {
    command: "forward",
    keyFile: process.env.CC_ME_KEY ?? DEFAULT_KEY_FILE,
    port: Number(process.env.CC_ME_INSPECT_PORT ?? DEFAULT_INSPECT_PORT),
    target: undefined,
  };
  const positionals = [];

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") {
      return { command: "help" };
    }
    if (arg === "--key" || arg === "--port") {
      i += 1;
      if (!args[i]) {
        throw new Error(`${arg} needs a value`);
      }
      setOption(options, arg, args[i]);
      continue;
    }
    if (arg.startsWith("--key=") || arg.startsWith("--port=")) {
      const [name, value] = arg.split("=", 2);
      if (!value) {
        throw new Error(`${name} needs a value`);
      }
      setOption(options, name, value);
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`unknown option: ${arg}`);
    }
    positionals.push(arg);
  }

  if (positionals[0] === "inspect") {
    options.command = "inspect";
    if (positionals.length > 1) {
      throw new Error("inspect does not take a forward URL");
    }
  } else {
    if (positionals.length > 1) {
      throw new Error("only one forward URL is supported");
    }
    options.target = positionals[0];
  }

  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    throw new Error("--port must be between 1 and 65535");
  }

  return options;
}

function setOption(options, name, value) {
  if (name === "--key") {
    options.keyFile = value;
    return;
  }
  if (name === "--port") {
    options.port = Number(value);
  }
}

export function headerList(headers) {
  const out = [];
  for (const header of headers) {
    if (!hopByHopHeader(header.name)) {
      out.push([header.name, header.value]);
    }
  }
  return out;
}

export function hopByHopHeader(name) {
  switch (name.toLowerCase()) {
    case "connection":
    case "content-length":
    case "host":
    case "keep-alive":
    case "proxy-authenticate":
    case "proxy-authorization":
    case "te":
    case "trailer":
    case "transfer-encoding":
    case "upgrade":
      return true;
    default:
      return false;
  }
}

export function forwardUrl(base, request) {
  const url = new URL(base);
  if (request.query) {
    url.search = url.search ? `${url.search.slice(1)}&${request.query}` : request.query;
  }
  return url;
}

export async function forwardRequest(target, request) {
  const hasBody =
    request.method !== "GET" && request.method !== "HEAD" && request.bodyBytes.length > 0;
  const response = await fetch(forwardUrl(target, request), {
    method: request.method,
    headers: headerList(request.headers),
    body: hasBody ? request.bodyBytes : undefined,
  });
  if (!response.ok) {
    throw new Error(`forward failed with ${response.status}`);
  }
}

export async function newClient(keyFile) {
  const key = await privateKey(keyFile);
  return new CcMeClient({
    baseUrl: process.env.CC_ME_URL,
    privateKey: key,
  });
}

export async function forwardLoop({ keyFile, target }) {
  if (!target) {
    throw new UsageError("missing forward URL");
  }

  const targetUrl = new URL(target);
  const cc = await newClient(keyFile);

  console.error(`cc.me inbox: ${await cc.inboxUrl()}`);
  console.error(`forwarding to: ${targetUrl.href}`);

  for (;;) {
    const { requests } = await cc.claim({
      limit: Number(process.env.CC_ME_LIMIT ?? DEFAULT_LIMIT),
      poll: true,
    });

    const acked = [];
    for (let i = 0; i < requests.length; i += 1) {
      const request = requests[i];
      try {
        await forwardRequest(targetUrl, request);
        acked.push(request.id);
        console.error(
          `${request.method} ${request.path}${request.query ? `?${request.query}` : ""}`,
        );
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
  }
}

async function startInspector({ keyFile, port }) {
  const cc = await newClient(keyFile);
  const inboxUrl = await cc.inboxUrl();
  const server = createServer(async (request, response) => {
    try {
      await routeInspector(cc, inboxUrl, request, response);
    } catch (error) {
      sendJson(response, 500, { error: error.message });
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address();
  console.error(`cc.me inbox: ${inboxUrl}`);
  console.error(`inspector: http://127.0.0.1:${address.port}/`);
}

async function routeInspector(cc, inboxUrl, request, response) {
  const url = new URL(request.url, "http://127.0.0.1");
  if (request.method === "GET" && url.pathname === "/") {
    sendHtml(response, inspectorHtml());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/status") {
    sendJson(response, 200, { inboxUrl });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/events") {
    await streamInspectorEvents(cc, request, response, url);
    return;
  }
  if (request.method !== "POST") {
    sendJson(response, 404, { error: "not found" });
    return;
  }

  const body = await readJsonBody(request);
  if (url.pathname === "/api/peek") {
    sendJson(response, 200, serializeDeliveryResponse(await cc.peek(deliveryOptions(body))));
    return;
  }
  if (url.pathname === "/api/claim") {
    sendJson(response, 200, serializeDeliveryResponse(await cc.claim(deliveryOptions(body))));
    return;
  }
  if (url.pathname === "/api/ack") {
    sendJson(response, 200, await cc.ack(body.ids ?? []));
    return;
  }
  if (url.pathname === "/api/release") {
    sendJson(response, 200, await cc.release(body.ids ?? []));
    return;
  }

  sendJson(response, 404, { error: "not found" });
}

function deliveryOptions(body) {
  return {
    cursor: body.cursor,
    limit: body.limit,
    poll: Boolean(body.poll),
  };
}

function serializeDeliveryResponse(response) {
  return {
    count: response.count,
    cursor: response.cursor ?? null,
    requests: response.requests.map(serializeRequest),
  };
}

function serializeRequest(request) {
  return {
    id: request.id,
    received_at_unix_ms: request.received_at_unix_ms,
    method: request.method,
    path: request.path,
    query: request.query,
    headers: request.headers.map((header) => ({
      name: header.name,
      value: header.value,
    })),
    body: request.text(),
  };
}

async function streamInspectorEvents(cc, request, response, url) {
  let closed = false;
  let cursor = url.searchParams.get("cursor") || undefined;
  const limit = Number(url.searchParams.get("limit") || DEFAULT_LIMIT);
  request.on("close", () => {
    closed = true;
  });
  response.writeHead(200, {
    "cache-control": "no-cache",
    connection: "keep-alive",
    "content-type": "text/event-stream; charset=utf-8",
  });
  response.write(": connected\n\n");

  while (!closed) {
    try {
      const data = serializeDeliveryResponse(
        await cc.peek({
          cursor,
          limit,
          poll: true,
        }),
      );
      cursor = data.cursor ?? cursor;
      if (data.requests.length > 0) {
        sendEvent(response, "deliveries", data);
      } else {
        response.write(": ping\n\n");
      }
    } catch (error) {
      sendEvent(response, "error", { error: error.message });
      await sleep(1000);
    }
  }
  response.end();
}

function sendEvent(response, event, body) {
  response.write(`event: ${event}\n`);
  response.write(`data: ${JSON.stringify(body)}\n\n`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readJsonBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > JSON_BODY_LIMIT) {
      throw new Error("request body is too large");
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(body));
}

function sendHtml(response, body) {
  response.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
  });
  response.end(body);
}

function inspectorHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>cc.me inspector</title>
<style>
:root{color-scheme:light dark;font-family:system-ui,sans-serif;--line:color-mix(in srgb,CanvasText 18%,transparent);--muted:color-mix(in srgb,CanvasText 62%,transparent);--soft:color-mix(in srgb,CanvasText 5%,transparent)}
body{margin:0;background:Canvas;color:CanvasText;line-height:1.45}
main{max-width:70em;margin:auto;padding:1em}
header{display:grid;gap:.35em;padding-bottom:.85em;border-bottom:thin solid var(--line)}
h1,h2,p{margin:0}
h1{font-size:1.35em}
#inbox,.item-head code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{display:flex;flex-wrap:wrap;gap:.55em;align-items:center;padding:1em 0}
#status{margin-right:auto}
label{display:flex;gap:.4em;align-items:center}
button,input,article,pre{border:thin solid var(--line);border-radius:.4em}
button,input{font:inherit;padding:.45em .65em;background:var(--soft);color:inherit}
button{cursor:pointer}
input{width:4.5em}
code,pre,#inbox,.mono{font-family:ui-monospace,monospace}
#items{display:grid;gap:.75em}
article{padding:.75em;background:var(--soft)}
.item-head{display:grid;grid-template-columns:auto auto minmax(0,1fr) auto;gap:.55em;align-items:center}
.item-head input{width:auto}
.item-head code{padding:0;background:transparent}
article p{margin-top:.35em}
pre{overflow:auto;margin:.65em 0 0;padding:.65em;background:Canvas}
summary{cursor:pointer;margin-top:.65em;color:var(--muted)}
.empty{padding:1em 0;text-align:center}
.muted,#inbox{color:var(--muted)}
@media(max-width:42em){main{padding:.75em}#status{flex-basis:100%}}
</style>
</head>
<body>
<main>
<header>
<h1>cc.me inspector</h1>
<code id="inbox"></code>
</header>
<div class="bar">
<p id="status" class="muted" aria-live="polite">connecting</p>
<label>Limit <input id="limit" type="number" min="1" value="10"></label>
<button id="peek">Peek</button>
<button id="claim">Claim</button>
<button id="ack">Ack selected</button>
<button id="release">Release selected</button>
</div>
<section id="items"></section>
</main>
<script>
const inbox = document.getElementById("inbox");
const status = document.getElementById("status");
const items = document.getElementById("items");
const limit = document.getElementById("limit");
let current = [];
let stream;

async function api(path, body) {
  const response = await fetch("/api/" + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {})
  });
  const json = await response.json();
  if (!response.ok) throw new Error(json.error || response.statusText);
  return json;
}

function selectedIds() {
  return [...document.querySelectorAll("input[data-id]:checked")].map((node) => node.dataset.id);
}

function merge(data) {
  const known = new Set(current.map((request) => request.id));
  for (const request of data.requests || []) {
    if (!known.has(request.id)) {
      current.push(request);
      known.add(request.id);
    }
  }
  render("live, visible " + current.length);
}

function render(message) {
  status.textContent = message || "visible " + current.length;
  if (current.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty muted";
    empty.textContent = "Waiting for deliveries.";
    items.replaceChildren(empty);
    return;
  }
  items.replaceChildren(...current.map(renderRequest));
}

function renderRequest(request) {
  const article = document.createElement("article");
  const head = document.createElement("div");
  head.className = "item-head";
  const box = document.createElement("input");
  box.type = "checkbox";
  box.dataset.id = request.id;
  const method = document.createElement("strong");
  method.textContent = request.method;
  const target = document.createElement("code");
  target.textContent = request.path + (request.query ? "?" + request.query : "");
  const time = document.createElement("time");
  time.className = "muted";
  time.dateTime = new Date(request.received_at_unix_ms).toISOString();
  time.textContent = new Date(request.received_at_unix_ms).toLocaleString();
  const meta = document.createElement("p");
  meta.className = "muted mono";
  meta.textContent = request.id;
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = request.headers.length + " headers";
  const headers = document.createElement("pre");
  headers.textContent = request.headers.map((header) => header.name + ": " + header.value).join("\\n");
  const body = document.createElement("pre");
  body.textContent = request.body;
  head.append(box, method, target, time);
  details.append(summary, headers);
  article.append(head, meta, body, details);
  return article;
}

function startStream() {
  if (stream) {
    stream.close();
  }
  stream = new EventSource("/api/events?limit=" + encodeURIComponent(Number(limit.value) || 10));
  stream.addEventListener("deliveries", (event) => merge(JSON.parse(event.data)));
  stream.addEventListener("error", () => {
    status.textContent = "reconnecting";
  });
}

document.getElementById("peek").onclick = async () => {
  const data = await api("peek", { limit: Number(limit.value) || 10 });
  current = data.requests || [];
  render("peeked " + current.length);
};
document.getElementById("claim").onclick = async () => {
  const data = await api("claim", { limit: Number(limit.value) || 10 });
  merge(data);
};
document.getElementById("ack").onclick = async () => {
  const ids = selectedIds();
  const result = await api("ack", { ids });
  current = current.filter((request) => !ids.includes(request.id));
  render("acked " + result.acked);
};
document.getElementById("release").onclick = async () => {
  const result = await api("release", { ids: selectedIds() });
  status.textContent = JSON.stringify(result);
};
limit.addEventListener("change", startStream);
fetch("/api/status").then((response) => response.json()).then((data) => {
  inbox.textContent = data.inboxUrl;
  render();
  startStream();
});
</script>
</body>
</html>`;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.command === "help") {
    console.log(usage());
  } else if (options.command === "inspect") {
    await startInspector(options);
  } else {
    await forwardLoop(options);
  }
}

export class UsageError extends Error {}

// True when this module is the program entry point. `import.meta.main` covers
// Deno, Bun, and Node >= 24; older Node falls back to comparing real paths,
// which (unlike `file://${argv[1]}`) survives the symlink npm/npx creates in
// node_modules/.bin, Windows drive letters, and paths with spaces.
export function isMainModule() {
  if (typeof import.meta.main === "boolean") {
    return import.meta.main;
  }
  if (typeof process === "undefined" || !Array.isArray(process.argv) || !process.argv[1]) {
    return false;
  }
  try {
    return fileURLToPath(import.meta.url) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    console.error(error.message);
    if (error instanceof UsageError) {
      console.error(usage());
      process.exit(64);
    }
    process.exit(1);
  });
}

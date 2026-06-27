import blake from "blakejs";
import ed2curve from "ed2curve";
import nacl from "tweetnacl";

const DEFAULT_BASE_URL = "https://cc.me/";
const SEALED_BOX_PUBLIC_KEY_BYTES = 32;
const SEALED_BOX_NONCE_BYTES = 24;
const AUTH_VERSION = "cc-me-v1";
const AUTH_TIMESTAMP_HEADER = "x-cc-me-timestamp";
const AUTH_SIGNATURE_HEADER = "x-cc-me-signature";

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");

  if (globalThis.Buffer) {
    return new Uint8Array(globalThis.Buffer.from(padded, "base64"));
  }

  const binary = globalThis.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  if (globalThis.Buffer) {
    return globalThis.Buffer.from(bytes).toString("base64url");
  }

  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return globalThis.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Base64Url(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToBase64Url(new Uint8Array(digest));
}

async function signRequest(privateKey, method, url, body = "") {
  const timestamp = Math.floor(Date.now() / 1000);
  const bodyBytes = typeof body === "string" ? encoder.encode(body) : body;
  const bodyHash = await sha256Base64Url(bodyBytes);
  const path = `${url.pathname}${url.search}`;
  const message = encoder.encode(
    `${AUTH_VERSION}\n${method}\n${path}\n${timestamp}\n${bodyHash}`,
  );
  const secretKey = nacl.sign.keyPair.fromSeed(privateKeyBytes(privateKey)).secretKey;
  const signature = nacl.sign.detached(message, secretKey);
  return {
    [AUTH_TIMESTAMP_HEADER]: String(timestamp),
    [AUTH_SIGNATURE_HEADER]: bytesToBase64Url(signature),
  };
}

export async function privateKey(file) {
  if (!file) {
    return generatePrivateKey();
  }

  assertFileRuntime();
  try {
    const key = validatePrivateKey((await readTextFile(file)).trim());
    await securePrivateKeyFile(file);
    return key;
  } catch (error) {
    if (!isNotFound(error)) {
      throw error;
    }
  }

  const key = generatePrivateKey();
  await writeTextFile(file, `${key}\n`);
  await securePrivateKeyFile(file);
  return key;
}

function generatePrivateKey() {
  return bytesToBase64Url(nacl.sign.keyPair().secretKey.subarray(0, 32));
}

function publicKey(privateKey) {
  return nacl.sign.keyPair.fromSeed(privateKeyBytes(privateKey)).publicKey;
}

function x25519PublicKey(privateKey) {
  return ed2curve.convertPublicKey(publicKey(privateKey));
}

function x25519SecretKey(privateKey) {
  return ed2curve.convertSecretKey(privateKeyBytes(privateKey));
}

export function trampolineUrl(target, options = {}) {
  const url = new URL("/", options.baseUrl ?? DEFAULT_BASE_URL);
  url.searchParams.set("at", String(target));
  appendParams(url, options.params);
  return url.toString();
}

export async function createAlias(target, options = {}) {
  const fetchFn = options.fetch ?? globalThis.fetch;
  if (!fetchFn) {
    throw new TypeError("fetch is required in this runtime");
  }
  const response = await fetchFn(new URL("/c", options.baseUrl ?? DEFAULT_BASE_URL), {
    method: "POST",
    headers: jsonHeaders(options.headers),
    body: JSON.stringify({ at: String(target) }),
    signal: options.signal,
  });
  return parseJsonResponse(response);
}

function publicInboxUrl(publicKey, options = {}) {
  const url = new URL(
    `/i/${encodeURIComponent(keyToString(publicKey))}`,
    options.baseUrl ?? DEFAULT_BASE_URL,
  );
  appendParams(url, {
    l: options.limit,
    c: options.cursor,
  });
  if (options.poll) {
    url.searchParams.set("p", "");
  }
  return url.toString();
}

function publicWebmentionUrl(publicKey, options = {}) {
  return publicProtocolUrl(publicKey, "webmention", options);
}

function publicWebsubUrl(publicKey, options = {}) {
  return publicProtocolUrl(publicKey, "websub", options);
}

function publicSlackUrl(publicKey, options = {}) {
  return publicProtocolUrl(publicKey, "slack", options);
}

function publicPingbackUrl(publicKey, options = {}) {
  return publicProtocolUrl(publicKey, "pingback", options);
}

function publicMetaUrl(publicKey, verifyToken, options = {}) {
  const url = new URL(publicProtocolUrl(publicKey, "meta", options));
  if (verifyToken !== undefined && verifyToken !== null) {
    url.searchParams.set("v", String(verifyToken));
  }
  return url.toString();
}

function publicCloudEventsUrl(publicKey, options = {}) {
  return publicProtocolUrl(publicKey, "cloudevents", options);
}

function publicDiscordUrl(publicKey, discordPublicKey, options = {}) {
  return new URL(
    `/i/${encodeURIComponent(keyToString(publicKey))}/discord/${encodeURIComponent(String(discordPublicKey))}`,
    options.baseUrl ?? DEFAULT_BASE_URL,
  ).toString();
}

function publicProtocolUrl(publicKey, protocol, options = {}) {
  return new URL(
    `/i/${encodeURIComponent(keyToString(publicKey))}/${protocol}`,
    options.baseUrl ?? DEFAULT_BASE_URL,
  ).toString();
}

function decryptEnvelope(envelope, privateKey) {
  const request = decryptItem(envelope.sealed, privateKey);
  if (request.id !== envelope.id) {
    throw new Error("delivery id mismatch");
  }
  return request;
}

function decryptItem(ciphertext, privateKey) {
  const sealed = keyToBytes(ciphertext);
  if (sealed.length < SEALED_BOX_PUBLIC_KEY_BYTES + nacl.box.overheadLength) {
    throw new Error("encrypted delivery is too short");
  }

  const recipientSecretKey = x25519SecretKey(privateKey);
  const recipientPublicKey = x25519PublicKey(privateKey);
  const ephemeralPublicKey = sealed.subarray(0, SEALED_BOX_PUBLIC_KEY_BYTES);
  const box = sealed.subarray(SEALED_BOX_PUBLIC_KEY_BYTES);
  const plaintext = nacl.box.open(
    box,
    sealedBoxNonce(ephemeralPublicKey, recipientPublicKey),
    ephemeralPublicKey,
    recipientSecretKey,
  );
  if (!plaintext) {
    throw new Error("failed to decrypt delivery");
  }
  return decodeCapturedRequest(plaintext);
}

function sealedBoxNonce(ephemeralPublicKey, recipientPublicKey) {
  return blake.blake2b(
    concatBytes(ephemeralPublicKey, recipientPublicKey),
    null,
    SEALED_BOX_NONCE_BYTES,
  );
}

function concatBytes(left, right) {
  const bytes = new Uint8Array(left.length + right.length);
  bytes.set(left);
  bytes.set(right, left.length);
  return bytes;
}

function decodeCapturedRequest(plaintext) {
  const parsed = JSON.parse(decoder.decode(plaintext));
  const bodyBytes = base64UrlToBytes(parsed.body_b64u);
  const headers = parsed.headers.map((header) => {
    const valueBytes = base64UrlToBytes(header.value_b64u);
    return {
      name: header.name,
      valueBytes,
      value: decoder.decode(valueBytes),
    };
  });

  return {
    id: parsed.id,
    received_at_unix_ms: parsed.received_at_unix_ms,
    method: parsed.method,
    path: parsed.path,
    query: parsed.query ?? null,
    headers,
    bodyBytes,
    text() {
      return decoder.decode(bodyBytes);
    },
    json() {
      return JSON.parse(decoder.decode(bodyBytes));
    },
  };
}

export class CcMeClient {
  #baseUrl;
  #fetch;
  #privateKey;
  #publicKey;

  constructor(options = {}) {
    this.#baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#privateKey = options.privateKey;

    if (!this.#privateKey) {
      throw new TypeError("privateKey is required");
    }
    if (!this.#fetch) {
      throw new TypeError("fetch is required in this runtime");
    }
  }

  #publicKeyForInbox() {
    if (!this.#publicKey) {
      this.#publicKey = publicKey(this.#privateKey);
    }
    return this.#publicKey;
  }

  async inboxUrl(options = {}) {
    return publicInboxUrl(this.#publicKeyForInbox(), { ...options, baseUrl: this.#baseUrl });
  }

  async webmentionUrl() {
    return publicWebmentionUrl(this.#publicKeyForInbox(), { baseUrl: this.#baseUrl });
  }

  async websubUrl() {
    return publicWebsubUrl(this.#publicKeyForInbox(), { baseUrl: this.#baseUrl });
  }

  async slackUrl() {
    return publicSlackUrl(this.#publicKeyForInbox(), { baseUrl: this.#baseUrl });
  }

  async pingbackUrl() {
    return publicPingbackUrl(this.#publicKeyForInbox(), { baseUrl: this.#baseUrl });
  }

  async metaUrl(verifyToken) {
    return publicMetaUrl(this.#publicKeyForInbox(), verifyToken, { baseUrl: this.#baseUrl });
  }

  async cloudEventsUrl() {
    return publicCloudEventsUrl(this.#publicKeyForInbox(), { baseUrl: this.#baseUrl });
  }

  async discordUrl(discordPublicKey) {
    if (!discordPublicKey) {
      throw new TypeError("discordPublicKey is required");
    }
    return publicDiscordUrl(this.#publicKeyForInbox(), discordPublicKey, {
      baseUrl: this.#baseUrl,
    });
  }

  async peek(options = {}) {
    const url = await this.inboxUrl({
      limit: options.limit,
      poll: options.poll,
      cursor: options.cursor,
    });
    return this.#readDeliveries(url, options);
  }

  async claim(options = {}) {
    const body = JSON.stringify({
      limit: options.limit,
      poll: options.poll,
    });
    const url = new URL(await this.#actionUrl("claim"));
    const response = await this.#fetch(url.toString(), {
      method: "POST",
      headers: await signedJsonHeaders(this.#privateKey, "POST", url, body, options.headers),
      body,
      signal: options.signal,
    });
    const responseBody = await parseJsonResponse(response);
    return decryptResponse(responseBody, this.#privateKey, options);
  }

  async ack(idOrIds, options = {}) {
    const body = await this.#postIds("ack", idOrIds, options);
    return body;
  }

  async release(idOrIds, options = {}) {
    const body = await this.#postIds("release", idOrIds, options);
    return body;
  }

  async #readDeliveries(url, options) {
    const requestUrl = new URL(url);
    const response = await this.#fetch(requestUrl.toString(), {
      method: "GET",
      headers: await signedHeaders(this.#privateKey, "GET", requestUrl, "", options.headers),
      signal: options.signal,
    });
    const body = await parseJsonResponse(response);
    return decryptResponse(body, this.#privateKey, options);
  }

  async #postIds(action, idOrIds, options) {
    const body = JSON.stringify({ ids: toIds(idOrIds) });
    const url = new URL(await this.#actionUrl(action));
    const response = await this.#fetch(url.toString(), {
      method: "POST",
      headers: await signedJsonHeaders(this.#privateKey, "POST", url, body, options.headers),
      body,
      signal: options.signal,
    });
    return parseJsonResponse(response);
  }

  async #actionUrl(action) {
    const url = await this.inboxUrl();
    return new URL(`${url.replace(/\/$/, "")}/${action}`).toString();
  }
}

function decryptResponse(body, privateKey, options) {
  if (options.decrypt === false) {
    return body;
  }
  return {
    ...body,
    requests: body.items.map((item) => decryptEnvelope(item, privateKey)),
  };
}

async function parseJsonResponse(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error ?? `cc.me request failed with ${response.status}`);
  }
  return body;
}

function appendParams(url, params) {
  if (!params) {
    return;
  }

  const entries = params instanceof URLSearchParams ? params.entries() : Object.entries(params);
  for (const [key, value] of entries) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }
}

function jsonHeaders(headers) {
  const out = new Headers(headers);
  if (!out.has("content-type")) {
    out.set("content-type", "application/json");
  }
  return out;
}

async function signedHeaders(privateKey, method, url, body, extraHeaders) {
  const out = new Headers(extraHeaders);
  const auth = await signRequest(privateKey, method, url, body);
  out.set(AUTH_TIMESTAMP_HEADER, auth[AUTH_TIMESTAMP_HEADER]);
  out.set(AUTH_SIGNATURE_HEADER, auth[AUTH_SIGNATURE_HEADER]);
  return out;
}

async function signedJsonHeaders(privateKey, method, url, body, extraHeaders) {
  const out = jsonHeaders(extraHeaders);
  const auth = await signRequest(privateKey, method, url, body);
  out.set(AUTH_TIMESTAMP_HEADER, auth[AUTH_TIMESTAMP_HEADER]);
  out.set(AUTH_SIGNATURE_HEADER, auth[AUTH_SIGNATURE_HEADER]);
  return out;
}

function toIds(idOrIds) {
  return Array.isArray(idOrIds) ? idOrIds : [idOrIds];
}

function keyToBytes(value) {
  if (typeof value === "string") {
    return base64UrlToBytes(value);
  }
  return value;
}

function keyToString(value) {
  if (typeof value === "string") {
    return value;
  }
  return bytesToBase64Url(value);
}

function validatePrivateKey(value) {
  privateKeyBytes(value);
  return value;
}

function privateKeyBytes(value) {
  const bytes = keyToBytes(value);
  if (bytes.length !== 32) {
    throw new TypeError("privateKey must be 32 bytes of base64url");
  }
  return bytes;
}

function assertFileRuntime() {
  if (
    !globalThis.Deno?.readTextFile &&
    !globalThis.Bun?.file &&
    !globalThis.process?.versions?.node
  ) {
    throw new Error("privateKey(path) requires Node.js, Bun, or Deno");
  }
}

async function readTextFile(file) {
  if (globalThis.Deno?.readTextFile) {
    return globalThis.Deno.readTextFile(file);
  }
  if (globalThis.Bun?.file) {
    const bunFile = globalThis.Bun.file(file);
    if (await bunFile.exists()) {
      return bunFile.text();
    }
    const error = new Error("file not found");
    error.code = "ENOENT";
    throw error;
  }

  const fs = await import("node:fs/promises");
  return fs.readFile(file, "utf8");
}

async function writeTextFile(file, contents) {
  if (globalThis.Deno?.writeTextFile) {
    await globalThis.Deno.writeTextFile(file, contents, { createNew: true, mode: 0o600 });
    return;
  }

  const fs = await import("node:fs/promises");
  await fs.writeFile(file, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
}

async function securePrivateKeyFile(file) {
  if (isWindows()) {
    return;
  }
  if (globalThis.Deno?.chmod) {
    await globalThis.Deno.chmod(file, 0o600);
    return;
  }

  const fs = await import("node:fs/promises");
  await fs.chmod(file, 0o600);
}

function isWindows() {
  return globalThis.Deno?.build?.os === "windows" || globalThis.process?.platform === "win32";
}

function isNotFound(error) {
  return error?.code === "ENOENT" || error?.name === "NotFound";
}

export default CcMeClient;

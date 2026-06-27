// Shared test helpers: mirror the server-side crypto_box_seal so tests can
// produce sealed deliveries the client must decrypt.
import nacl from "tweetnacl";
import ed2curve from "ed2curve";
import blake from "blakejs";

const encoder = new TextEncoder();

export function bytesToB64u(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function b64uToBytes(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

export function concatBytes(left, right) {
  const out = new Uint8Array(left.length + right.length);
  out.set(left);
  out.set(right, left.length);
  return out;
}

// A fixed, known 32-byte seed used across deterministic tests.
export const KNOWN_SEED_BYTES = new Uint8Array(32);
for (let i = 0; i < 32; i += 1) {
  KNOWN_SEED_BYTES[i] = i + 1;
}
export const KNOWN_SEED_B64U = bytesToB64u(KNOWN_SEED_BYTES);

export function ed25519PublicKey(seed) {
  return nacl.sign.keyPair.fromSeed(seed).publicKey;
}

export function recipientX25519Public(seed) {
  return ed2curve.convertPublicKey(ed25519PublicKey(seed));
}

// Build the libsodium-style sealed box nonce: BLAKE2b(eph || recipientPub, 24).
function sealedNonce(ephemeralPub, recipientPub) {
  return blake.blake2b(concatBytes(ephemeralPub, recipientPub), null, 24);
}

// Seal `plaintextBytes` to the recipient identified by the Ed25519 seed,
// returning the base64url-no-pad sealed value the server would emit.
export function sealForSeed(seed, plaintextBytes) {
  const recipientPub = recipientX25519Public(seed);
  const eph = nacl.box.keyPair();
  const nonce = sealedNonce(eph.publicKey, recipientPub);
  const box = nacl.box(plaintextBytes, nonce, recipientPub, eph.secretKey);
  return bytesToB64u(concatBytes(eph.publicKey, box));
}

// Build a captured-request plaintext JSON (server wire shape) and seal it.
export function sealedDelivery(seed, request) {
  const headers = (request.headers ?? []).map((h) => ({
    name: h.name,
    value_b64u: bytesToB64u(
      typeof h.value === "string" ? encoder.encode(h.value) : h.value,
    ),
  }));
  const bodyBytes =
    typeof request.body === "string" ? encoder.encode(request.body) : (request.body ?? new Uint8Array());
  const payload = {
    id: request.id,
    received_at_unix_ms: request.received_at_unix_ms ?? 1781337600000,
    method: request.method ?? "POST",
    path: request.path ?? "/i/test",
    query: request.query ?? null,
    headers,
    body_b64u: bytesToB64u(bodyBytes),
  };
  const sealed = sealForSeed(seed, encoder.encode(JSON.stringify(payload)));
  return { id: request.id, sealed };
}

// Stand up a minimal in-process HTTP server. `handler(req,res)` is node:http.
export async function startServer(handler) {
  const { createServer } = await import("node:http");
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    port,
    url: `http://127.0.0.1:${port}/`,
    origin: `http://127.0.0.1:${port}`,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

export function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

#!/usr/bin/env node
// cc.me proof of work — CPU solver, verifier, and benchmark for V8.
//
//   node pow.mjs solve <level> [doc] [--threads N]   doc from argument or stdin
//   node pow.mjs verify <token>
//   node pow.mjs bench [seconds] [--threads N]
//
// Token: b64u(doc) "." b64u(suffix). A token reaches level L when
// SHA-256(SHA-256(doc) || suffix), read as a big-endian 256-bit integer,
// ends in at least L zero bits. See https://cc.me/pow.

import { createHash, randomBytes } from "node:crypto";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { availableParallelism } from "node:os";
import process from "node:process";

const K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

// Miner over the fixed 40-byte message SHA-256(doc) || suffix, which pads to a
// single SHA-256 block. The suffix is the 8-byte big-endian counter hi:lo, so
// W[8] = hi and W[9] = lo directly.
function makeMiner(prefixWords, level) {
  const W = new Int32Array(64);
  for (let i = 0; i < 8; i++) W[i] = prefixWords[i];
  W[10] = 0x80000000 | 0;
  W[15] = 320; // bit length of the 40-byte message
  const maskLo = level >= 32 ? -1 : (1 << level) - 1;
  const maskHi = level <= 32 ? 0 : level >= 64 ? -1 : (1 << (level - 32)) - 1;
  // Runs `count` attempts starting at counter hi:lo; returns the winning
  // counter plus the number of attempts spent, or null.
  return function run(hi, lo, count) {
    for (let i = 0; i < count; i++) {
      W[8] = hi;
      W[9] = lo;
      for (let t = 16; t < 64; t++) {
        const x = W[t - 15];
        const y = W[t - 2];
        const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) | 0;
        const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) | 0;
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
      }
      let a = 0x6a09e667 | 0, b = 0xbb67ae85 | 0, c = 0x3c6ef372 | 0, d = 0xa54ff53a | 0;
      let e = 0x510e527f | 0, f = 0x9b05688c | 0, g = 0x1f83d9ab | 0, h = 0x5be0cd19 | 0;
      for (let t = 0; t < 64; t++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      const d7 = (0x5be0cd19 + h) | 0;
      if ((d7 & maskLo) === 0) {
        const d6 = (0x1f83d9ab + g) | 0;
        if (maskHi === 0 || (d6 & maskHi) === 0) {
          return { hi: hi >>> 0, lo: lo >>> 0, attempts: i + 1 };
        }
      }
      lo = (lo + 1) | 0;
      if (lo === 0) hi = (hi + 1) | 0;
    }
    return null;
  };
}

const sha256 = (bytes) => new Uint8Array(createHash("sha256").update(bytes).digest());

function prefixWordsOf(doc) {
  const inner = sha256(doc);
  const view = new DataView(inner.buffer);
  const words = new Int32Array(8);
  for (let i = 0; i < 8; i++) words[i] = view.getInt32(i * 4);
  return words;
}

function trailingZeroBits(digest) {
  let n = 0;
  for (let i = 31; i >= 0; i--) {
    const b = digest[i];
    if (b === 0) {
      n += 8;
      continue;
    }
    n += 31 - Math.clz32(b & -b);
    break;
  }
  return n;
}

const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

function unb64u(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("invalid base64url");
  const bytes = Buffer.from(text, "base64url");
  if (b64u(bytes) !== text) throw new Error("invalid base64url");
  return new Uint8Array(bytes);
}

function suffixBytes(hi, lo) {
  return Uint8Array.from(
    [hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo],
    (v) => v & 0xff,
  );
}

function tokenLevel(doc, suffix) {
  const check = createHash("sha256").update(sha256(doc)).update(suffix).digest();
  return trailingZeroBits(new Uint8Array(check));
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", (c) => chunks.push(c));
    process.stdin.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    process.stdin.on("error", reject);
  });
}

function parseArgs(argv) {
  const rest = [];
  let threads;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--threads") {
      threads = Number(argv[++i]);
      if (!Number.isInteger(threads) || threads < 1) fail("--threads takes a positive integer");
    } else {
      rest.push(argv[i]);
    }
  }
  return { rest, threads };
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

// ---- worker ----------------------------------------------------------------

if (!isMainThread) {
  const { prefixWords, level, startHi, startLo, durationMs, stop } = workerData;
  const stopFlag = new Int32Array(stop);
  const run = makeMiner(prefixWords, level);
  const CHUNK = 1 << 20;
  let hi = startHi | 0;
  let lo = startLo | 0;
  const t0 = performance.now();
  const deadline = durationMs ? t0 + durationMs : 0;
  while (Atomics.load(stopFlag, 0) === 0) {
    const found = run(hi, lo, CHUNK);
    if (found) {
      parentPort.postMessage({ found: [found.hi, found.lo], n: found.attempts });
      break;
    }
    parentPort.postMessage({ n: CHUNK });
    if (deadline && performance.now() >= deadline) break;
    // Advance the 64-bit counter by CHUNK.
    const next = (lo >>> 0) + CHUNK;
    lo = next | 0;
    if (next > 0xffffffff) hi = (hi + 1) | 0;
  }
  parentPort.postMessage({ dt: (performance.now() - t0) / 1000 });
}

// ---- main ------------------------------------------------------------------

function spawnMiners({ prefixWords, level, threads, seconds, onDone }) {
  const workers = [];
  const stop = new SharedArrayBuffer(4);
  const stopFlag = new Int32Array(stop);
  let attempts = 0;
  let exited = 0;
  let winner = null;
  let elapsed = 0;
  const started = performance.now();
  const status = setInterval(() => {
    const dt = (performance.now() - started) / 1000;
    process.stderr.write(`\r${attempts.toLocaleString("en-US")} hashes, ${(attempts / dt / 1e6).toFixed(2)} MH/s`);
  }, 1000);
  for (let i = 0; i < threads; i++) {
    const start = randomBytes(8);
    const worker = new Worker(new URL(import.meta.url), {
      workerData: {
        prefixWords,
        level,
        startHi: start.readInt32BE(0),
        startLo: start.readInt32BE(4),
        durationMs: seconds ? seconds * 1000 : 0,
        stop,
      },
    });
    worker.on("message", (m) => {
      if (m.n) attempts += m.n;
      if (m.dt) elapsed = Math.max(elapsed, m.dt);
      if (m.found && !winner) {
        winner = m.found;
        elapsed = (performance.now() - started) / 1000;
        Atomics.store(stopFlag, 0, 1);
      }
    });
    worker.on("error", (err) => fail(String(err)));
    worker.on("exit", () => {
      if (++exited < threads) return;
      clearInterval(status);
      process.stderr.write("\n");
      onDone({ attempts, seconds: elapsed || (performance.now() - started) / 1000, found: winner });
    });
    workers.push(worker);
  }
}

// Workers fall through to here after mining (and Bun even inherits argv), so
// gate the CLI dispatch on being the main thread.
const { rest, threads } = isMainThread ? parseArgs(process.argv.slice(2)) : { rest: [] };
const command = rest[0];

if (!isMainThread) {
  // nothing more to do off the main thread
} else if (command === "solve") {
  const level = Number(rest[1]);
  if (!Number.isInteger(level) || level < 1 || level > 64) fail("level must be an integer in 1..64");
  const doc = rest[2] !== undefined ? new TextEncoder().encode(rest[2]) : await readStdin();
  spawnMiners({
    prefixWords: prefixWordsOf(doc),
    level,
    threads: threads ?? availableParallelism(),
    onDone: ({ attempts, seconds, found }) => {
      const suffix = suffixBytes(found[0], found[1]);
      const achieved = tokenLevel(doc, suffix);
      if (achieved < level) fail(`internal error: solved level ${achieved} < ${level}`);
      console.error(
        `level ${achieved} in ${attempts.toLocaleString("en-US")} hashes, ` +
          `${seconds.toFixed(2)}s, ${(attempts / seconds / 1e6).toFixed(2)} MH/s`,
      );
      console.log(`${b64u(doc)}.${b64u(suffix)}`);
      process.exit(0);
    },
  });
} else if (command === "verify") {
  const token = rest[1] ?? fail("usage: pow.mjs verify <token>");
  const dot = token.indexOf(".");
  if (dot < 0) fail("token must be b64u(doc).b64u(suffix)");
  let doc, suffix;
  try {
    doc = unb64u(token.slice(0, dot));
    suffix = unb64u(token.slice(dot + 1));
  } catch (err) {
    fail(String(err.message ?? err));
  }
  if (suffix.length > 32) fail("suffix longer than 32 bytes");
  console.log(`level ${tokenLevel(doc, suffix)}`);
  console.log(`doc (${doc.length} bytes): ${new TextDecoder().decode(doc)}`);
} else if (command === "bench") {
  const seconds = rest[1] !== undefined ? Number(rest[1]) : 5;
  if (!(seconds > 0)) fail("seconds must be positive");
  const nThreads = threads ?? 1;
  spawnMiners({
    prefixWords: prefixWordsOf(new TextEncoder().encode("bench")),
    level: 64, // realistic two-word check that never triggers
    threads: nThreads,
    seconds,
    onDone: ({ attempts, seconds }) => {
      console.log(
        `${attempts.toLocaleString("en-US")} hashes in ${seconds.toFixed(2)}s on ` +
          `${nThreads} thread(s): ${(attempts / seconds / 1e6).toFixed(2)} MH/s`,
      );
      process.exit(0);
    },
  });
} else {
  fail("usage: pow.mjs solve <level> [doc] [--threads N] | verify <token> | bench [seconds] [--threads N]");
}

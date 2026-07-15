// cc.me proof of work — browser solver and verifier, shared by /pow and /shot.
// Token: b64u(doc) "." b64u(suffix); level = trailing zero bits of
// SHA-256(SHA-256(doc) || suffix) as a big-endian 256-bit integer.
"use strict";

const ccmePow = (() => {
  // Pure-JS miner shared with pow/pow.mjs: hashes the fixed 40-byte message
  // SHA-256(doc) || suffix (a single SHA-256 block), suffix being the 8-byte
  // big-endian counter hi:lo.
  const MINER_SOURCE = String.raw`
    "use strict";
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
    onmessage = (event) => {
      const { prefixWords, level, startHi, startLo } = event.data;
      const W = new Int32Array(64);
      for (let i = 0; i < 8; i++) W[i] = prefixWords[i];
      W[10] = 0x80000000 | 0;
      W[15] = 320; // bit length of the 40-byte message
      const maskLo = level >= 32 ? -1 : (1 << level) - 1;
      const maskHi = level <= 32 ? 0 : level >= 64 ? -1 : (1 << (level - 32)) - 1;
      const CHUNK = 1 << 20;
      let hi = startHi | 0;
      let lo = startLo | 0;
      for (;;) {
        for (let i = 0; i < CHUNK; i++) {
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
              postMessage({ found: [hi >>> 0, lo >>> 0], n: i + 1 });
              return;
            }
          }
          lo = (lo + 1) | 0;
          if (lo === 0) hi = (hi + 1) | 0;
        }
        postMessage({ n: CHUNK });
      }
    };
  `;
  const minerUrl = URL.createObjectURL(new Blob([MINER_SOURCE], { type: "text/javascript" }));

  function b64u(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }

  function unb64u(text) {
    if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
      throw new Error("not unpadded base64url");
    }
    const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    if (b64u(bytes) !== text) throw new Error("not canonical base64url");
    return bytes;
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

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  async function checkDigest(doc, suffix) {
    const inner = await sha256(doc);
    const message = new Uint8Array(32 + suffix.length);
    message.set(inner);
    message.set(suffix, 32);
    return sha256(message);
  }

  // Mines a suffix for `doc` (Uint8Array) reaching `level`, across `threads`
  // Web Workers. Returns { promise, stop }; the promise resolves to
  // { suffix, token, attempts, seconds } and rejects on stop().
  function solve(doc, level, threads, onProgress) {
    const workers = [];
    let interval = 0;
    const stopAll = () => {
      clearInterval(interval);
      for (const worker of workers) worker.terminate();
    };
    let stop = stopAll;
    const promise = (async () => {
      const inner = await sha256(doc);
      const view = new DataView(inner.buffer);
      const prefixWords = new Int32Array(8);
      for (let i = 0; i < 8; i++) prefixWords[i] = view.getInt32(i * 4);
      return new Promise((resolve, reject) => {
        stop = () => {
          stopAll();
          reject(new Error("stopped"));
        };
        const started = performance.now();
        let attempts = 0;
        if (onProgress) {
          interval = setInterval(
            () => onProgress(attempts, (performance.now() - started) / 1000),
            250,
          );
        }
        for (let i = 0; i < threads; i++) {
          const start = new Int32Array(2);
          crypto.getRandomValues(start);
          const worker = new Worker(minerUrl);
          worker.onmessage = (event) => {
            const m = event.data;
            attempts += m.n;
            if (!m.found) return;
            const seconds = (performance.now() - started) / 1000;
            stopAll();
            const [hi, lo] = m.found;
            const suffix = Uint8Array.from(
              [hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo],
              (v) => v & 0xff,
            );
            resolve({ suffix, token: `${b64u(doc)}.${b64u(suffix)}`, attempts, seconds });
          };
          worker.postMessage({ prefixWords, level, startHi: start[0], startLo: start[1] });
          workers.push(worker);
        }
      });
    })();
    return { promise, stop: () => stop() };
  }

  return { b64u, unb64u, trailingZeroBits, sha256, checkDigest, solve };
})();

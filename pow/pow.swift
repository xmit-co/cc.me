// cc.me proof of work — GPU solver, verifier, and benchmark (Metal).
//
//   swiftc -O pow.swift -o pow
//   ./pow solve <level> [doc]     doc from argument or stdin
//   ./pow verify <token>
//   ./pow bench [seconds]
//
// Token: b64u(doc) "." b64u(suffix). A token reaches level L when
// SHA-256(SHA-256(doc) || suffix), read as a big-endian 256-bit integer,
// ends in at least L zero bits. See https://cc.me/pow.

import CryptoKit
import Foundation
import Metal

let kernelSource = """
#include <metal_stdlib>
using namespace metal;

constant uint K[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

struct Params {
  uint h[8];     // SHA-256(doc), big-endian words
  uint level;    // required trailing zero bits, 1..64
  uint nonceHi;  // starting 64-bit counter, split
  uint nonceLo;
};

static inline uint rotr(uint x, uint n) { return (x >> n) | (x << (32u - n)); }

// One thread hashes the 40-byte message SHA-256(doc) || suffix, where the
// suffix is the 8-byte big-endian counter base + tid. The message pads to a
// single SHA-256 block: W[8] = counter hi, W[9] = counter lo.
kernel void mine(constant Params &p [[buffer(0)]],
                 device atomic_uint *found [[buffer(1)]],
                 device uint *out [[buffer(2)]],
                 uint tid [[thread_position_in_grid]]) {
  uint lo = p.nonceLo + tid;
  uint hi = p.nonceHi + (lo < p.nonceLo ? 1u : 0u);

  uint W[64];
  for (int i = 0; i < 8; i++) W[i] = p.h[i];
  W[8] = hi;
  W[9] = lo;
  W[10] = 0x80000000u;
  W[11] = 0u; W[12] = 0u; W[13] = 0u; W[14] = 0u;
  W[15] = 320u;  // bit length of the 40-byte message
  for (int t = 16; t < 64; t++) {
    uint x = W[t - 15], y = W[t - 2];
    uint s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    uint s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
    W[t] = W[t - 16] + s0 + W[t - 7] + s1;
  }

  uint a = 0x6a09e667u, b = 0xbb67ae85u, c = 0x3c6ef372u, d = 0xa54ff53au;
  uint e = 0x510e527fu, f = 0x9b05688cu, g = 0x1f83d9abu, h = 0x5be0cd19u;
  for (int t = 0; t < 64; t++) {
    uint S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint t1 = h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t];
    uint S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  // Low 64 bits of the big-endian digest are its last two words.
  ulong low = (ulong(0x1f83d9abu + g) << 32) | ulong(0x5be0cd19u + h);
  ulong mask = p.level >= 64u ? ~0ul : ((1ul << ulong(p.level)) - 1ul);
  if ((low & mask) == 0ul) {
    if (atomic_fetch_or_explicit(found, 1u, memory_order_relaxed) == 0u) {
      out[0] = hi;
      out[1] = lo;
    }
  }
}
"""

func fail(_ message: String) -> Never {
  FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
  exit(1)
}

func b64u(_ data: Data) -> String {
  data.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
}

func unb64u(_ text: String) -> Data? {
  guard text.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
  else { return nil }
  var b64 = text
    .replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  let rem = b64.count % 4
  if rem == 1 { return nil }
  if rem > 0 { b64 += String(repeating: "=", count: 4 - rem) }
  return Data(base64Encoded: b64)
}

func trailingZeroBits(_ digest: [UInt8]) -> Int {
  var n = 0
  for byte in digest.reversed() {
    if byte == 0 {
      n += 8
      continue
    }
    n += byte.trailingZeroBitCount
    break
  }
  return n
}

func tokenLevel(doc: Data, suffix: Data) -> Int {
  let inner = Data(SHA256.hash(data: doc))
  return trailingZeroBits(Array(SHA256.hash(data: inner + suffix)))
}

func readDoc(_ arg: String?) -> Data {
  if let arg { return Data(arg.utf8) }
  return FileHandle.standardInput.readDataToEndOfFile()
}

struct Miner {
  let device: MTLDevice
  let queue: MTLCommandQueue
  let pipeline: MTLComputePipelineState
  let foundBuffer: MTLBuffer
  let outBuffer: MTLBuffer

  init() {
    guard let device = MTLCreateSystemDefaultDevice(),
      let queue = device.makeCommandQueue()
    else { fail("no Metal device") }
    let library: MTLLibrary
    do {
      library = try device.makeLibrary(source: kernelSource, options: nil)
    } catch { fail("kernel compilation failed: \(error)") }
    guard let function = library.makeFunction(name: "mine"),
      let pipeline = try? device.makeComputePipelineState(function: function),
      let foundBuffer = device.makeBuffer(length: 4, options: .storageModeShared),
      let outBuffer = device.makeBuffer(length: 8, options: .storageModeShared)
    else { fail("Metal setup failed") }
    self.device = device
    self.queue = queue
    self.pipeline = pipeline
    self.foundBuffer = foundBuffer
    self.outBuffer = outBuffer
  }

  // Dispatches `batch` hash attempts starting at counter `base`; returns the
  // winning counter if any thread reached the level.
  func dispatch(prefixWords: [UInt32], level: UInt32, base: UInt64, batch: Int) -> UInt64? {
    foundBuffer.contents().storeBytes(of: UInt32(0), as: UInt32.self)
    var params = [UInt32](repeating: 0, count: 12)
    for i in 0..<8 { params[i] = prefixWords[i] }
    params[8] = level
    params[9] = UInt32(truncatingIfNeeded: base >> 32)
    params[10] = UInt32(truncatingIfNeeded: base)
    guard let commands = queue.makeCommandBuffer(),
      let encoder = commands.makeComputeCommandEncoder()
    else { fail("command encoding failed") }
    encoder.setComputePipelineState(pipeline)
    encoder.setBytes(&params, length: params.count * 4, index: 0)
    encoder.setBuffer(foundBuffer, offset: 0, index: 1)
    encoder.setBuffer(outBuffer, offset: 0, index: 2)
    let group = MTLSize(width: min(256, pipeline.maxTotalThreadsPerThreadgroup), height: 1, depth: 1)
    encoder.dispatchThreads(MTLSize(width: batch, height: 1, depth: 1), threadsPerThreadgroup: group)
    encoder.endEncoding()
    commands.commit()
    commands.waitUntilCompleted()
    if foundBuffer.contents().load(as: UInt32.self) != 0 {
      let hi = outBuffer.contents().load(fromByteOffset: 0, as: UInt32.self)
      let lo = outBuffer.contents().load(fromByteOffset: 4, as: UInt32.self)
      return UInt64(hi) << 32 | UInt64(lo)
    }
    return nil
  }
}

func prefixWordsOf(_ doc: Data) -> [UInt32] {
  let inner = Array(SHA256.hash(data: doc))
  var words = [UInt32](repeating: 0, count: 8)
  for i in 0..<8 {
    var word: UInt32 = UInt32(inner[i * 4]) << 24
    word |= UInt32(inner[i * 4 + 1]) << 16
    word |= UInt32(inner[i * 4 + 2]) << 8
    word |= UInt32(inner[i * 4 + 3])
    words[i] = word
  }
  return words
}

func suffixBytes(_ counter: UInt64) -> Data {
  Data((0..<8).map { UInt8(truncatingIfNeeded: counter >> ((7 - $0) * 8)) })
}

let batch = 1 << 25

func status(_ line: String) {
  FileHandle.standardError.write(("\r" + line).data(using: .utf8)!)
}

let arguments = CommandLine.arguments
switch arguments.count > 1 ? arguments[1] : "" {
case "solve":
  guard arguments.count >= 3, let level = UInt32(arguments[2]), (1...64).contains(level)
  else { fail("usage: pow solve <level 1..64> [doc]") }
  let doc = readDoc(arguments.count > 3 ? arguments[3] : nil)
  let prefixWords = prefixWordsOf(doc)
  let miner = Miner()
  var base = UInt64.random(in: .min ... .max)
  var attempts: UInt64 = 0
  let started = Date()
  var lastStatus = started
  while true {
    if let counter = miner.dispatch(prefixWords: prefixWords, level: level, base: base, batch: batch) {
      // The winner is one of this dispatch's threads, not necessarily the first.
      attempts += counter &- base &+ 1
      let seconds = -started.timeIntervalSinceNow
      let suffix = suffixBytes(counter)
      let achieved = tokenLevel(doc: doc, suffix: suffix)
      guard achieved >= Int(level) else { fail("internal error: solved level \(achieved) < \(level)") }
      status("level \(achieved) in \(attempts) hashes, "
        + String(format: "%.2fs, %.0f MH/s\n", seconds, Double(attempts) / seconds / 1e6))
      print("\(b64u(doc)).\(b64u(suffix))")
      exit(0)
    }
    attempts += UInt64(batch)
    base &+= UInt64(batch)
    if -lastStatus.timeIntervalSinceNow > 1 {
      lastStatus = Date()
      status("\(attempts) hashes, "
        + String(format: "%.0f MH/s", Double(attempts) / -started.timeIntervalSinceNow / 1e6))
    }
  }

case "verify":
  guard arguments.count >= 3 else { fail("usage: pow verify <token>") }
  let token = arguments[2]
  guard let dot = token.firstIndex(of: "."),
    let doc = unb64u(String(token[..<dot])),
    let suffix = unb64u(String(token[token.index(after: dot)...]))
  else { fail("token must be b64u(doc).b64u(suffix)") }
  guard suffix.count <= 32 else { fail("suffix longer than 32 bytes") }
  print("level \(tokenLevel(doc: doc, suffix: suffix))")
  print("doc (\(doc.count) bytes): \(String(decoding: doc, as: UTF8.self))")

case "bench":
  let seconds = arguments.count > 2 ? Double(arguments[2]) ?? 5 : 5
  guard seconds > 0 else { fail("seconds must be positive") }
  let miner = Miner()
  let prefixWords = prefixWordsOf(Data("bench".utf8))
  // Warm up the pipeline before timing.
  _ = miner.dispatch(prefixWords: prefixWords, level: 64, base: 0, batch: batch)
  var attempts: UInt64 = 0
  let started = Date()
  var base = UInt64.random(in: .min ... .max)
  while -started.timeIntervalSinceNow < seconds {
    _ = miner.dispatch(prefixWords: prefixWords, level: 64, base: base, batch: batch)
    attempts += UInt64(batch)
    base &+= UInt64(batch)
  }
  let elapsed = -started.timeIntervalSinceNow
  print("\(attempts) hashes in " + String(format: "%.2f", elapsed) + "s: "
    + String(format: "%.0f", Double(attempts) / elapsed / 1e6) + " MH/s")

default:
  fail("usage: pow solve <level> [doc] | verify <token> | bench [seconds]")
}

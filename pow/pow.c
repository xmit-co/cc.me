/* cc.me proof of work — GPU solver, verifier, and benchmark (OpenCL).
 *
 * Runs on NVIDIA and AMD GPUs on Linux (and Apple's legacy OpenCL on macOS):
 *   Linux:  cc -O2 pow.c -lOpenCL -o pow-cl
 *   macOS:  cc -O2 pow.c -framework OpenCL -o pow-cl
 *
 *   ./pow-cl solve <level> [doc] [--device N]   doc from argument or stdin
 *   ./pow-cl verify <token>
 *   ./pow-cl bench [seconds] [--device N]
 *   ./pow-cl devices
 *
 * Token: b64u(doc) "." b64u(suffix). A token reaches level L when
 * SHA-256(SHA-256(doc) || suffix), read as a big-endian 256-bit integer,
 * ends in at least L zero bits. See https://cc.me/pow.
 */

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#define CL_TARGET_OPENCL_VERSION 200
#include <CL/cl.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- SHA-256 (host side, for the doc digest and verification) ---------- */

static const uint32_t K256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t state[8], const uint8_t block[64]) {
  uint32_t W[64];
  for (int t = 0; t < 16; t++) {
    W[t] = (uint32_t)block[t * 4] << 24 | (uint32_t)block[t * 4 + 1] << 16 |
           (uint32_t)block[t * 4 + 2] << 8 | (uint32_t)block[t * 4 + 3];
  }
  for (int t = 16; t < 64; t++) {
    uint32_t s0 = ROTR(W[t - 15], 7) ^ ROTR(W[t - 15], 18) ^ (W[t - 15] >> 3);
    uint32_t s1 = ROTR(W[t - 2], 17) ^ ROTR(W[t - 2], 19) ^ (W[t - 2] >> 10);
    W[t] = W[t - 16] + s0 + W[t - 7] + s1;
  }
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
  for (int t = 0; t < 64; t++) {
    uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
    uint32_t t1 = h + S1 + ((e & f) ^ (~e & g)) + K256[t] + W[t];
    uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
    uint32_t t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  size_t i = 0;
  for (; i + 64 <= len; i += 64) sha256_block(state, data + i);
  uint8_t block[64] = {0};
  size_t rem = len - i;
  memcpy(block, data + i, rem);
  block[rem] = 0x80;
  if (rem >= 56) {
    sha256_block(state, block);
    memset(block, 0, 64);
  }
  uint64_t bits = (uint64_t)len * 8;
  for (int j = 0; j < 8; j++) block[63 - j] = (uint8_t)(bits >> (j * 8));
  sha256_block(state, block);
  for (int j = 0; j < 8; j++) {
    out[j * 4] = (uint8_t)(state[j] >> 24);
    out[j * 4 + 1] = (uint8_t)(state[j] >> 16);
    out[j * 4 + 2] = (uint8_t)(state[j] >> 8);
    out[j * 4 + 3] = (uint8_t)state[j];
  }
}

/* ---- base64url (unpadded, canonical) ------------------------------------ */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64u_encode(const uint8_t *data, size_t len) {
  char *out = malloc((len + 2) / 3 * 4 + 1);
  if (!out) return NULL;
  char *p = out;
  size_t i = 0;
  for (; i + 3 <= len; i += 3) {
    uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8 | data[i + 2];
    *p++ = B64[v >> 18]; *p++ = B64[(v >> 12) & 63]; *p++ = B64[(v >> 6) & 63]; *p++ = B64[v & 63];
  }
  if (len - i == 1) {
    uint32_t v = (uint32_t)data[i] << 16;
    *p++ = B64[v >> 18]; *p++ = B64[(v >> 12) & 63];
  } else if (len - i == 2) {
    uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8;
    *p++ = B64[v >> 18]; *p++ = B64[(v >> 12) & 63]; *p++ = B64[(v >> 6) & 63];
  }
  *p = 0;
  return out;
}

/* Returns 0 on success; rejects padded, non-alphabet, and non-canonical input. */
static int b64u_decode(const char *text, size_t textlen, uint8_t **out, size_t *outlen) {
  int8_t rev[256];
  memset(rev, -1, sizeof rev);
  for (int i = 0; i < 64; i++) rev[(uint8_t)B64[i]] = (int8_t)i;
  if (textlen % 4 == 1) return -1;
  uint8_t *bytes = malloc(textlen * 3 / 4 + 1);
  if (!bytes) return -1;
  size_t n = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < textlen; i++) {
    int8_t v = rev[(uint8_t)text[i]];
    if (v < 0) { free(bytes); return -1; }
    acc = acc << 6 | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[n++] = (uint8_t)(acc >> bits);
    }
  }
  if (acc & ((1u << bits) - 1)) { free(bytes); return -1; } /* non-canonical tail */
  *out = bytes;
  *outlen = n;
  return 0;
}

/* ---- token helpers ------------------------------------------------------ */

static int trailing_zero_bits(const uint8_t digest[32]) {
  int n = 0;
  for (int i = 31; i >= 0; i--) {
    if (digest[i] == 0) {
      n += 8;
      continue;
    }
    uint8_t b = digest[i];
    while (!(b & 1)) {
      n++;
      b >>= 1;
    }
    break;
  }
  return n;
}

static int token_level(const uint8_t *doc, size_t doclen, const uint8_t *suffix, size_t suffixlen) {
  uint8_t message[32 + 32];
  sha256(doc, doclen, message);
  memcpy(message + 32, suffix, suffixlen);
  uint8_t check[32];
  sha256(message, 32 + suffixlen, check);
  return trailing_zero_bits(check);
}

/* ---- OpenCL kernel ------------------------------------------------------ */

/* One thread hashes the 40-byte message SHA-256(doc) || suffix, where the
 * suffix is the 8-byte big-endian counter base + tid. The message pads to a
 * single SHA-256 block: W[8] = counter hi, W[9] = counter lo.
 * p = { h[0..7], level, nonceHi, nonceLo }. */
static const char *KERNEL_SRC =
  "__constant uint K[64] = {\n"
  "  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,\n"
  "  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,\n"
  "  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,\n"
  "  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,\n"
  "  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,\n"
  "  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,\n"
  "  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,\n"
  "  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,\n"
  "};\n"
  "static inline uint rotr(uint x, uint n) { return (x >> n) | (x << (32u - n)); }\n"
  "__kernel void mine(__constant uint *p,\n"
  "                   __global volatile uint *found,\n"
  "                   __global uint *out) {\n"
  "  uint tid = (uint)get_global_id(0);\n"
  "  uint lo = p[10] + tid;\n"
  "  uint hi = p[9] + (lo < p[10] ? 1u : 0u);\n"
  "  uint W[64];\n"
  "  for (int i = 0; i < 8; i++) W[i] = p[i];\n"
  "  W[8] = hi;\n"
  "  W[9] = lo;\n"
  "  W[10] = 0x80000000u;\n"
  "  W[11] = 0u; W[12] = 0u; W[13] = 0u; W[14] = 0u;\n"
  "  W[15] = 320u;\n"
  "  for (int t = 16; t < 64; t++) {\n"
  "    uint x = W[t - 15], y = W[t - 2];\n"
  "    uint s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);\n"
  "    uint s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);\n"
  "    W[t] = W[t - 16] + s0 + W[t - 7] + s1;\n"
  "  }\n"
  "  uint a = 0x6a09e667u, b = 0xbb67ae85u, c = 0x3c6ef372u, d = 0xa54ff53au;\n"
  "  uint e = 0x510e527fu, f = 0x9b05688cu, g = 0x1f83d9abu, h = 0x5be0cd19u;\n"
  "  for (int t = 0; t < 64; t++) {\n"
  "    uint S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);\n"
  "    uint t1 = h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t];\n"
  "    uint S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);\n"
  "    uint t2 = S0 + ((a & b) ^ (a & c) ^ (b & c));\n"
  "    h = g; g = f; f = e; e = d + t1;\n"
  "    d = c; c = b; b = a; a = t1 + t2;\n"
  "  }\n"
  "  ulong low = ((ulong)(0x1f83d9abu + g) << 32) | (ulong)(0x5be0cd19u + h);\n"
  "  ulong mask = p[8] >= 64u ? ~0UL : ((1UL << (ulong)p[8]) - 1UL);\n"
  "  if ((low & mask) == 0UL) {\n"
  "    if (atomic_or(found, 1u) == 0u) {\n"
  "      out[0] = hi;\n"
  "      out[1] = lo;\n"
  "    }\n"
  "  }\n"
  "}\n";

/* ---- OpenCL host --------------------------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#endif
static void fail(const char *message) {
  fprintf(stderr, "%s\n", message);
  exit(1);
}

static void check_cl(cl_int err, const char *what) {
  if (err != CL_SUCCESS) {
    fprintf(stderr, "%s failed: OpenCL error %d\n", what, err);
    exit(1);
  }
}

typedef struct {
  cl_platform_id platform;
  cl_device_id device;
} DeviceRef;

static int list_devices(DeviceRef *refs, int max) {
  cl_platform_id platforms[16];
  cl_uint nplatforms = 0;
  if (clGetPlatformIDs(16, platforms, &nplatforms) != CL_SUCCESS) return 0;
  int n = 0;
  /* GPUs across all platforms first, then everything else as a fallback. */
  for (int pass = 0; pass < 2 && n == 0; pass++) {
    cl_device_type type = pass == 0 ? CL_DEVICE_TYPE_GPU : CL_DEVICE_TYPE_ALL;
    for (cl_uint i = 0; i < nplatforms && n < max; i++) {
      cl_device_id devices[16];
      cl_uint ndevices = 0;
      if (clGetDeviceIDs(platforms[i], type, 16, devices, &ndevices) != CL_SUCCESS) continue;
      for (cl_uint j = 0; j < ndevices && n < max; j++) {
        refs[n].platform = platforms[i];
        refs[n].device = devices[j];
        n++;
      }
    }
  }
  return n;
}

static void device_name(cl_device_id device, char *name, size_t size) {
  if (clGetDeviceInfo(device, CL_DEVICE_NAME, size, name, NULL) != CL_SUCCESS) {
    snprintf(name, size, "(unknown)");
  }
}

typedef struct {
  cl_context context;
  cl_command_queue queue;
  cl_kernel kernel;
  cl_mem params;
  cl_mem found;
  cl_mem out;
} Miner;

static Miner miner_new(int device_index) {
  DeviceRef refs[64];
  int n = list_devices(refs, 64);
  if (n == 0) fail("no OpenCL devices");
  if (device_index < 0 || device_index >= n) fail("no such device; run `pow-cl devices`");
  cl_device_id device = refs[device_index].device;
  char name[256];
  device_name(device, name, sizeof name);
  fprintf(stderr, "device: %s\n", name);

  cl_int err;
  Miner m;
  m.context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
  check_cl(err, "clCreateContext");
#ifdef __APPLE__
  m.queue = clCreateCommandQueue(m.context, device, 0, &err);
#else
  m.queue = clCreateCommandQueueWithProperties(m.context, device, NULL, &err);
#endif
  check_cl(err, "clCreateCommandQueue");
  cl_program program = clCreateProgramWithSource(m.context, 1, &KERNEL_SRC, NULL, &err);
  check_cl(err, "clCreateProgramWithSource");
  err = clBuildProgram(program, 1, &device, "", NULL, NULL);
  if (err != CL_SUCCESS) {
    char log[8192] = "";
    clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, sizeof log - 1, log, NULL);
    fprintf(stderr, "kernel compilation failed:\n%s\n", log);
    exit(1);
  }
  m.kernel = clCreateKernel(program, "mine", &err);
  check_cl(err, "clCreateKernel");
  m.params = clCreateBuffer(m.context, CL_MEM_READ_ONLY, 11 * 4, NULL, &err);
  check_cl(err, "clCreateBuffer params");
  m.found = clCreateBuffer(m.context, CL_MEM_READ_WRITE, 4, NULL, &err);
  check_cl(err, "clCreateBuffer found");
  m.out = clCreateBuffer(m.context, CL_MEM_WRITE_ONLY, 8, NULL, &err);
  check_cl(err, "clCreateBuffer out");
  clSetKernelArg(m.kernel, 0, sizeof(cl_mem), &m.params);
  clSetKernelArg(m.kernel, 1, sizeof(cl_mem), &m.found);
  clSetKernelArg(m.kernel, 2, sizeof(cl_mem), &m.out);
  return m;
}

/* Dispatches `batch` hash attempts starting at counter `base`; returns 1 and
 * stores the winning counter if any thread reached the level. */
static int miner_dispatch(Miner *m, const uint32_t prefix_words[8], uint32_t level,
                          uint64_t base, size_t batch, uint64_t *counter) {
  uint32_t params[11];
  memcpy(params, prefix_words, 8 * 4);
  params[8] = level;
  params[9] = (uint32_t)(base >> 32);
  params[10] = (uint32_t)base;
  uint32_t zero = 0;
  check_cl(clEnqueueWriteBuffer(m->queue, m->params, CL_FALSE, 0, sizeof params, params, 0, NULL, NULL),
           "clEnqueueWriteBuffer params");
  check_cl(clEnqueueWriteBuffer(m->queue, m->found, CL_FALSE, 0, 4, &zero, 0, NULL, NULL),
           "clEnqueueWriteBuffer found");
  check_cl(clEnqueueNDRangeKernel(m->queue, m->kernel, 1, NULL, &batch, NULL, 0, NULL, NULL),
           "clEnqueueNDRangeKernel");
  uint32_t found = 0;
  check_cl(clEnqueueReadBuffer(m->queue, m->found, CL_TRUE, 0, 4, &found, 0, NULL, NULL),
           "clEnqueueReadBuffer found");
  if (!found) return 0;
  uint32_t out[2];
  check_cl(clEnqueueReadBuffer(m->queue, m->out, CL_TRUE, 0, 8, out, 0, NULL, NULL),
           "clEnqueueReadBuffer out");
  *counter = (uint64_t)out[0] << 32 | out[1];
  return 1;
}

/* ---- CLI ----------------------------------------------------------------- */

static double now_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint64_t random_base(void) {
  uint64_t v = 0;
  FILE *urandom = fopen("/dev/urandom", "rb");
  if (urandom) {
    if (fread(&v, sizeof v, 1, urandom) != 1) v = 0;
    fclose(urandom);
  }
  if (v == 0) v = (uint64_t)time(NULL) * 2654435761u;
  return v;
}

static uint8_t *read_doc(const char *arg, size_t *len) {
  if (arg) {
    *len = strlen(arg);
    uint8_t *doc = malloc(*len ? *len : 1);
    memcpy(doc, arg, *len);
    return doc;
  }
  size_t cap = 1 << 16, n = 0;
  uint8_t *doc = malloc(cap);
  size_t got;
  while ((got = fread(doc + n, 1, cap - n, stdin)) > 0) {
    n += got;
    if (n == cap) doc = realloc(doc, cap *= 2);
  }
  *len = n;
  return doc;
}

static void prefix_words_of(const uint8_t *doc, size_t doclen, uint32_t words[8]) {
  uint8_t inner[32];
  sha256(doc, doclen, inner);
  for (int i = 0; i < 8; i++) {
    words[i] = (uint32_t)inner[i * 4] << 24 | (uint32_t)inner[i * 4 + 1] << 16 |
               (uint32_t)inner[i * 4 + 2] << 8 | (uint32_t)inner[i * 4 + 3];
  }
}

#define BATCH ((size_t)1 << 25)

int main(int argc, char **argv) {
  const char *rest[4] = {NULL, NULL, NULL, NULL};
  int nrest = 0;
  int device_index = 0;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
      device_index = atoi(argv[++i]);
    } else if (nrest < 4) {
      rest[nrest++] = argv[i];
    }
  }
  const char *command = rest[0] ? rest[0] : "";

  if (strcmp(command, "devices") == 0) {
    DeviceRef refs[64];
    int n = list_devices(refs, 64);
    for (int i = 0; i < n; i++) {
      char name[256];
      device_name(refs[i].device, name, sizeof name);
      printf("%d: %s\n", i, name);
    }
    if (n == 0) fail("no OpenCL devices");
    return 0;
  }

  if (strcmp(command, "solve") == 0) {
    int level = rest[1] ? atoi(rest[1]) : 0;
    if (level < 1 || level > 64) fail("usage: pow-cl solve <level 1..64> [doc]");
    size_t doclen;
    uint8_t *doc = read_doc(rest[2], &doclen);
    uint32_t prefix_words[8];
    prefix_words_of(doc, doclen, prefix_words);
    Miner m = miner_new(device_index);
    uint64_t base = random_base();
    uint64_t attempts = 0;
    uint64_t counter = 0;
    double started = now_seconds();
    double last_status = started;
    for (;;) {
      if (miner_dispatch(&m, prefix_words, (uint32_t)level, base, BATCH, &counter)) {
        attempts += counter - base + 1;
        break;
      }
      attempts += BATCH;
      base += BATCH;
      double now = now_seconds();
      if (now - last_status > 1) {
        last_status = now;
        fprintf(stderr, "\r%llu hashes, %.0f MH/s", (unsigned long long)attempts,
                (double)attempts / (now - started) / 1e6);
      }
    }
    double seconds = now_seconds() - started;
    uint8_t suffix[8];
    for (int i = 0; i < 8; i++) suffix[i] = (uint8_t)(counter >> ((7 - i) * 8));
    int achieved = token_level(doc, doclen, suffix, 8);
    if (achieved < level) fail("internal error: solved level below target");
    fprintf(stderr, "\rlevel %d in %llu hashes, %.2fs, %.0f MH/s\n", achieved,
            (unsigned long long)attempts, seconds, (double)attempts / seconds / 1e6);
    char *doc64 = b64u_encode(doc, doclen);
    char *suffix64 = b64u_encode(suffix, 8);
    printf("%s.%s\n", doc64, suffix64);
    return 0;
  }

  if (strcmp(command, "verify") == 0) {
    if (!rest[1]) fail("usage: pow-cl verify <token>");
    const char *token = rest[1];
    const char *dot = strchr(token, '.');
    if (!dot) fail("token must be b64u(doc).b64u(suffix)");
    uint8_t *doc, *suffix;
    size_t doclen, suffixlen;
    if (b64u_decode(token, (size_t)(dot - token), &doc, &doclen) != 0 ||
        b64u_decode(dot + 1, strlen(dot + 1), &suffix, &suffixlen) != 0) {
      fail("segments must be canonical unpadded base64url");
    }
    if (suffixlen > 32) fail("suffix longer than 32 bytes");
    printf("level %d\n", token_level(doc, doclen, suffix, suffixlen));
    printf("doc (%zu bytes): %.*s\n", doclen, (int)doclen, doc);
    return 0;
  }

  if (strcmp(command, "bench") == 0) {
    double seconds = rest[1] ? atof(rest[1]) : 5;
    if (seconds <= 0) fail("seconds must be positive");
    Miner m = miner_new(device_index);
    uint8_t doc[] = "bench";
    uint32_t prefix_words[8];
    prefix_words_of(doc, 5, prefix_words);
    uint64_t counter;
    /* Warm up the pipeline before timing; level 64 never fires. */
    miner_dispatch(&m, prefix_words, 64, 0, BATCH, &counter);
    uint64_t attempts = 0;
    uint64_t base = random_base();
    double started = now_seconds();
    while (now_seconds() - started < seconds) {
      miner_dispatch(&m, prefix_words, 64, base, BATCH, &counter);
      attempts += BATCH;
      base += BATCH;
    }
    double elapsed = now_seconds() - started;
    printf("%llu hashes in %.2fs: %.0f MH/s\n", (unsigned long long)attempts, elapsed,
           (double)attempts / elapsed / 1e6);
    return 0;
  }

  fail("usage: pow-cl solve <level> [doc] [--device N] | verify <token> | bench [seconds] [--device N] | devices");
}

# Proof-of-work solvers

Reference solvers for the token format specified at [cc.me/pow](https://cc.me/pow):
`b64u(doc).b64u(suffix)`, where the level is the number of trailing zero bits of
`SHA-256(SHA-256(doc) || suffix)` read as a big-endian 256-bit integer.

Both solvers pick 8-byte suffixes by walking a randomly seeded 64-bit big-endian
counter, so the hot loop hashes a fixed 40-byte message — a single SHA-256 block.

## `pow.mjs` — CPU (V8)

Pure-JavaScript SHA-256, the same miner the `/pow` page runs in Web Workers.
Solving fans out over `worker_threads`.

```sh
node pow.mjs solve 24 'hello world'      # all cores; --threads N to limit
node pow.mjs verify aGVsbG8gd29ybGQ.XBCKI7lQ3i4
node pow.mjs bench 10 [--threads N]
```

## `pow.swift` — GPU (Metal, macOS)

A Metal compute kernel; each GPU thread hashes one candidate suffix. Compile
with the system toolchain (the repo's Nix devshell pins an SDK that the system
Swift refuses; `env -u SDKROOT -u DEVELOPER_DIR` sidesteps it):

```sh
env -u SDKROOT -u DEVELOPER_DIR /usr/bin/swiftc -O pow.swift -o pow
./pow solve 36 'hello world'
./pow verify aGVsbG8gd29ybGQ.XBCKI7lQ3i4
./pow bench 10
```

## `pow.c` — GPU (OpenCL: NVIDIA, AMD, and others)

The same kernel as OpenCL C, for Linux boxes with NVIDIA (their driver ships
OpenCL) or AMD GPUs (ROCm, or Mesa's rusticl). The repo devshell carries
`opencl-headers` and `ocl-icd` on Linux; it also runs on macOS's legacy OpenCL,
where it matches the Metal kernel's throughput.

```sh
cc -O2 pow.c -lOpenCL -o pow-cl                    # Linux
env -u SDKROOT -u DEVELOPER_DIR /usr/bin/cc -O2 pow.c -framework OpenCL -o pow-cl  # macOS
./pow-cl devices                                   # list GPUs; pick with --device N
./pow-cl solve 36 'hello world'
./pow-cl bench 10
```

## Building

`./configure && ninja` builds everything the platform supports: `pow-cl`
everywhere, plus the Metal `pow` on macOS (configure bakes in the
`SDKROOT`/`DEVELOPER_DIR` workaround). The devshell carries ninja; on Linux,
`nix build .#pow-cl` packages the OpenCL solver the same way.

## Benchmark

Apple M5 Pro (18 CPU cores, 20-core GPU), macOS 26, Node 24.15 (V8 13.x),
Swift 6.3, 10-second runs, level-64 target (the check never fires):

| Solver                  | Rate       | vs 1 V8 thread |
| ----------------------- | ---------- | -------------: |
| V8, 1 thread            | 5.4 MH/s   |             1× |
| V8, 18 worker threads   | 72 MH/s    |            13× |
| Metal, 20-core GPU      | 2,033 MH/s |           377× |
| OpenCL, same GPU        | 2,031 MH/s |           376× |

At these rates a level-32 token (4.3 G expected hashes) costs ~13 minutes of
single-threaded JavaScript, ~1 minute across all cores, or ~2 seconds on the
GPU; each step of 10 levels is a ~1,000× cost multiplier.

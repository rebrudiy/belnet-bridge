# Native ARM64 BelNet testnet build

Completed an **unmodified-source** BelNet 0.9.8 daemon for Linux ARM64. This is a
`TESTNET=ON` private-lab build, not the official release build or a mainnet binary.
The baseline below has no source patch. A separate queue-fix variant is documented
at the end. No existing lab containers or image tags changed.

| Artifact | Value |
|---|---|
| Source | `Beldex-Coin/belnet` commit `480aafb3c68ac359f0711b2cbd8a07be661703c0`, clean checkout |
| Daemon | `bin/belnet`, preserved as `bin/belnet.unmodified` |
| Daemon SHA-256 | `0036805558f8a88494937237d375f13b3a3deabb343ef726836dca0369a50425` |
| Version | `belnet-0.9.8-unknown` |
| Runtime image | `belnet-bridge:source-testnet-o0-unmodified` |
| Image ID | `sha256:c186b383a502943677be4b583d6cd08112a7051414ec7bfdd03e65ca853f3f43` |
| Platform | `linux/arm64`; runtime `uname -m` returns `aarch64` |

The runtime resolves every `ldd` dependency and contains native Go transport,
`dig`, `openssl`, `ip`, `iptables`, `tcpdump`, and `curl`. Standalone network-disabled
version/hash/dependency checks passed. These do not establish successful BelNet
routing; topology experiments are performed separately by the lab runner.

## Exact configuration

GCC 12.2.0, CMake 3.25.1, C++20, Release `-O3 -DNDEBUG`, dynamic system dependencies.
Only `llarp/service/endpoint.cpp` uses `-O0` with compiler garbage-collection options
`--param ggc-min-expand=5 --param ggc-min-heapsize=32768`. These are compiler options,
not a source modification. See `endpoint-optimization-gc.diff` for the exact rule.

`TESTNET=ON` is the actual CMake option; obsolete `WITH_TESTNET=ON` does not enable
it. Testnet changes path selection/admission behavior and must be disclosed in any
experiment using this image. It is not equivalent to the official non-testnet
release's routing or privacy properties.

Other options are recorded in `compile.sh` and `cmake/CMakeCache.txt`: GUI, tests,
Python hive, bootstrap downloader, LTO, systemd, setcap and jemalloc disabled;
shared libraries enabled. Source was mounted read-only throughout.

## Recovery and provenance

Earlier attempts OOM-killed GCC at Release `-O3` with 1500 MiB, and at endpoint
`-O0` with 500 and 1100 MiB. The successful distinct attempt added the GC options
and finished all 18 remaining steps in 58 seconds with one CPU, a 1100 MiB memory
cap and no extra swap. Logs retain every attempt.

`resume-unmodified.sh` builds the existing generated Ninja graph without CMake
regeneration, which can discard the per-file override. The older `compile.sh`
records the initial build attempt; it is not the fresh-build entry point.
`package.sh` accepts a new image tag through `BB_SOURCE_IMAGE`.

Evidence: `build-status.json`, `gcc-gc-attempt.json`, `source.commit`,
`source.submodules`, daemon/transport SHA files, compiler/CMake and package
versions, `belnet.ldd`, runtime validation and image files.

## Reproduce from a fresh checkout

Requires Docker with Linux ARM64 support, Bash, Git, Go, awk and patch. Prepare a
separate source clone; existing pinned `vendor/belnet` with all submodules also works.

```sh
git clone https://github.com/Beldex-Coin/belnet.git /absolute/path/new-belnet-source
git -C /absolute/path/new-belnet-source checkout --detach 480aafb3c68ac359f0711b2cbd8a07be661703c0
git -C /absolute/path/new-belnet-source submodule update --init --recursive

# Run from the belnet-bridge repository root. Choose one variant per build.
BB_SOURCE_DIR=/absolute/path/new-belnet-source bash build-lab/build.sh unmodified
BB_SOURCE_DIR=/absolute/path/new-belnet-source bash build-lab/build.sh queuefix
```

`build.sh` invokes `fresh-build.sh`. Each invocation creates a separate ignored
`reproductions/` directory, unique builder container and new image tags. It refuses
existing output image tags. The default is one CPU, one Ninja job, 1500 MiB and no
extra swap; build before starting a memory-heavy lab. Overrides:
`BB_FRESH_MEMORY`, `BB_FRESH_CPUS`, `BB_FRESH_IMAGE` and `BB_SOURCE_DIR`.

The recipe pins and checks the BelNet commit/submodules, cross-compiles the current
Go transport for Linux ARM64, then applies the tested endpoint `-O0` and GCC GC
flags **before the first native compilation**. Queuefix applies the exact recorded
patch only to a copied handler mounted read-only over the source file. The original
checkout is never edited. Both variants remain `TESTNET=ON`.

Each output records source/patch identity, compiler/packages, exact generated flag
diff, binary hashes, image IDs and runtime dependency checks. Debian/package inputs
are recorded rather than pinned to an archive, so byte-identical rebuilds are not
promised. This fresh workflow has been **syntax/configuration reviewed, not freshly
rerun**. Its flag transformation matches the graph used by the successful build;
the previously built images and experiment results are separate evidence.

## Separate queue-wakeup variant

`belnet-bridge:source-testnet-o0-queuefix` was subsequently built after explicit
authorization. Its sole source difference is `queue-wakeup.patch`, which adds
`_router->TriggerPump()` after a successful outbound enqueue. This was mounted as
a read-only single-file overlay; the vendor checkout remains clean.

Queue-fix daemon SHA-256:
`53bdf1d5712a058e43a2e03a3c22bfccc2d96234d4354258b1fffd186329b881`.
Patch SHA-256:
`83f1339d42e96c30d814a29ec8505c4d3285a5bddf46266a2b0a3d728623bfe6`.
Image ID: `sha256:7bd079886619e8d7714b2af6c6fbff85cf7c3514128e31a4bb2133c677d57047`.
The Go transport is identical in both images. Source commit, TESTNET mode and
compiler options are unchanged. Scheduling is modified; cryptography, identity,
admission and path-selection code are not modified by this one-line patch.

The original daemon files and image above remain intact. The shared object cache
now contains the queue-fix object. Both resume scripts validate their expected
handler content and force that object to rebuild when switching variants.
`queuefix-provenance.json` records exact hashes, timing and validation. A real
network pilot remains separate from successful packaging.

The older `rebuild-patched.sh` invokes CMake regeneration; use the new
`resume-queuefix.sh` with the explicit read-only overlay instead.

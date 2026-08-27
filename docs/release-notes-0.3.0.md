# Release Notes: 0.3.0

## Highlights

- Fixed builder/send-task ownership transfer under allocator failure.
- Persistent records now remain recoverable after retry-budget exhaustion or
  temporary internal queue/budget failures instead of being implicitly ACKed.
- Added explicit buffered-WAL and sync-WAL durability, checkpoint durability
  observability, and high-to-low watermark reclaim behavior.
- Versioned persistent records now carry enqueue timestamps while retaining
  legacy-record recovery; runtime target updates remain an explicit
  last-write-wins operation with backlog risk documented to callers.
- Aligned Android persistent capacity/durability configuration and pinned the
  wrapper to an immutable C core commit.
- Added a shared-library ABI boundary with hidden default visibility and a
  checked approved export surface.
- Added the versioned producer constructor to the approved 0.3.0 ABI surface.
- Added public-header C++ compile/link coverage for core, adapter, and Android
  binding headers.
- Added install rules, a relocatable CMake package, and an independent C
  consumer example using `find_package(ve_tls_core CONFIG)`.
- Kept LZ4 implementation headers private to the SDK target. Zlib, pthread, and
  optional curl dependencies are propagated through the installed package as
  required by the selected build.
- Added platform-vtable and per-platform ABI baseline documentation.
- Added SPDX 2.3 SBOM, bundled LZ4 notice, and installable license and release
  documentation.

## Compatibility notes

The record-layout values in `docs/abi.md` are platform snapshots, not a
universal structure ABI. Consumers must use matching headers, API version, and
target/compiler layout. The 0.3.0 ABI gate intentionally rejects internal
queue, persistent, hash, protocol, signing, compression, and adapter symbols.
Only the approved headers are installed; source-tree internal headers remain
unsupported implementation interfaces.

Release acceptance also requires the static/shared test matrix, exact export
check, sanitizer run, installed C consumer, and Android integration to pass
against the immutable release commit.

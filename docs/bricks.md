# Bricks

`ve_tls_bricks_core` is the tiny profile for severely resource-constrained
devices. It is for callers that own HTTP transport, retry, queueing, callbacks,
credential refresh, persistence, scheduling, and metrics.

The public entry point is `ve_tls_bricks_pack_request()`. It builds a `POST`
`/PutLogs?TopicId=...` request with protobuf body bytes, TLS V4 signing
headers, and caller-provided metadata. It does not send the request.

The core target must stay free of producer, thread, curl, retry, metrics,
persistence, and environment runtime dependencies.

The release target is capability parity for constrained environments with
same-order resource usage. Matching SLS' smallest quoted memory number is not a
hard gate because this target keeps TLS V4 signing inside the SDK instead of
delegating all crypto/time work to the caller.

This design is intentionally close to Aliyun SLS `bricks-https`: keep the SDK
core as a request packer, move platform HTTP and retry decisions to the caller,
and keep optional features off by default. The main difference is that TLS V4
signing is built into this core, while SLS bricks delegates MD5, HMAC-SHA1, and
time formatting to user-provided function pointers.

## Build

Tiny profile:

```sh
cmake -S . -B build-bricks \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_BRICKS_ENABLE_LZ4=OFF \
  -DVE_TLS_BRICKS_ENABLE_ZLIB=OFF
cmake --build build-bricks --target ve_tls_bricks_core
```

Optional compression is intentionally separate from the full SDK compression
switches. Keep both off for the smallest binary; enable
`VE_TLS_BRICKS_ENABLE_LZ4` or `VE_TLS_BRICKS_ENABLE_ZLIB` only when the caller
needs compressed request bodies.

Real-environment demo target:

```sh
cmake -S . -B build-bricks-real \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_BUILD_TOOLS=ON \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=ON \
  -DVE_TLS_BRICKS_ENABLE_LZ4=OFF \
  -DVE_TLS_BRICKS_ENABLE_ZLIB=OFF
cmake --build build-bricks-real --target ve_tls_bricks_demo_real
```

`ve_tls_bricks_demo_real` links curl only in the demo binary. It does not add
curl to `ve_tls_bricks_core`.

For the lowest runtime heap, keep `compress_type="none"` and set
`body_no_copy=1` in `ve_tls_bricks_config`. In that mode the request body points
at the caller-owned protobuf buffer and `ve_tls_bricks_request_free()` does not
free it. If `body_no_copy=0`, or compression is enabled, the request owns the
returned body buffer.

## Scope

Included:

- protobuf log-group packing helpers
- MD5/SHA256/HMAC signing
- `POST /PutLogs?TopicId=...` request assembly
- owned or caller-borrowed request bodies returned by `ve_tls_bricks_pack_request()`

Excluded:

- HTTP transport and curl
- producer queueing, retries, callbacks, scheduling, metrics, persistence
- pthread runtime and environment discovery
- credential refresh

The caller owns sending, retry policy, backpressure, credentials, and memory
lifetime after `ve_tls_bricks_pack_request()` returns.

When using libcurl directly, preserve empty signed headers. For example,
`x-tls-hashkey: ` is part of the signature even when the hash key is empty.
libcurl treats `Header:` as header removal, so the demo converts empty-value
headers to `Header;`, matching the full producer curl adapter.

## SLS Bricks Reference

The SLS `bricks-https` branch removes the normal producer implementation and
keeps only:

- `src/log_builder.c`: protobuf builder with one growing log buffer
- `src/log_api.c`: URL/header/signature packing for raw or LZ4 body
- `src/sds.c`: small dynamic strings for headers and path
- optional `src/lz4.c`, disabled by default

SLS moves these pieces out of the core:

- HTTP transport is only in sample code and uses libcurl
- MD5/HMAC/time are user-provided hooks from `log_util.h`
- retry/drop/time-fix logic is in the sample, not in the library
- queue, producer manager, sender, config, zstd, pthread, and dynamic
  credentials are absent from the bricks target

The important implementation lesson is no-copy body ownership. SLS
`serialize_to_proto_buf_with_malloc()` returns the builder's internal buffer,
and `pack_logs_from_raw_buffer()` only creates headers. `body_no_copy=1` mirrors
that behavior for TLS bricks.

## Size And Perf Baseline

Measured on macOS with AppleClang 17, `CMAKE_BUILD_TYPE=MinSizeRel`.

Run:

```sh
tools/bricks_size_report.sh build-bricks-size-report-tiny2
VE_TLS_SIZE_BRICKS_ENABLE_LZ4=ON tools/bricks_size_report.sh build-bricks-size-report-lz4-2
cmake -S . -B build-bricks-bench -DVE_TLS_BUILD_BRICKS=ON -DVE_TLS_BUILD_TOOLS=ON -DVE_TLS_BRICKS_ENABLE_LZ4=OFF
cmake --build build-bricks-bench --target ve_tls_bricks_bench
/usr/bin/time -l build-bricks-bench/ve_tls_bricks_bench --iterations 10000 --logs 10 --message-bytes 128 --compress-type none --copy-body 0 --track-alloc 1
```

Static archive sizes:

| target/config | archive bytes | ratio vs full core |
| --- | ---: | ---: |
| `ve_tls_core`, LZ4 on | 179064 | 100% |
| `ve_tls_bricks_core`, LZ4 off | 35320 | 19.7% |
| `ve_tls_bricks_core`, LZ4 on | 74408 | 41.6% |
| SLS `log_c_sdk_static`, LZ4 off | 47736 | 26.7% |

`nm -g` forbidden-symbol check passed for `pthread`, `curl`,
`ve_tls_producer`, `ve_tls_env`, retry, metrics, persistence, and file-runtime
symbols.

Runtime measurements use `/usr/bin/time -l`, so RSS includes executable,
loader, libc, and process baseline. `sdk_heap_peak_bytes` is measured through
`ve_tls_alloc_set_hooks()` and only covers TLS SDK heap allocations.

Benchmark with 10000 iterations, 10 logs per request, 128-byte message,
`compress_type=none`, `body_no_copy=1`:

| metric | value |
| --- | ---: |
| avg encode+pack time, allocation tracking on | 47.042 us |
| requests per second, allocation tracking on | 21257.55 |
| raw throughput, allocation tracking on | 31.30 MiB/s |
| SDK heap peak | 7092 bytes |
| SDK heap after run | 0 bytes |
| maximum resident set size | 1769472 bytes |
| peak memory footprint | 1524000 bytes |

Small-payload benchmark with 10000 iterations, 1 log per request,
16-byte message:

| metric | value |
| --- | ---: |
| SDK heap peak | 2736 bytes |
| SDK heap after run | 0 bytes |
| maximum resident set size | 1998848 bytes |
| peak memory footprint | 1769784 bytes |

Same-host SLS `bricks-https` reference runs, built from
`origin/bricks-https` with `WITH_LZ4=OFF`, show:

| workload | avg time | max RSS | peak footprint |
| --- | ---: | ---: | ---: |
| 10000 x 10 logs x 128 bytes | 5.633 us | 1556480 bytes | 1343800 bytes |
| 10000 x 1 log x 16 bytes | 3.685 us | 1654784 bytes | 1458512 bytes |

Those SLS numbers are not an exact protocol-equivalent comparison: SLS uses
HMAC-SHA1 helpers supplied by the caller, while TLS bricks runs built-in TLS V4
SHA256/HMAC canonical signing. The remaining gap for a strict sub-1KB SDK heap
target would require a specialized bricks signer and a streaming protobuf
builder that avoid the generic signer/parser allocation path. That optimization
is optional unless a deployment has a strict sub-1KB SDK-heap budget.

## Real Environment Validation

Run after local build/tests:

```sh
VE_TLS_ENDPOINT=... \
VE_TLS_REGION=... \
VE_TLS_TOPIC_ID=... \
VE_TLS_ACCESS_KEY_ID=... \
VE_TLS_ACCESS_KEY_SECRET=... \
VE_TLS_COMPRESS_TYPE=none \
build-bricks-real/ve_tls_bricks_demo_real --count 1 --timeout-ms 15000
```

The validation must return `http=200`. A real run against the Guilin BOE TLS
endpoint returned:

```text
attempt=1 curl=0 http=200 request_bytes=86 response_bytes=0
```

This verifies that the bricks protobuf body, TLS V4 signature, signed headers,
and caller-side curl transport are accepted by the service.

Real-environment sequential benchmark uses the same binary with `--quiet`:

```sh
VE_TLS_ENDPOINT=... \
VE_TLS_REGION=... \
VE_TLS_TOPIC_ID=... \
VE_TLS_ACCESS_KEY_ID=... \
VE_TLS_ACCESS_KEY_SECRET=... \
VE_TLS_COMPRESS_TYPE=none \
build-bricks-real/ve_tls_bricks_demo_real --count 20 --timeout-ms 15000 --quiet
```

Measured against the Guilin BOE TLS endpoint:

| run | success | elapsed | req/s | avg latency | min latency | max latency | request bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| sequential 20 requests | 20/20 | 3503.200 ms | 5.71 | 175.151 ms | 146.232 ms | 327.387 ms | 1731 |
| sequential 20 requests with `/usr/bin/time -l` | 20/20 | 8590.317 ms | 2.33 | 429.510 ms | 134.199 ms | 3098.894 ms | 1731 |

Resource sample from the timed run:

| metric | value |
| --- | ---: |
| maximum resident set size | 6619136 bytes |
| peak memory footprint | 4342240 bytes |
| user CPU time | 0.01 s |
| system CPU time | 0.00 s |

These are real network measurements, so latency is dominated by endpoint and
network variance. Use the local `ve_tls_bricks_bench` numbers for CPU-only pack
cost, and this real benchmark for end-to-end service acceptance and network
path sanity.

# Production Alignment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make ve-tls-c-sdk producer production-ready with richer curl networking options, pluggable metrics export (including latency), and safer concurrency controls (ordering, rate limiting, circuit breaker).

**Architecture:** Extend `ve_tls_config` with networking/observability/controls settings. Implement curl option wiring in the adapter, implement a lightweight metrics sink interface and latency accounting in sender threads, and add concurrency controls (optional ordered send + token bucket + circuit breaker) in the send path.

**Tech Stack:** C, libcurl (optional), pthread (optional), CMake, current internal platform abstraction (`ve_tls_platform`).

---

### Task 1: Curl networking options

**Files:**
- Modify: [ve_tls_producer.h](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/include/ve_tls_producer.h)
- Modify: [ve_tls_http.h](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/include/ve_tls_http.h)
- Modify: [ve_tls_http_curl.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/adapters/src/ve_tls_http_curl.c)
- Test: [test_basic.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/tests/test_basic.c)

**Step 1: Add config knobs**
- Add `tls_verify_peer`, `tls_verify_host`, `ca_cert_path`, `proxy`, keepalive knobs (enable/idle/intvl), and optional `user_agent` to config.

**Step 2: Wire knobs into curl**
- Map to `CURLOPT_SSL_VERIFYPEER`, `CURLOPT_SSL_VERIFYHOST`, `CURLOPT_CAINFO`, `CURLOPT_PROXY`, `CURLOPT_TCP_KEEPALIVE`, `CURLOPT_TCP_KEEPIDLE`, `CURLOPT_TCP_KEEPINTVL`, `CURLOPT_USERAGENT`.

**Step 3: Unify error mapping**
- Ensure `transport_kind/transport_code/transport_retryable` are always populated.

**Step 4: Verify builds**
- Build with curl ON/OFF and run `ctest`.

---

### Task 2: Pluggable metrics sink + latency

**Files:**
- Modify: [ve_tls_producer.h](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/include/ve_tls_producer.h)
- Modify: [ve_tls_producer.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/ve_tls_producer.c)
- Test: [test_basic.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/tests/test_basic.c)

**Step 1: Define sink interface**
- Add `ve_tls_metrics_sink` with callback receiving event name + integer fields or a typed struct.

**Step 2: Emit events**
- Emit enqueue/drop/batch/request/retry/success/failure and latency (ms). Keep emission lock-free and optional.

**Step 3: Latency histogram**
- Keep a fixed-bucket histogram internally (or emit raw latencies).

**Step 4: Add test**
- Use mock HTTP client to force one request and assert sink received at least one latency event.

---

### Task 3: Concurrency controls (ordering + rate limit + circuit breaker)

**Files:**
- Modify: [ve_tls_producer.h](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/include/ve_tls_producer.h)
- Modify: [ve_tls_producer.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/core/src/ve_tls_producer.c)
- Test: [test_basic.c](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/tests/test_basic.c)

**Step 1: Ordered send option**
- Add config `ordered_send=1` to ensure at most one in-flight send task per producer.

**Step 2: Token bucket**
- Add `rate_limit_rps` and `rate_limit_bps` (optional). Block senders until tokens available.

**Step 3: Circuit breaker**
- Add `breaker_fail_threshold`, `breaker_open_ms`, `breaker_half_open_max_inflight`.
- Open on consecutive failures (post-retry) and gate new sends while open.

**Step 4: Tests**
- Mock HTTP 500 and assert breaker opens and prevents immediate subsequent sends; mock HTTP 200 and assert recovery.

---

### Task 4: Verification matrix

Run builds:
- curl+zlib+lz4 ON
- no curl, no zlib, lz4 ON
- no curl, zlib ON, lz4 OFF
- no curl, no zlib, no lz4

Run:
- `ctest --output-on-failure`


# 指标与观测

## 指标接口

Full Producer 提供 SDK 内置观测接口：

- `ve_tls_producer_get_metrics()` 提供累计快照。
- `metrics_sink.emit` 可导出 SDK 事件，由上层决定 pull/push 和采样策略。
- `ve_tls_producer_get_buffered_bytes()` 返回当前 producer buffered 估算值，用于观察内存预算压力。
- `send_done_v2` 回调提供结构化错误、request_id、HTTP code、可重试状态和批次 log_id 范围。

Bricks tiny core 不提供 metrics API、metrics sink 或 send callback。它只返回 pack 结果和 request struct。调用方如果需要观测，应在 Bricks 外层埋点：

- pack 调用次数和失败次数
- pack latency
- request body bytes 和 raw body bytes
- HTTP attempts、success、failures、latency
- retry attempts 和 retry delay
- 调用方队列长度、队列 bytes、drop 数
- transport 层 request id、HTTP code、服务端 error code

## 最小指标集

Full Producer 最小指标：

- `logs_enqueued_total`
- `logs_dropped_total`
- `bytes_enqueued_total`
- `bytes_dropped_total`
- `batches_built_total`
- `requests_total`
- `requests_failed_total`
- `retries_total`
- `bytes_sent_total`
- `request_latency_buckets`

Bricks 建议最小指标：

| 指标 | 说明 |
| --- | --- |
| `bricks_pack_total` | 调用 `ve_tls_bricks_pack_request()` 次数 |
| `bricks_pack_failed_total` | pack 返回非 0 次数，按 rc 维度拆分 |
| `bricks_pack_latency_us` | pack 耗时 |
| `bricks_raw_body_bytes_total` | `raw_body_size` 累计 |
| `bricks_request_body_bytes_total` | `body_size` 累计 |
| `http_requests_total` | 调用方 transport 请求数 |
| `http_requests_failed_total` | transport 失败数 |
| `http_request_latency_ms` | transport 端到端耗时 |
| `http_retries_total` | 调用方重试次数 |
| `queue_bytes` | 调用方队列或持久化中的待发送 bytes |

## 建议派生维度

Full Producer：

- drop reason：buffer full、send_queue full、alloc failed、closed、invalid input。
- HTTP code：2xx、4xx、429、5xx。
- retryable：true/false。
- hashKey：只建议做采样或 top-N，避免高基数指标拖垮上层系统。

Bricks：

- `compress_type`：`none` / `lz4` / `zlib`
- `body_no_copy`：true / false
- `pack_rc`：`0` / `-1` / `-3`
- `http_code_class`：2xx / 4xx / 429 / 5xx
- `curl_code` 或调用方 HTTP client 的错误码
- `topic_id`：只建议低基数或脱敏维度
- `hash_key`：只建议采样或 top-N

## 日志

通用安全要求：

- 禁止打印 AK/SK/security token。
- 禁止打印完整 Authorization header。
- 默认禁止打印完整请求体；排障时也应采样和脱敏。

Full Producer 错误日志应包含：

- request_id
- http_code
- error_code
- error_message
- retryable
- log_id 范围

Bricks 调用方日志应包含：

- pack rc
- body size 和 raw body size
- compress type
- HTTP code / transport error code
- request id，如果服务端返回
- retry attempt
- endpoint region 和 topic 的脱敏标识

不要把 `req.headers` 原样打到日志中，因为其中包含 `Authorization` 和可选 `X-Security-Token`。

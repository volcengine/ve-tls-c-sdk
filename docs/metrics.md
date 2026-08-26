# 指标与观测

SDK 提供三类观测入口：累计指标、事件回调和发送完成回调。

## 接口

- `ve_tls_producer_get_metrics()` 返回 Producer 的累计指标快照。
- `ve_tls_producer_get_buffered_bytes()` 返回当前 buffered bytes 估算值，可用于观察内存压力。
- `metrics_sink.emit` 输出 SDK 内部事件，上层可以采样、聚合或转发。
- `send_done_v2` 返回结构化错误、request id、HTTP code、重试判断和批次 log id 范围。

## 基础指标

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

## 建议维度

- drop reason：buffer full、send queue full、persistent quota、alloc failed、closed、invalid input。
- HTTP code：2xx、4xx、429、5xx。
- retryable：true / false。
- result：`VE_TLS_OK`、`VE_TLS_DROP_ERROR`、`VE_TLS_PERSISTENT_ERROR`、`VE_TLS_TIMEOUT`。
- hashKey：只建议采样或记录 top-N，避免高基数拖垮上层指标系统。

## Persistent 排障

Persistent 模式下，指标要和本地目录状态一起看：

- `logs_dropped_total` 增长，且 `add_log` 返回 `VE_TLS_DROP_ERROR`：先查内存背压和 persistent quota。
- `requests_failed_total` 与 `retries_total` 增长：先看回调中的 `http_code`、`error_code` 和 `retryable`。
- `ve_tls_producer_get_buffered_bytes()` 长时间接近 `max_buffer_bytes`：发送速度跟不上写入，或 close/drain 时间不足。
- persistent 目录持续增长：说明 backlog 没有被 ack 到可回收位置，优先查发送回调和网络。
- `persistent_append_failed(log_id, bytes)`：record 未完整 append，常见原因是目录权限、磁盘空间或短写。
- `persistent_sync_failed(log_id, bytes)`：record 或 dirty segment 的 `fsync` 失败；flush/close 失败时两个值为 `0`。
- `persistent_checkpoint_save_failed(start_id, end_id)`：checkpoint 未 durable；保持 dirty 且不回收对应范围。
- `persistent_flush_failed(0, 0)`：flush 的非 sync、非 checkpoint 阶段失败。

`tools/persistent_real_bench.c` 会输出 `current_records`、`current_bytes`、`acked_log_id` 等字段，适合压测和恢复验证。它不是稳定的公共 metrics API，线上接入不要依赖这些内部字段。

## 日志

- 不要打印 AK/SK/security token、完整 Authorization header 或完整请求体。
- 错误日志建议包含 request id、HTTP code、error code、error message、retryable 和 log id 范围。
- 资源压力日志建议包含 buffered bytes、max buffer bytes、send queue size、persistent 目录、overflow policy 和当前策略。

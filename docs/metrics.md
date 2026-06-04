# 指标与观测

SDK 提供两类观测入口：累计快照和事件回调。

## 接口

- `ve_tls_producer_get_metrics()` 返回当前 producer 的累计指标快照。
- `metrics_sink.emit` 输出 SDK 内部事件，上层可以按需采样、聚合或转发。
- `ve_tls_producer_get_buffered_bytes()` 返回当前 producer 的 buffered bytes 估算值，可用于观察内存压力。
- `send_done_v2` 回调提供结构化错误、request id、HTTP code、重试判断和批次 log id 范围。

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

- drop reason：buffer full、send queue full、alloc failed、closed、invalid input。
- HTTP code：2xx、4xx、429、5xx。
- retryable：true / false。
- hashKey：只建议采样或记录 top-N，避免高基数拖垮上层指标系统。

## 日志

- 不要打印 AK/SK/security token、完整 Authorization header 或完整请求体。
- 错误日志建议包含 request id、HTTP code、error code、error message 和 retryable。
- 资源压力日志建议包含 buffered bytes、max buffer bytes、send queue size 和当前策略。

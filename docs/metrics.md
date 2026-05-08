# 指标与观测规范

## 指标接口

- `ve_tls_producer_get_metrics()` 提供累计快照。
- `metrics_sink.emit` 可导出 SDK 事件，由上层决定 pull/push 和采样策略。
- `ve_tls_producer_get_buffered_bytes()` 返回当前 producer buffered 估算值，用于观察内存预算压力。
- `send_done_v2` 回调提供结构化错误、request_id、HTTP code、可重试状态和批次 log_id 范围。

## 最小指标集

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

## 建议派生维度

- drop reason：buffer full、send_queue full、alloc failed、closed、invalid input。
- HTTP code：2xx、4xx、429、5xx。
- retryable：true/false。
- hashKey：只建议做采样或 top-N，避免高基数指标拖垮上层系统。

## 日志

- 禁止打印 AK/SK/security token、完整 Authorization header 或完整请求体。
- 错误日志应包含 request_id、http_code、error_code、error_message。
- 资源压力日志应带上 buffered bytes、max_buffer_bytes、send_queue_size 和策略。

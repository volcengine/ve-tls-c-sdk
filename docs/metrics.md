# 指标与观测规范

## 指标接口
- SDK 内部统计聚合，提供可注入的指标导出接口（pull 或 push 由上层实现）

## 指标项（建议最小集）
- logs_enqueued_total
- logs_dropped_total（按原因维度）
- batches_sent_total
- batches_failed_total（按 http_code/error_code 维度）
- retries_total
- retry_delay_ms（分位统计）
- request_latency_ms（分位统计）
- persistent_bytes_used（persistent 分支）
- persistent_logs_pending（persistent 分支）

## 日志
- 错误日志必须脱敏（禁止打印 AK/SK/token、完整请求体）
- 关键错误必须包含 request_id 与 error_code（若存在）

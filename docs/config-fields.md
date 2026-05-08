# 配置字段清单

本文档面向 Linux 通用 Producer，列出公开建议使用的配置字段。

## 目标与鉴权

- `endpoint`
- `region`
- `project_id`
- `topic_id`
- `source`
- `file_name`
- `context_flow`
- `log_tags` / `log_tag_count`
- `hash_key`
- `access_key_id`
- `access_key_secret`
- `security_token`
- `credentials_provider`
- `credentials_provider_param`
- `credentials_expire_advance_ms`
- `credentials_refresh_min_interval_ms`

## 聚合与发送

- `compress_type`
- `send_thread_count`
- `pack_thread_count`
- `use_global_env`
- `ordered_send`
- `log_bytes_per_package`
- `log_count_per_package`
- `flush_interval_ms`
- `agg_strategy`
- `agg_max_log_group_logs`
- `agg_max_raw_bytes_per_request`
- `agg_max_compressed_bytes_per_request`
- `enable_time_ns`

## 资源与背压

- `max_buffer_bytes`
- `buffer_full_policy`
- `buffer_full_block_timeout_ms`
- `send_queue_size`
- `send_queue_full_policy`
- `send_queue_block_timeout_ms`
- `send_queue_sample_every_n`

运行期默认值派生规则：

- 如果 `log_bytes_per_package` 仍是初始化默认值，`max_buffer_bytes <= 64MB` 时派生为 `2MB`，否则派生为 `4MB`。
- 如果 `send_thread_count` 仍是初始化默认值，`<=64MB` 派生为 `2`，`<=256MB` 派生为 `4`，更大派生为 `8`。
- 如果 `pack_thread_count` 仍是初始化默认值，跟随 `send_thread_count`。
- 如果 `send_queue_size` 仍是初始化默认值，派生为 `8 + max_buffer_bytes/log_bytes_per_package`，范围限制在 `8..128`。
- 显式配置过的字段不会被派生默认值覆盖。

## 限流与熔断

- `rate_limit_rps`
- `rate_limit_bps`
- `breaker_fail_threshold`
- `breaker_open_ms`
- `breaker_half_open_max_inflight`
- `key_queue_max_active`
- `key_queue_bucket_count`
- `key_queue_idle_ttl_ms`
- `key_rate_limit_rps`
- `key_rate_limit_bps`
- `key_breaker_fail_threshold`
- `key_breaker_open_ms`

## 网络与 TLS

- `connect_timeout_ms`
- `request_timeout_ms`
- `tls_verify_peer`
- `tls_verify_host`
- `ca_cert_path`
- `proxy`
- `user_agent`
- `http_debug`
- `tcp_keepalive`
- `tcp_keepidle`
- `tcp_keepintvl`
- `http_client`

## 回调与重试

- `metrics_sink`
- `retry_max_attempts`
- `retry_policy`
- `callback_from_sender_thread`

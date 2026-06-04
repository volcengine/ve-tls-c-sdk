# 配置字段

本文列出 `ve_tls_config` 中建议公开使用的字段。字段名以 `core/include/ve_tls_producer.h` 为准。

## 目标与鉴权

| 字段 | 说明 |
| --- | --- |
| `endpoint` | TLS endpoint，例如 `https://tls-cn-beijing.volces.com`。 |
| `region` | TLS region，例如 `cn-beijing`。 |
| `project_id` | 项目 ID。通常可以不填，发送请求主要依赖 topic。 |
| `topic_id` | 目标 topic。 |
| `source` | 写入到 LogGroup 的 source。 |
| `file_name` | 写入到 LogGroup 的 file name。 |
| `context_flow` | 写入到 LogGroup 的 context flow。 |
| `log_tags` / `log_tag_count` | LogGroup 级别的 tags。 |
| `hash_key` | 默认 hashKey。单次写入传入 hashKey 时会覆盖该默认值。 |
| `access_key_id` / `access_key_secret` | 静态 AK/SK。 |
| `security_token` | 临时凭证 token。 |
| `credentials_provider` | 临时凭证刷新回调。 |
| `credentials_provider_param` | 传给凭证回调的用户参数。 |
| `credentials_expire_advance_ms` | 提前刷新凭证的时间。 |
| `credentials_refresh_min_interval_ms` | 两次刷新之间的最小间隔。 |

## 聚合与发送

| 字段 | 说明 |
| --- | --- |
| `compress_type` | `lz4`、`zlib` 或 `none`。 |
| `send_thread_count` | sender 线程数。 |
| `pack_thread_count` | packer 线程数。 |
| `use_global_env` | 是否共享全局运行环境。 |
| `ordered_send` | 是否按 hashKey 保持有序发送。 |
| `log_bytes_per_package` | 单批日志字节阈值。 |
| `log_count_per_package` | 单批日志条数阈值。 |
| `flush_interval_ms` | 聚合等待时间。 |
| `agg_strategy` | 聚合策略。默认策略会按压缩后大小继续切分。 |
| `agg_max_log_group_logs` | 单个 LogGroup 的日志条数上限。 |
| `agg_max_raw_bytes_per_request` | 单个请求的原始日志字节上限。 |
| `agg_max_compressed_bytes_per_request` | 单个请求的压缩后字节上限。 |
| `enable_time_ns` | 是否写入纳秒时间字段。 |

## 资源与背压

| 字段 | 说明 |
| --- | --- |
| `max_buffer_bytes` | Producer 总缓存预算。 |
| `buffer_full_policy` | 写入侧队列满策略：`DROP` 或 `BLOCK`。 |
| `buffer_full_block_timeout_ms` | 写入侧阻塞超时。 |
| `send_queue_size` | manager 到 sender 的队列容量。 |
| `send_queue_full_policy` | send queue 满策略：`DROP`、`BLOCK` 或 `DROP_SAMPLED`。 |
| `send_queue_block_timeout_ms` | send queue 阻塞超时。 |
| `send_queue_sample_every_n` | `DROP_SAMPLED` 的采样间隔。 |

默认值派生规则：

- `log_bytes_per_package` 未显式配置时，`max_buffer_bytes <= 64MB` 派生为 `2MB`，否则派生为 `4MB`。
- `send_thread_count` 未显式配置时，`<=64MB` 派生为 `2`，`<=256MB` 派生为 `4`，更大派生为 `8`。
- `pack_thread_count` 未显式配置时，跟随 `send_thread_count`。
- `send_queue_size` 未显式配置时，派生为 `8 + max_buffer_bytes / log_bytes_per_package`，范围限制在 `8..128`。
- 显式配置过的字段不会被派生值覆盖。

## 限流、熔断与 hashKey 队列

| 字段 | 说明 |
| --- | --- |
| `rate_limit_rps` / `rate_limit_bps` | 全局请求数和字节数限流。 |
| `breaker_fail_threshold` | 全局熔断失败阈值。 |
| `breaker_open_ms` | 全局熔断打开时间。 |
| `breaker_half_open_max_inflight` | 半开状态允许的并发请求数。 |
| `key_queue_max_active` | 活跃 hashKey 队列数量上限。 |
| `key_queue_bucket_count` | hashKey 队列哈希桶数量。 |
| `key_queue_idle_ttl_ms` | 空闲 hashKey 队列保留时间。 |
| `key_rate_limit_rps` / `key_rate_limit_bps` | 单 hashKey 请求数和字节数限流。 |
| `key_breaker_fail_threshold` | 单 hashKey 熔断失败阈值。 |
| `key_breaker_open_ms` | 单 hashKey 熔断打开时间。 |

## 网络与 TLS

| 字段 | 说明 |
| --- | --- |
| `connect_timeout_ms` | 连接超时。 |
| `request_timeout_ms` | 单请求超时。 |
| `tls_verify_peer` / `tls_verify_host` | TLS 证书校验开关，默认开启。 |
| `ca_cert_path` | 自定义 CA 证书路径。 |
| `proxy` | HTTP 代理。 |
| `user_agent` | 自定义 User-Agent。 |
| `http_debug` | HTTP 调试开关，生产环境不要开启。 |
| `tcp_keepalive` / `tcp_keepidle` / `tcp_keepintvl` | TCP keepalive 参数。 |
| `http_client` | 自定义 HTTP client。默认由构建选项选择 curl 或 noop adapter。 |

## 回调与重试

| 字段 | 说明 |
| --- | --- |
| `metrics_sink` | SDK 事件输出回调。 |
| `retry_max_attempts` | 批次重试次数上限。 |
| `retry_policy` | 请求级重试策略。 |

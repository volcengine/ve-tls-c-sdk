# 配置字段

本文列出 `ve_tls_config` 中建议接入方直接使用的字段。字段名以 `core/include/ve_tls_producer.h` 为准。

## 目标与鉴权

| 字段 | 说明 |
| --- | --- |
| `endpoint` | TLS endpoint，例如 `https://tls-cn-beijing.volces.com`。真实发送必填。 |
| `region` | TLS region，例如 `cn-beijing`。真实发送必填。 |
| `topic_id` | 目标 topic。真实发送必填。 |
| `project_id` | 项目 ID。通常可以不填，发送主要依赖 topic。 |
| `source` | 写入到 LogGroup 的 source。 |
| `file_name` | 写入到 LogGroup 的 file name。 |
| `context_flow` | 写入到 LogGroup 的 context flow。 |
| `log_tags` / `log_tag_count` | LogGroup 级别 tags。 |
| `hash_key` | 默认 hashKey。单次写入传入 hashKey 时会覆盖该默认值。 |
| `access_key_id` / `access_key_secret` | 静态 AK/SK。 |
| `security_token` | 临时凭证 token。 |
| `credentials_provider` | 临时凭证刷新回调。 |
| `credentials_provider_param` | 传给凭证回调的用户参数。 |
| `credentials_expire_advance_ms` | 凭证过期前提前刷新的时间。 |
| `credentials_refresh_min_interval_ms` | 两次刷新之间的最小间隔。 |

## 聚合与发送

| 字段 | 说明 |
| --- | --- |
| `compress_type` | `lz4`、`zlib` 或 `none`。默认 `lz4`。 |
| `send_thread_count` | sender 线程数。未显式设置时按内存预算派生。 |
| `pack_thread_count` | packer 线程数。未显式设置时跟随 `send_thread_count`。 |
| `use_global_env` | 是否使用进程级共享 sender。多个 Producer 并存时建议开启。 |
| `ordered_send` | 是否按 hashKey 串行发送。严格顺序场景建议同时设置 `send_thread_count=1`。 |
| `log_bytes_per_package` | 单批原始日志字节阈值。不能超过 `max_buffer_bytes / 2`。 |
| `log_count_per_package` | 单批日志条数阈值。 |
| `flush_interval_ms` | 聚合等待时间。延迟敏感场景可调小，但请求数会增加。 |
| `agg_strategy` | 聚合策略。默认策略会按压缩后大小继续切分。 |
| `agg_max_log_group_logs` | 单个 LogGroup 的日志条数上限。 |
| `agg_max_raw_bytes_per_request` | 单个请求的原始日志字节上限。 |
| `agg_max_compressed_bytes_per_request` | 单个请求的压缩后字节上限。 |
| `enable_time_ns` | 是否写入纳秒时间字段。 |

默认派生规则：

- `log_bytes_per_package` 未配置时，`max_buffer_bytes <= 64 MiB` 派生为 `2 MiB`，否则派生为 `4 MiB`。
- `send_thread_count` 未配置时，`max_buffer_bytes <= 64 MiB` 派生为 `2`，`<= 256 MiB` 派生为 `4`，更大派生为 `8`。
- `pack_thread_count` 未配置时跟随 `send_thread_count`。
- `send_queue_size` 未配置时派生为 `8 + max_buffer_bytes / log_bytes_per_package`，范围限制在 `8..128`。
- 显式配置过的字段不会被派生值覆盖。

## 资源与背压

| 字段 | 说明 |
| --- | --- |
| `max_buffer_bytes` | Producer 主要内存预算。写入队列、send queue、inflight 批次、raw 导入和压缩 scratch 都受它约束。 |
| `buffer_full_policy` | 写入侧内存不足时的策略：`DROP` 或 `BLOCK`。 |
| `buffer_full_block_timeout_ms` | `BLOCK` 策略下等待内存预算释放的最长时间。 |
| `send_queue_size` | manager 到 sender 的队列容量。 |
| `send_queue_full_policy` | send queue 满策略：`BLOCK`、`DROP` 或 `DROP_SAMPLED`。 |
| `send_queue_block_timeout_ms` | send queue 阻塞超时。 |
| `send_queue_sample_every_n` | `DROP_SAMPLED` 的采样间隔。 |

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

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `connect_timeout_ms` | `10000` | 建连超时。 |
| `request_timeout_ms` | `50000` | 单请求超时。真实网络环境不建议过小，否则容易把服务端处理慢误判成失败。 |
| `tls_verify_peer` / `tls_verify_host` | 开启 | TLS 证书校验开关。生产环境不要关闭。 |
| `ca_cert_path` | 空 | 自定义 CA 证书路径。 |
| `proxy` | 空 | HTTP 代理。 |
| `user_agent` | 空 | 自定义客户端标识。通常不需要配置。 |
| `http_debug` | `0` | HTTP 调试开关。生产环境不要开启。 |
| `tcp_keepalive` / `tcp_keepidle` / `tcp_keepintvl` | 关闭 / `60` / `30` | curl adapter 的 TCP keepalive 参数。 |
| `http_client` | 由构建选项决定 | 自定义 HTTP client。`do_request` 返回 transport failure 时必须显式设置 `response.transport_retryable`；`0` 表示终态不可重试，非零表示允许重放。该合同对 generic/curl transport 一致。真实网络发送通常使用 curl adapter。 |

## 回调与重试

| 字段 | 说明 |
| --- | --- |
| `metrics_sink` | SDK 事件输出回调。 |
| `retry_max_attempts` | 批次重试次数上限。 |
| `retry_policy` | 单请求退避、总耗时和尝试次数策略。 |

HTTP `429`、`500`、`502`、`503`、`504` 属于可重试状态。`401/403` 会分类为
authentication failure；Persistent 模式下是否保留由
`persistent_auth_failure_policy` 决定。

## Persistent

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `use_persistent` | `0` | 设为 `1` 开启本地持久化。 |
| `persistent_file_path` | 无 | Persistent 目录。开启后必填，建议每个 Producer 使用独立目录。 |
| `max_persistent_file_size` | 必填 | 单个 segment 文件大小上限，常用 `1..10 MiB`。 |
| `max_persistent_file_count` | 必填 | segment 文件数量上限。 |
| `max_persistent_log_count` | 必填 | 单个 segment 最大记录数。 |
| `persistent_max_bytes` | 文件大小乘文件数 | 本地持久化总字节上限。 |
| `persistent_max_records` | `max_persistent_log_count` | 本地持久化总记录上限。 |
| `persistent_max_segments` | `max_persistent_file_count` | segment 总数上限。 |
| `persistent_high_watermark_pct` | `85` | bytes、records、segments 任一已配置维度达到该比例时，触发已 ack closed segment 回收。 |
| `persistent_low_watermark_pct` | `70` | 压力回收持续到所有已配置维度都不高于该比例，或没有可回收 segment。必须满足 `0 < low < high <= 100`。 |
| `persistent_overflow_policy` | `VE_TLS_POVERFLOW_REJECT_NEW` | 空间不足时拒绝新日志、阻塞、丢最老未 ack segment 或采样丢弃新日志。 |
| `persistent_sample_every_n` | `10` | `DROP_NEWEST_SAMPLE` 策略下的采样间隔。 |
| `persistent_block_timeout_ms` | `1000` | `BLOCK` 策略下等待可用空间的最长时间。 |
| `persistent_lease_timeout_ms` | `60000` | owner stale 判定时间。 |
| `persistent_heartbeat_interval_ms` | `10000` | owner lease 心跳间隔。 |
| `persistent_open_mode` | `VE_TLS_POPEN_TAKEOVER_IF_STALE` | `FAIL_IF_OWNED` 会在目录被占用时失败；`TAKEOVER_IF_STALE` 允许 stale 后接管。 |
| `persistent_durability` | `VE_TLS_PDURABILITY_DEFAULT` | 默认解析为 `BUFFERED_WAL`；也可显式选择 `BUFFERED_WAL` 或 `SYNC_WAL`。 |
| `force_flush_disk` | `0` | 兼容字段。durability 为 `DEFAULT` 且该值非零时映射为 `SYNC_WAL`；与显式 `BUFFERED_WAL` 同时设置会拒绝创建。 |
| `persistent_max_log_delay_ms` | `0` | recover 时的最大记录年龄；`0` 表示关闭，负值是非法配置。只有 WAL 中 `enqueue_time_ms > 0` 的记录才参与判断。 |
| `persistent_expired_log_policy` | `VE_TLS_PEXPIRED_REWRITE` | 超龄记录重写为当前恢复时间后发送，或显式 `DROP` 并推进 checkpoint。字段只在 max delay 开启时生效。 |
| `persistent_auth_failure_policy` | `VE_TLS_PAUTH_RETAIN` | `401/403` 或凭证刷新失败达到本轮终态时保留 WAL；只有显式 `DROP` 才推进对应 checkpoint。 |

`persistent_durability` 属于 version 1 尾部；三个 max-age/auth 字段属于 version 2
尾部。使用这些字段时必须配对调用 `ve_tls_config_init_versioned` 和
`ve_tls_producer_create_versioned`，并传对应版本的精确 size。旧 init/create 只消费
`VE_TLS_CONFIG_LEGACY_SIZE`，继续通过 `force_flush_disk` 保留原有 sync-WAL 映射。

Core 默认不启用 max-age。需要与 SLS iOS 行为对齐的语言层可以显式配置 7 天并选择
`VE_TLS_PEXPIRED_REWRITE`，但该语言层默认不应反向改变 C Core 和其他 SDK 的兼容默认。

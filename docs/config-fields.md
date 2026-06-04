# 配置字段清单

本文档按 profile 列出当前分支的公开配置面：

- Full Producer：`ve_tls_config`，提供异步写入、聚合、发送、重试、背压、metrics 和回调。
- Bricks tiny core：`ve_tls_bricks_config`，只配置 request packing；transport、retry、队列和观测由调用方负责。

## 目标与鉴权

Full Producer 字段：

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

Bricks 字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `endpoint` | 是 | 生成 `{endpoint}/PutLogs?TopicId=...` |
| `region` | 是 | TLS V4 signing scope |
| `topic_id` | 是 | query 中的 `TopicId` |
| `api_version` | 否 | `x-tls-apiversion`，为空使用 SDK 默认版本 |
| `access_key_id` / `access_key_secret` | 是 | 静态 AK/SK |
| `security_token` | 否 | 临时凭证 token；Bricks 不负责刷新 |
| `hash_key` | 否 | `x-tls-hashkey`，空值也参与签名 |
| `xdate` | 否 | 固定 `X-Date`，用于测试或调用方自管时间 |

Bricks 没有 `project_id`、`source`、`file_name`、`log_tags`、`context_flow` 配置字段。这些 LogGroup 属性如果需要，应在调用 `ve_tls_proto_encode_log_group_list*()` 时传入，或由调用方自己编码 protobuf。

## 聚合与发送

Full Producer 字段：

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

Bricks 字段和入参：

| 字段/入参 | 说明 |
| --- | --- |
| `compress_type` | `none` / `lz4` / `zlib`；Bricks LZ4/ZLIB 需要独立 CMake 开启 |
| `body_no_copy` | `compress_type=none` 时允许返回 body 借用调用方 buffer |
| `raw_log_group_list` / `raw_log_group_list_size` | 已编码 LogGroupList body |
| `log_count` | 写入 `log-count` header |
| `earliest_log_time_ms` | 写入 `earliest-log-time` header |
| `latest_log_time_ms` | 写入 `latest-log-time` header |

Bricks 没有聚合线程、flush interval、send queue 或 ordered send。调用方如果要合批，需要在调用 Bricks 之前完成 protobuf 聚合。

## 资源与背压

Full Producer 字段：

- `max_buffer_bytes`
- `buffer_full_policy`
- `buffer_full_block_timeout_ms`
- `send_queue_size`
- `send_queue_full_policy`
- `send_queue_block_timeout_ms`
- `send_queue_sample_every_n`

Full Producer 运行期默认值派生规则：

- 如果 `log_bytes_per_package` 仍是初始化默认值，`max_buffer_bytes <= 64MB` 时派生为 `2MB`，否则派生为 `4MB`。
- 如果 `send_thread_count` 仍是初始化默认值，`<=64MB` 派生为 `2`，`<=256MB` 派生为 `4`，更大派生为 `8`。
- 如果 `pack_thread_count` 仍是初始化默认值，跟随 `send_thread_count`。
- 如果 `send_queue_size` 仍是初始化默认值，派生为 `8 + max_buffer_bytes/log_bytes_per_package`，范围限制在 `8..128`。
- 显式配置过的字段不会被派生默认值覆盖。

Bricks 没有资源预算或背压配置。它每次调用只为 URL、headers、签名中间结果和可选 body copy/压缩分配内存。调用方负责：

- 限制单次 protobuf body 大小
- 控制并发 pack 和发送数量
- 决定队列满时 drop、block 还是落盘
- 在 no-copy body 模式下管理 buffer 生命周期

## 限流与熔断

Full Producer 字段：

- `rate_limit_rps`
- `rate_limit_bps`
- `breaker_fail_threshold`
- `breaker_open_ms`
- `breaker_half_open_max_inflight`
- `breaker_ingress_policy`
- `key_queue_max_active`
- `key_queue_bucket_count`
- `key_queue_idle_ttl_ms`
- `key_rate_limit_rps`
- `key_rate_limit_bps`
- `key_breaker_fail_threshold`
- `key_breaker_open_ms`

`breaker_ingress_policy` 只影响全局 breaker open 后的写入入口：

| 值 | 写入侧行为 |
| --- | --- |
| `VE_TLS_BREAKER_INGRESS_ALLOW` | 继续接收入队，保持历史默认行为 |
| `VE_TLS_BREAKER_INGRESS_FAIL_FAST` | 不入队，写入接口返回 `VE_TLS_DROP_ERROR` |
| `VE_TLS_BREAKER_INGRESS_DROP_WITH_CALLBACK` | 不入队，写入接口返回 `VE_TLS_DROP_ERROR`，并触发 `send_done_v2` 丢弃回调 |

Bricks 不实现限流或熔断。真实接入中应在调用方 transport 层按 endpoint、topic、hash key 或业务队列维度实现。

## 网络与 TLS

Full Producer 字段：

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

Bricks core 没有网络字段。`ve_tls_bricks_demo_real` 的 libcurl 行为仅是样例，支持：

- `--count N`
- `--timeout-ms N`
- `--quiet`
- 环境变量 `VE_TLS_ENDPOINT`、`VE_TLS_REGION`、`VE_TLS_TOPIC_ID`、`VE_TLS_ACCESS_KEY_ID`、`VE_TLS_ACCESS_KEY_SECRET`
- 可选环境变量 `VE_TLS_SECURITY_TOKEN`、`VE_TLS_COMPRESS_TYPE`、`VE_TLS_HASH_KEY`、`VE_TLS_HTTP_DEBUG`

调用方 transport 必须保留 Bricks 输出的所有签名头，包括空值 `x-tls-hashkey`。

## 回调与重试

Full Producer 字段：

- `metrics_sink`
- `retry_max_attempts`
- `retry_policy`
- `callback_from_sender_thread`

Bricks 不提供回调或 retry policy。`ve_tls_bricks_pack_request()` 返回 `int`：

- `0`：pack 成功
- `-1`：参数、内存或内部构造失败
- `-3`：请求了未编译或未知的压缩类型

HTTP code、request id、服务端错误体、网络错误和重试状态都由调用方 transport 产生和记录。

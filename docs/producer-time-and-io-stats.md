# Producer 时间字段与 IO 统计头使用说明

本文面向使用方说明 ve-tls C Producer 的时间字段（`time`/`timeNs`）与 IO 统计头（`log-count`/`earliest-log-time`/`latest-log-time`）的语义、推荐用法与边界限制。

## 时间字段语义（time / timeNs）

### 1) KV API：推荐使用 time parts 接口

Producer 支持两类写入：KV（由 SDK 负责编码 protobuf）与 raw（用户直接传入 bytes）。只有 KV 写入可以由 SDK 完整掌控 `time`/`timeNs` 的写入逻辑。

推荐使用以下接口显式表达时间字段：

- `ve_tls_producer_add_log_kv_time_parts(producer, time_ms, has_time_ns, time_ns, kvs, kv_count, flush)`
- `ve_tls_producer_add_log_kv_time_parts_hashkey(producer, time_ms, has_time_ns, time_ns, hash_key, kvs, kv_count, flush)`

字段解释：

- `time_ms`：日志毫秒时间戳。
- `has_time_ns`：是否写入 `timeNs` 字段（0/1）。
- `time_ns`：毫秒之后的剩余纳秒部分（`0..999999` 是推荐范围），当 `has_time_ns=1` 时写入 protobuf 的 `timeNs`。

语义约束：

- 当 `time_ms > 0`：
  - `has_time_ns=1` 时，SDK **不对 `time_ns` 进行归一化/夹逼/取模**，用户传什么就写什么。
  - `has_time_ns=0` 时，SDK 不写入 `timeNs`。
- 当 `time_ms <= 0`（用户未传 time）：
  - SDK 自动生成 `time_ms`。
  - 默认不写入 `timeNs`；如果开启了 `enable_time_ns`（见下文），SDK 会根据自身时间写入 `timeNs`。

### 2) enable_time_ns：仅影响“用户未传 time”的自动填充

`ve_tls_config.enable_time_ns` 默认关闭（0）。

开启后，仅当用户未传 `time_ms` 时（`time_ms <= 0`），SDK 才会尝试自动填充：

- `time_ms`：来自 `config.platform.time_ms()`
- `timeNs`：来自 `config.platform.time_unix_ns()` 的剩余纳秒部分（`unix_ns % 1_000_000`）

注意：

- 若平台未实现 `time_unix_ns`（为 NULL），则不会自动填充 `timeNs`，仍只填充 `time_ms`。
- 自动填充只用于“缺省时间”的场景；用户显式传入 `time_ms` 时，不会覆盖用户输入。

### 3) raw 写入：必须显式提供时间，否则统计信息不可用

raw 写入表示用户直接传入日志 bytes，SDK 无法从 bytes 中可靠解析 `time/timeNs`。

因此：

- 若你希望服务端使用 `earliest-log-time/latest-log-time` 做索引重建、时间范围消费等能力，raw 写入必须显式提供时间元信息。
- 推荐使用：
  - `ve_tls_producer_add_log_raw_time_parts(producer, time_ms, has_time_ns, time_ns, log_buf, log_size, flush)`

若使用 `ve_tls_producer_add_log_raw(...)` 且不提供时间元信息，则该条日志的时间统计将不可推导，可能导致 IO 统计头无法反映真实时间范围。

## IO 统计头（PutLogs）

Producer 在发送 PutLogs 请求时默认携带以下统计头，用于服务端无需解包 LogGroupList 即可完成 IO 写入与索引辅助信息采集：

- `log-count`：本次请求包含的日志条数
- `earliest-log-time`：本次请求中最早的日志毫秒时间戳
- `latest-log-time`：本次请求中最晚的日志毫秒时间戳

### 统计值来源与性能保证

- 统计值在 producer 阶段维护：worker/manager 在遍历队列项时计算统计信息，并写入 send task；sender 发送时直接写 header。
- PutLogs 阶段不会再次遍历/解包 LogGroupList 来计算统计信息，避免重复扫描带来的 CPU 开销。

### 边界与限制

- KV 写入：SDK 可以保证 `log-count/earliest/latest` 的正确性（当 `time_ms` 缺省时也会自动填充）。
- raw 写入：
  - 使用 `*_raw_time_parts` 可以保证统计正确。
  - 使用 `*_raw` 且不提供时间：`earliest/latest` 无法可靠维护，可能影响服务端索引重建、按时间范围消费等能力。

## 示例

### KV：显式 time + timeNs（不归一化）

```c
ve_tls_kv kvs[1] = {{"k","v"}};
// time_ms=1710000000000, has_time_ns=1, time_ns=123456（原样写入）
ve_tls_producer_add_log_kv_time_parts(p, 1710000000000LL, 1, 123456, kvs, 1, 1);
```

### KV：不传 time，开启 enable_time_ns 让 SDK 自动补齐

```c
ve_tls_config cfg;
ve_tls_config_init(&cfg);
cfg.enable_time_ns = 1;
// 其它字段省略
```

```c
ve_tls_kv kvs[1] = {{"k","v"}};
// time_ms<=0 表示用户未传 time，SDK 会自动填 time_ms；enable_time_ns=1 时也会自动填 timeNs
ve_tls_producer_add_log_kv_time_parts(p, 0, 0, 0, kvs, 1, 1);
```

### raw：必须传 time parts 才能维护 IO 统计头

```c
const char * raw = "..."; // 用户自定义 bytes
ve_tls_producer_add_log_raw_time_parts(p, 1710000000000LL, 0, 0, raw, strlen(raw), 1);
```


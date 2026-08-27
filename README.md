# ve-tls-c-sdk

ve-tls-c-sdk 是纯 C 的 TLS 日志 Producer。它适合 Linux 服务器、嵌入式 Linux，以及通过 JNI/FFI 接入的 Native 应用。SDK 负责日志编码、聚合、压缩、签名和 HTTPS 发送；开启 Persistent 模式后，待发送日志会先写入本地文件，进程重启后可以继续补发。

## 主要能力

- 异步写入：业务线程调用 `add_log` 后只进入本地队列，不直接做网络 I/O。队列满时可以选择丢弃、阻塞或采样丢弃。
- 批量聚合：按日志条数、日志字节数和 flush 时间窗口打包，减少请求数。`log_count_per_package`、`log_bytes_per_package`、`flush_interval_ms` 都可以配置。
- 压缩发送：支持 `lz4`、`zlib` 和 `none`，默认使用 `lz4`。如果部署环境不需要 zlib，可以在构建时关闭。
- 失败重试：可配置最大重试次数、退避策略、全局限流、key 级限流和熔断。
- HashKey：调用级 hashKey 优先于 `cfg.hash_key`。需要同一 hashKey 在客户端侧串行发送时，建议显式设置 `send_thread_count=1`；多 sender 配置优先资源利用，不承诺严格串行。
- 动态凭证：支持静态 AK/SK，也支持 `credentials_provider` 动态刷新临时凭证。
- 运行期更新：支持更新 endpoint、region、topic 和静态凭证。已经进入发送路径的请求可能仍使用旧快照，后续请求会切到新配置。
- 多 Producer 资源共享：同一进程内多个 Producer 可以通过 `ve_tls_env_init()` 和 `cfg.use_global_env=1` 共享 sender 线程。
- 连接复用：启用 curl 后，每个 sender 线程复用自己的 curl easy handle，从而复用同线程上的连接。SDK 当前不做跨线程全局连接池；如果同进程有多个 Producer，优先用共享 sender 控制连接数。
- Persistent 模式：支持 append-before-send、重启 recover、checkpoint、segment 回收、lease 和 stale takeover。语义是 at-least-once，不是 exactly-once。
- 观测：提供累计 metrics、metrics sink、发送完成回调和结构化错误信息，便于定位失败类型、请求 ID、HTTP 状态码和可重试性。

## 构建

真实网络发送需要开启 curl：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j
```

默认构建包含 `lz4` 和 `zlib`。如果只需要 `lz4` 和不压缩发送，可以关闭 zlib：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DVE_TLS_ENABLE_CURL=ON \
  -DVE_TLS_ENABLE_ZLIB=OFF
cmake --build build -j
```

常用目录：

```text
core/      C API、Producer、队列、发送、persistent 核心逻辑
adapters/  HTTP、压缩、平台适配
bindings/  平台绑定
tests/     单元测试和集成测试
tools/     demo、benchmark 和构建脚本
```

## 最小示例

```c
#include "ve_tls_producer.h"

int main(void) {
    ve_tls_config cfg;
    ve_tls_config_init(&cfg);
    cfg.endpoint = "https://tls-cn-beijing.volces.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "your-topic-id";
    cfg.access_key_id = "your-ak";
    cfg.access_key_secret = "your-sk";

    ve_tls_producer * producer = ve_tls_producer_create(&cfg);
    if (!producer) {
        return 1;
    }

    ve_tls_kv kvs[2];
    kvs[0].key = "event";
    kvs[0].value = "login";
    kvs[1].key = "status";
    kvs[1].value = "ok";

    ve_tls_result add_rc = ve_tls_producer_add_log_kv(producer, 0, kvs, 2, 1);
    ve_tls_result close_rc = ve_tls_producer_close(producer, 3000);
    ve_tls_producer_destroy(producer);

    return add_rc == VE_TLS_OK && close_rc == VE_TLS_OK ? 0 : 2;
}
```

`time_ms=0` 时由 SDK 使用当前时间。需要纳秒字段时，设置 `enable_time_ns=1`，并使用 `*_time_parts` 或 template API 写入 `timeNs`。

## 真实发送 demo

仓库内有三个常用入口：

- `tools/demo.c`：基于 Producer API 的最小异步发送 demo。
- `tools/putlogs_demo.c`：直调 `/PutLogs` 的最小 demo，适合看 protobuf、签名和 HTTP 发送流程。
- `tools/real_demo.c`：支持环境变量或配置文件，适合在真实环境做小规模验证。

运行前设置必要参数：

```bash
export VE_TLS_ENDPOINT=https://tls-cn-beijing.volces.com
export VE_TLS_REGION=cn-beijing
export VE_TLS_TOPIC_ID=your-topic-id
export VE_TLS_ACCESS_KEY_ID=your-ak
export VE_TLS_ACCESS_KEY_SECRET=your-sk

./build/ve_tls_demo
```

也可以复制模板后用配置文件运行：

```bash
cp tools/real_demo_perf.env.template .local/config/real_demo.env
./build/ve_tls_demo_real --config .local/config/real_demo.env --count 10 --wait-ms 15000
```

不要把真实 AK/SK 提交到仓库。`.local/` 已经在 `.gitignore` 中。

## Persistent 模式

Persistent 适合进程崩溃、异常退出、短时网络失败后仍要补发的场景。开启后，SDK 会先把日志 append 到本地 segment，再进入发送队列。重启后需要先调用 `ve_tls_producer_recover()`，再写入新日志。

```c
ve_tls_config cfg;
ve_tls_config_init(&cfg);
cfg.endpoint = "https://tls-cn-beijing.volces.com";
cfg.region = "cn-beijing";
cfg.topic_id = "your-topic-id";
cfg.access_key_id = "your-ak";
cfg.access_key_secret = "your-sk";

cfg.use_persistent = 1;
cfg.persistent_file_path = "/var/lib/ve-tls/producer-a";
cfg.max_persistent_file_size = 8 * 1024 * 1024;
cfg.max_persistent_file_count = 32;
cfg.max_persistent_log_count = 200000;
cfg.persistent_max_records = 200000;
cfg.persistent_max_segments = 32;
cfg.persistent_overflow_policy = VE_TLS_POVERFLOW_REJECT_NEW;
cfg.persistent_open_mode = VE_TLS_POPEN_TAKEOVER_IF_STALE;
cfg.send_thread_count = 1;

ve_tls_producer * producer = ve_tls_producer_create(&cfg);
if (!producer) {
    return 1;
}

if (ve_tls_producer_recover(producer) != VE_TLS_OK) {
    ve_tls_producer_destroy(producer);
    return 2;
}

/* recover 完成后再 add_log */
```

Persistent 的可靠性边界需要说清楚：

- SDK 提供 at-least-once。崩溃、重试和 checkpoint 持久化边界可能产生少量重复；如果业务不能接受重复，需要用业务主键或消费侧去重。
- at-least-once 只覆盖已经成功进入 persistent 的日志。如果 `add_log` 因参数错误、内存背压或 persistent quota 返回失败，这条日志不在恢复范围内。
- `success callback` 表示请求进入成功路径，不等于 checkpoint 已经 durable 落盘。崩溃发生在两者之间时，recover 可能重放边界内日志。
- persistent 默认使用 buffered WAL，在 segment rotation、显式 flush 和正常 close 时同步；`force_flush_disk=1` 兼容映射为每条 append 同步的 sync WAL。新接入显式配置 `persistent_durability` 时，必须配对使用 `ve_tls_config_init_versioned` 与 `ve_tls_producer_create_versioned`。
- lease 用于避免多个活跃 owner 同时写一个目录。`TAKEOVER_IF_STALE` 适合崩溃恢复，不适合多个活跃进程共享同一路径。
- `DROP_OLDEST_UNACKED` 会牺牲完整性，只适合明确要保新丢旧的场景。

推荐做法：

- 每个 Producer 或进程使用独立 `persistent_file_path`。
- 进程启动后先创建 Producer，再调用 `ve_tls_producer_recover()`，然后才开始写新日志。
- 资源或问题定界优先时，把 `send_thread_count` 固定为 `1`；需要更高发送并发时再显式调大。
- 把 persistent 目录放到可用空间受控的路径，并配置 `persistent_max_bytes`、`persistent_max_records`、`persistent_max_segments`。
- 关闭时先停止业务侧写入，再调用 `ve_tls_producer_close()`。超时后再 destroy，避免无意义等待。

## 关键配置

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `request_timeout_ms` | `50000` | 单次 HTTP 请求超时。真实网络环境建议保留足够长的超时，再用重试和背压控制总延迟。 |
| `connect_timeout_ms` | `10000` | 建连超时。网络不稳定或跨地域访问时可以调大。 |
| `max_buffer_bytes` | `64 MiB` | Producer 主要内存预算。内存队列、发送队列、导入 raw buffer 和压缩临时内存都会受这个预算约束。 |
| `send_thread_count` | 按内存预算派生 | sender 线程数。多线程可提高并发，但也会增加连接数和内存压力。 |
| `pack_thread_count` | 跟随 sender | 打包线程数。未显式设置时跟随 `send_thread_count`。 |
| `send_queue_size` | 按包大小和内存预算派生 | 已打包待发送队列长度。真实环境不要只调大队列，先确认服务端配额、网络延迟和 close 等待时间。 |
| `send_queue_full_policy` | `BLOCK` | 发送队列满时的策略：阻塞、丢弃或采样丢弃。 |
| `buffer_full_policy` | `DROP` | 内存预算不足时的策略。对丢失敏感的业务可改为 `BLOCK`，同时设置阻塞超时。 |
| `log_count_per_package` | 按预算派生 | 单包日志条数上限。小日志可调大，大日志应受 `log_bytes_per_package` 控制。 |
| `log_bytes_per_package` | 按预算派生 | 单包原始字节上限。需要结合服务端限制和内存预算设置。 |
| `flush_interval_ms` | `3000` | 最长聚合等待时间。低延迟场景可以调小，但请求数会增加。 |
| `compress_type` | `lz4` | 支持 `lz4`、`zlib`、`none`。 |
| `tcp_keepalive` | `0` | 设为 `1` 后通过 curl 开启 TCP keepalive，可配 `tcp_keepidle` 和 `tcp_keepintvl`。 |
| `use_global_env` | `0` | 多 Producer 共享 sender 时设为 `1`，并在进程启动时调用 `ve_tls_env_init()`。 |

Persistent 相关配置：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `use_persistent` | `0` | 设为 `1` 开启本地持久化。 |
| `persistent_file_path` | 无 | 开启 persistent 后必填。建议每个 Producer 独立目录。 |
| `max_persistent_file_size` | 必填 | 单个 segment 文件大小上限，常用 `1-10 MiB`。 |
| `max_persistent_file_count` | 必填 | segment 文件数量上限。 |
| `max_persistent_log_count` | 必填 | 单个 segment 最大记录数。 |
| `persistent_max_bytes` | 文件大小乘文件数 | persistent 总字节上限。 |
| `persistent_max_records` | `max_persistent_log_count` | persistent 总记录上限。需要缓存更多日志时显式调大。 |
| `persistent_max_segments` | `max_persistent_file_count` | segment 总数上限。 |
| `persistent_high_watermark_pct` | `85` | bytes、records、segments 任一维度达到该比例时触发安全回收。 |
| `persistent_low_watermark_pct` | `70` | 所有维度回落到该比例后停止压力回收；要求 `0 < low < high <= 100`。 |
| `persistent_overflow_policy` | `VE_TLS_POVERFLOW_REJECT_NEW` | 空间不足时拒绝新日志、阻塞、丢最老未 ack segment 或采样丢弃新日志。 |
| `persistent_block_timeout_ms` | `1000` | `BLOCK` 策略下等待可用空间的最长时间。 |
| `persistent_lease_timeout_ms` | `60000` | owner stale 判定时间。 |
| `persistent_heartbeat_interval_ms` | `10000` | owner lease 心跳间隔。 |
| `persistent_open_mode` | `VE_TLS_POPEN_TAKEOVER_IF_STALE` | owned 目录的打开策略。 |

## 多 Producer 示例

同一进程内创建多个 Producer 时，不要让每个实例都独占一组 sender 线程。可以先初始化全局 Env：

```c
if (ve_tls_env_init(2) != VE_TLS_OK) {
    return 1;
}

ve_tls_config cfg;
ve_tls_config_init(&cfg);
cfg.endpoint = "https://tls-cn-beijing.volces.com";
cfg.region = "cn-beijing";
cfg.topic_id = "your-topic-id";
cfg.access_key_id = "your-ak";
cfg.access_key_secret = "your-sk";
cfg.use_global_env = 1;

ve_tls_producer * p1 = ve_tls_producer_create(&cfg);
ve_tls_producer * p2 = ve_tls_producer_create(&cfg);

/* add_log / close / destroy */

ve_tls_producer_destroy(p1);
ve_tls_producer_destroy(p2);
ve_tls_env_destroy(3000);
```

## 性能与资源测试

本地发送路径 benchmark：

```bash
./build/ve_tls_perf_tls --mode curl \
  --config .local/config/real_demo.env \
  --duration-s 30 \
  --rate-lps 10000 \
  --writers 4 \
  --profile tls700
```

`ve_tls_perf_tls` 会输出 `enq_lps`、`us_per_log`、`raw_kb_s`、`cpu_cores`、`cpu_pct_total`、`rss_mb`、`requests`、`dropped` 等字段。看资源时优先看 `cpu_cores` 和 `rss_mb`，不要只看单次发送成功量。

Persistent 真实发送 benchmark：

```bash
/usr/bin/time -v ./build/ve_tls_persistent_real_bench \
  --config .local/config/real_demo.env \
  --mode steady \
  --write-mode kv \
  --profile tls700 \
  --duration-s 30 \
  --rate-lps 10000 \
  --report-interval-s 1 \
  --wait-ms 120000
```

常用压测组合：

```bash
for profile in tls700 tls5120; do
  for rate in 10000 30000 50000; do
    /usr/bin/time -v ./build/ve_tls_persistent_real_bench \
      --config .local/config/real_demo.env \
      --mode steady \
      --write-mode kv \
      --profile "$profile" \
      --duration-s 30 \
      --rate-lps "$rate" \
      --report-interval-s 1 \
      --wait-ms 120000
  done
done
```

结果解读：

- `add_fail` 增长：本地参数、内存背压或 persistent quota 已经限制写入。
- `success` 明显落后于 `add_ok`：发送路径、网络或远端处理速度跟不上写入。
- `current_records/current_bytes` 持续增长：persistent backlog 正在堆积。
- `acked_log_id` 长时间不前进：请求没有成功 ack，先查回调里的错误码、HTTP 状态和 retryable。
- `time -v` 的 `Maximum resident set size` 是进程最大 RSS，适合和 `max_buffer_bytes` 一起看。

## 更多文档

- [配置字段](docs/config-fields.md)：公开配置、默认值和 persistent 字段。
- [Persistent 模式](docs/persistent.md)：本地持久化、recover、checkpoint、lease 和重复边界。
- [调优与性能测试](docs/tuning.md)：内存、磁盘、线程、队列和 benchmark。
- [错误模型](docs/error-model.md)：发送回调、错误字段和 persistent 失败分类。
- [重试策略](docs/retry-policy.md)：请求重试、批次重试和 recover 重放关系。
- [指标与观测](docs/metrics.md)：metrics、回调和资源压力排查。
- [签名与鉴权](docs/signing.md)：凭证、签名输入和常见签名问题。
- [安全规范](docs/security.md)：凭证脱敏、TLS 校验和 persistent 目录安全。
- [架构图源文件](docs/diagrams/architecture.mmd)：persistent 链路的 Mermaid 源文件。

## 测试

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

如果只改 persistent 相关逻辑，至少跑 `ve_tls_test_basic` 和 `ve_tls_test_android_binding`。如果改 HTTP、签名或压缩路径，还需要跑真实发送 demo。

## 安全

如果发现安全问题，请不要创建公开 Issue。报告方式见 [SECURITY.md](SECURITY.md)。

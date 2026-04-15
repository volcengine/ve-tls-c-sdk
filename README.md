# ve-tls-c-sdk

TLS C Producer（纯 C 实现）是面向 **Linux 服务器 / 嵌入式 / 多端 Native** 的日志采集客户端核心库，提供更精简的环境依赖、更低的资源占用与更可控的吞吐/背压治理能力，用于将日志通过网络发送到 TLS 服务端。

## 功能特点

- 异步写入
  - 写入侧仅入内存队列，不阻塞业务线程（除非你选择阻塞背压策略）
- 聚合与压缩上传
  - 支持按超时时间、日志条数、日志字节数聚合发送
  - 支持 `lz4`/`zlib`（按编译能力自动选择默认压缩）
- HashKey 有序与多 key 并发
  - 同一 hashKey 严格有序
  - 不同 hashKey 并发发送提升吞吐
- 背压与队列保护
  - 有界 send_queue，支持 `DROP/BLOCK/DROP_SAMPLED`
  - key_queue 保护与限流/熔断，避免热点与故障扩散
- 重试、限流、熔断
  - 可配置重试策略、全局与 key 级别的 token bucket 限流与 breaker 熔断
- 观测与诊断
  - 结构化错误回调（含 http_code/request_id/error_code/retryable）
  - 内置累计 metrics + 可插拔 metrics_sink 事件流
- 鉴权
  - 支持静态 AK/SK
  - 支持 STS/临时凭证（credentials_provider 动态刷新）
- Agent 与 IO 统计头
  - 默认携带 `User-Agent: volc-tls-c/producer/v<version>`
  - PutLogs 固定携带 IO 统计头（rawsize/compresstype/log-count/earliest/latest/apiversion），减少服务端解析成本

## 功能优势

- 低依赖：核心库可在不同平台通过 adapter 层裁剪；启用真实网络需 `libcurl`（可通过开关控制）
- 低资源占用：核心逻辑以队列与异步线程为主，避免业务线程与网络 I/O 强耦合
- 易接入：稳定 C API，适合 JNI/FFI，多端复用一套核心逻辑
- 可控退出：提供优雅退出与强制退出两种关闭语义，便于生产环境稳定停机

## 分支选择
| 分支 | 状态 | 功能优势 | 建议使用场景 |
| --- | --- | --- | --- |
| master | 可用 | 低依赖、高性能、资源占用小 | Linux 服务器、嵌入式 Linux |
| live | 可用 | 功能与 master 等价，支持更多平台 | Windows、Mac、Android、iOS |
| bricks | 可用 | 极致精简、体积极小 | 资源极小场景，例如 RTOS |
| persistent | 可用 | 在 master 基础上增加落盘缓存，限制单线程发送 | Android、iOS |

## 目录结构
```
core/          核心能力
adapters/      平台适配层
bindings/      平台绑定
tests/         测试
tools/         工具与脚本
docs/          文档
```

## 安装与构建

### 依赖

- 启用真实网络发送：需要 `libcurl`
- 压缩（可选）：`lz4` 或 `zlib`

### 构建（CMake）

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

真实环境建议开启 curl（否则 http client 为空实现，无法发往真实环境）：

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build
```

## 使用

### 最小接入示例

```c
ve_tls_config cfg;
ve_tls_config_init(&cfg);
cfg.endpoint = "https://tls-cn-beijing.volces.com";
cfg.region = "cn-beijing";
cfg.topic_id = "your-topic-id";
cfg.access_key_id = "your-ak";
cfg.access_key_secret = "your-sk";

ve_tls_producer * p = ve_tls_producer_create(&cfg);
if (!p) {
  return 1;
}

ve_tls_kv kvs[1];
kvs[0].key = "k";
kvs[0].value = "v";
(void)ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1);

ve_tls_result rc = ve_tls_producer_close(p, 3000);
ve_tls_producer_destroy(p);
return rc == VE_TLS_OK ? 0 : 2;
```

### 多 Producer 场景（共享 sender 线程池）

当同一进程需要创建多个 Producer（例如按 Source/Topic 隔离），建议初始化全局 Env，并让 Producer 选择使用共享 sender。

```c
ve_tls_result erc = ve_tls_env_init(2);
if (erc != VE_TLS_OK) {
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

// ... 写入与 close/destroy

ve_tls_producer_destroy(p1);
ve_tls_producer_destroy(p2);
(void)ve_tls_env_destroy(3000);
```

### 时间字段与 IO 统计头说明

`time/timeNs` 与 `log-count/earliest-log-time/latest-log-time` 的语义、推荐用法与 raw 写入边界见：

- [producer-time-and-io-stats.md](file:///Users/bytedance/workspace/src/sdk/volcengine-sdk/ve-tls-android-sdk/ve-tls-c-sdk/docs/producer-time-and-io-stats.md)

### 真实环境 Demo

- 可执行 demo：`tools/real_demo.c`
- 可执行真实环境 persistent benchmark：`tools/persistent_real_bench.c`
- 支持通过环境变量或配置文件注入参数：`tools/real_demo.env`
- persistent 真实环境完整性验证脚本：`tools/persistent_real_validation.sh`
- 服务端结果查询脚本：`tools/tls_search_logs.go`（依赖本地 `volc-sdk-golang` checkout）

示例：

``` 
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build
./build/ve_tls_demo_real --config tools/real_demo.env --duration-s 60 --wait-ms 3000
./build/ve_tls_persistent_real_bench --config tools/real_demo.env --mode steady --write-mode kv --profile tls700 --duration-s 30 --rate-lps 0 --report-interval-s 1 --wait-ms 120000
```

其中 `ve_tls_persistent_real_bench` 是适合直接部署到真实环境机器上跑的单个二进制：

- `--mode steady`：真实环境直发，测 persistent 开启后的 steady-state 吞吐
- `--mode recover`：对已有 persistent 路径做 recover 回灌，测 backlog drain 吞吐
- `--write-mode kv|raw`：`kv` 更贴近真实业务，`raw` 在这个二进制里走单字段模板快路径，更适合测 producer/persistent 极限
- `--profile tls200|tls700|tls5120|custom`：固定日志模板；`custom` 时可配 `--message-bytes`
- `--rate-lps 0`：表示不做节流，直接压满发送路径
- `--report-interval-s 1`：每秒输出一次实时速率与 backlog
- persistent 模式下会强制 `send_thread_count=1`；如果配置文件里写了更大的值，二进制会打印收敛结果
- 输出包括：
  - `PERSISTENT_REAL_PROGRESS ...`：实时窗口速率与 backlog，包含 `phase=steady|recover|drain`、窗口 `enqueue_lps/success_lps`、累计 `enqueue_lps_avg/success_lps_avg`、`buffered_bytes`、`acked_log_id`、`active_segment_id`、`current_segments/current_records/current_bytes`
  - `PERSISTENT_REAL_BENCH ...`：最终汇总结果

判断瓶颈时可直接看：

- `enqueue_lps` 低，且 `buffered_bytes` 不增长：更像 producer/persistent 本地链路先卡住
- `enqueue_lps` 高、`success_lps` 低，且 `buffered_bytes` 持续增长：更像网络或服务端吞吐先卡住
- `phase=drain` 持续输出，但 `acked_log_id` 不前进：说明 close 后仍在排空，但服务端 ack 没回来
- `current_segments/current_bytes` 长时间不下降且 `acked_log_id` 落后很多：说明还没 ack 到可回收区间，`seg` 不会被删

持久化/断点续传真实环境验证：

```
export GO_SDK_ROOT=/path/to/volc-sdk-golang
/bin/zsh tools/persistent_real_validation.sh
```

真实环境 benchmark：

```
export GO_SDK_ROOT=/path/to/volc-sdk-golang
/bin/zsh tools/persistent_real_bench.sh --mode steady --rates 1000,2000,5000 --duration-s 15
/bin/zsh tools/persistent_real_bench.sh --mode recover --recover-records 5000,20000
```

默认会编排这些场景：

- baseline：正常发送与重复 recover 不重放
- crash_before_send：入盘后、发送前崩溃，重启 recover 后补齐
- partial_send_then_crash：部分发送成功后崩溃，重启 recover 后补齐
- timeout_then_recover：网络失败/超时后崩溃，重启 recover 后补齐
- terminal_auth_drop：鉴权终态失败后不重放
- quota_reject_new：用 persistent quota 打满模拟本地持久化空间耗尽，验证 `reject_new` 后只恢复已落盘日志
- checkpoint_corruption：人为破坏 `checkpoint` 文件后重启 recover，验证损坏恢复路径
- stale_takeover：同一路径第二个进程在 owner 存活时被拒绝，owner stale 后允许 takeover 并恢复数据

说明：

- `quota_reject_new` 当前覆盖的是 SDK 自身 quota 打满，不等同于真实文件系统 `ENOSPC`
- `checkpoint_corruption` 当前修复策略是将损坏的 checkpoint 重置为零 checkpoint 后继续 recover；这能优先保证完整性，但在“已有部分 ack 且 checkpoint 丢失”的更复杂场景下，语义会退化为可能重复发送
- `stale_takeover` 的结果判断以 `unique_seq` 完整性为准；若服务端在重试歧义下出现重复写入，会在查询结果里用 `duplicates=` 显式体现
- `tools/persistent_real_bench.sh` 会把每轮 benchmark 的 stdout/stderr 和查询结果归档到 `build-persistent-real/bench-results/<timestamp>/`
- benchmark 当前支持两类模式：steady-state rate sweep 和 recover drain throughput

`tools/real_demo.c` 现在也支持通过环境变量直接驱动 persistent 验证，例如：

- `VE_TLS_USE_PERSISTENT=1`
- `VE_TLS_PERSISTENT_FILE_PATH=/tmp/ve-tls-demo-persistent`
- `VE_TLS_DEMO_RUN_ID=...`
- `VE_TLS_DEMO_SCENARIO=...`
- `VE_TLS_DEMO_RECOVER=1`
- `VE_TLS_DEMO_EXIT_AFTER_ENQUEUE=1`
- `VE_TLS_DEMO_EXIT_AFTER_SUCCESS=10`
- `VE_TLS_PERSISTENT_MAX_RECORDS=5`
- `VE_TLS_PERSISTENT_OVERFLOW_POLICY=reject_new`

## 退出语义

- 优雅退出：`ve_tls_producer_close(p, timeout_ms)`
  - 停止接收新写入
  - 触发 flush 并等待队列与在途发送 drain（超时返回 `VE_TLS_TIMEOUT`）
- 强制退出：`ve_tls_producer_destroy(p)`
  - 立即停止 worker/sender 并释放资源，允许丢弃未处理数据

## 可靠性边界（master）

- master 分支默认仅使用内存队列，不提供落盘与崩溃恢复能力
- 正常退出建议：先停止业务侧产生新日志，再调用 `ve_tls_producer_close(p, timeout_ms)`，最后 `ve_tls_producer_destroy(p)` 回收资源
- 若业务必须具备 at-least-once（崩溃后恢复）语义，请使用 persistent 分支或在上层自行做外部持久化

## 文档索引

- master 能力清单：docs/master-capabilities.md
- 配置字段：docs/config-fields.md
- 调优指南：docs/tuning.md
- 重试策略：docs/retry-policy.md
- 签名：docs/signing.md
- 错误模型：docs/error-model.md
- 指标：docs/metrics.md

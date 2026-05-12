# ve-tls-c-sdk

`ve-tls-c-sdk` 是 Volcengine TLS Producer 的纯 C11 日志发送 SDK，面向 Linux 服务器、嵌入式 Linux、macOS 和 Windows C core 场景。SDK 提供异步写入、批量聚合、压缩、重试、背压控制和运行期观测能力，用于将业务日志稳定发送到 TLS。

## 核心能力与最佳实践

- 异步 Producer：业务线程调用写入接口后进入内存队列，后台线程负责聚合、压缩、签名、发送和重试。建议按进程或业务日志流复用长生命周期 producer，不要按单条日志或单个请求频繁创建销毁。
- 批量聚合：支持按 `flush_interval_ms`、`log_count_per_package`、`log_bytes_per_package` 触发发送，减少 HTTP 请求数和签名开销。低延迟场景降低 flush interval，高吞吐场景增大单批大小并配合更多发送线程。
- 压缩发送：支持 `lz4`、`zlib` 和不压缩。默认优先使用 `lz4`，适合日志文本这类高重复内容；只有在 CPU 极紧张且日志本身不可压缩时，才建议压测比较 `none`。
- HashKey 有序：同一 hashKey 内保持发送顺序，不同 hashKey 可并行聚合和发送。需要分区内有序时使用稳定 hashKey；不需要顺序时可不传 hashKey，让 SDK 追求整体吞吐。
- 背压控制：写入队列支持 `DROP` / `BLOCK`，发送队列支持 `DROP` / `BLOCK` / `DROP_SAMPLED`。实时观测类日志通常选择丢弃优先，关键业务日志应选择阻塞并设置有限超时，避免无限阻塞业务线程。
- 有界资源：`max_buffer_bytes` 统一约束写入队列、发送队列预留、inflight 批次和构建缓冲。嵌入式或小规格容器应先定内存预算，再让 SDK 派生包大小、线程数和队列容量。
- 重试治理：内置指数退避、可重试错误识别、全局/按 key 限流与熔断。建议把 `requests_failed_total`、`retries_total`、回调里的 HTTP code 和 request_id 接入业务监控。
- 动态配置：支持运行期更新 endpoint、region、topic 以及静态 AK/SK/token。使用临时凭证时优先接入 `credentials_provider`，避免在业务日志中打印 AK/SK/token。
- 可观测性：支持结构化发送回调、累计 metrics、metrics sink、buffered bytes 查询和 `*_with_id` 写入接口。建议在发送回调中记录 result、request_id、error_code、HTTP code 和 log_id 范围，便于定位批次级问题。
- 可控退出：`ve_tls_producer_close()` 会停止接收新日志并等待队列 drain，`ve_tls_producer_destroy()` 负责释放资源。生产服务收到退出信号后应先停止产生日志，再 close，最后 destroy。

## 安装与构建

依赖：

- CMake 3.16+
- C11 编译器
- pthread，默认开启
- libcurl，用于 HTTP 网络发送
- lz4 默认内置，zlib 可选

生产构建推荐显式启用 libcurl HTTP adapter：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

常用 CMake 选项：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `VE_TLS_ENABLE_PTHREAD` | `ON` | pthread 运行时 |
| `VE_TLS_ENABLE_CURL` | `OFF` | libcurl HTTP adapter；生产网络发送建议显式开启 |
| `VE_TLS_ENABLE_LZ4` | `ON` | 内置 lz4 压缩 |
| `VE_TLS_ENABLE_ZLIB` | `OFF` | zlib 压缩 |
| `VE_TLS_BUILD_TESTS` | `ON` | 构建并注册 `ve_tls_test_basic` |
| `VE_TLS_BUILD_TOOLS` | `ON` | 构建 demo 和 benchmark 工具 |
| `VE_TLS_ENABLE_ASAN` / `VE_TLS_ENABLE_UBSAN` | `OFF` | Sanitizer |

平台支持矩阵和 Windows 构建说明见 [docs/platform-support.md](docs/platform-support.md)。

## 快速开始

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

    ve_tls_producer * p = ve_tls_producer_create(&cfg);
    if (!p) {
        return 1;
    }

    ve_tls_kv kvs[1] = {{"k", "v"}};
    if (ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1) != VE_TLS_OK) {
        ve_tls_producer_destroy(p);
        return 2;
    }

    ve_tls_result rc = ve_tls_producer_close(p, 3000);
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_OK ? 0 : 3;
}
```

## 配置参数

所有参数通过 `ve_tls_config` 设置，先调用 `ve_tls_config_init()` 获取默认值，再覆盖需要的字段。

| 参数 | 说明 | 常见取值 |
| --- | --- | --- |
| `endpoint` | TLS endpoint | `https://...` |
| `region` | TLS region | `cn-beijing` |
| `topic_id` | 目标 topic | 字符串 |
| `access_key_id` / `access_key_secret` | 静态 AK/SK | 字符串 |
| `security_token` | 临时凭证 token | 可选 |
| `credentials_provider` | 动态凭证刷新函数 | 可选 |
| `compress_type` | 压缩类型 | `lz4` / `zlib` / `none` |
| `max_buffer_bytes` | Producer 总缓存预算 | 默认 `64MB` |
| `log_bytes_per_package` | 单批日志字节阈值 | 默认按内存预算派生 |
| `log_count_per_package` | 单批日志条数阈值 | 默认 `4096` |
| `flush_interval_ms` | 聚合超时时间 | 默认 `1000` |
| `send_thread_count` | 发送线程数 | 默认按内存预算派生 |
| `pack_thread_count` | 打包线程数 | 默认跟随发送线程数 |
| `send_queue_size` | manager 到 sender 的队列容量 | 默认按内存预算派生 |
| `buffer_full_policy` | 写入队列满策略 | `DROP` / `BLOCK` |
| `send_queue_full_policy` | send_queue 满策略 | `DROP` / `BLOCK` / `DROP_SAMPLED` |
| `connect_timeout_ms` | 连接超时 | 默认 `10000` |
| `request_timeout_ms` | 单请求超时 | 默认 `50000` |
| `tls_verify_peer` / `tls_verify_host` | TLS 校验 | 默认开启 |

完整配置字段见 [docs/config-fields.md](docs/config-fields.md)，调优建议见 [docs/tuning.md](docs/tuning.md)。

## 写入接口

常用写入方式：

- KV 写入：`ve_tls_producer_add_log_kv()`。
- Raw 写入：`ve_tls_producer_add_log_raw()`。
- 指定 hashKey：使用 `*_hashkey` 变体。
- 指定时间字段：使用 `*_time_parts` 变体。
- 返回 log_id：使用 `*_with_id` 变体。
- 固定 key 模板：`ve_tls_template_create()` + `ve_tls_template_add_values()`。

运行期能力：

- 更新目标：`ve_tls_producer_update_endpoint()`。
- 更新静态凭证：`ve_tls_producer_update_static_credentials()`。
- 拉取指标：`ve_tls_producer_get_metrics()`。
- 查询缓存估算值：`ve_tls_producer_get_buffered_bytes()`。
- 设置发送回调：`ve_tls_producer_set_send_done_v2()`。

## Demo

最小真实发送 demo：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j

VE_TLS_ENDPOINT=https://tls-cn-beijing.volces.com \
VE_TLS_REGION=cn-beijing \
VE_TLS_TOPIC_ID=your-topic-id \
VE_TLS_ACCESS_KEY_ID=your-ak \
VE_TLS_ACCESS_KEY_SECRET=your-sk \
./build/ve_tls_demo
```

完整 demo：

```sh
./build/ve_tls_demo_real --config tools/real_demo.env --duration-s 60 --wait-ms 3000
```

## 性能测试

真实环境 benchmark 使用 `ve_tls_benchmark_tls`，会通过 libcurl 向实际 TLS endpoint 发送日志。运行前先准备包含 endpoint、topic、AK/SK 或临时凭证的 env 文件，不要把凭证写入命令行或提交到仓库。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j --target ve_tls_benchmark_tls

set -a
. /path/to/real_demo.env
set +a

for profile in tls200 tls700; do
  TLS_BENCH_MODE=curl TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 10000 10 "$profile"
  TLS_BENCH_MODE=curl TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 30000 10 "$profile"
  TLS_BENCH_MODE=curl TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 50000 10 "$profile"
done

TLS_BENCH_MODE=curl TLS_MAX_BUFFER_BYTES=268435456 TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 10000 10 tls5120
TLS_BENCH_MODE=curl TLS_MAX_BUFFER_BYTES=268435456 TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 30000 10 tls5120
TLS_BENCH_MODE=curl TLS_MAX_BUFFER_BYTES=268435456 TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 50000 10 tls5120
```

真实发送参考数据：

- 环境：Linux x86_64 / Debian 5.15 / 16 vCPU Intel Xeon Platinum 8260 / libcurl 7.88.1 / Release / `VE_TLS_ENABLE_CURL=ON` / 真实 TLS endpoint。
- 配置：`send_thread_count=10`、`pack_thread_count=10`、`send_queue_size=10000`、`flush_interval_ms=1000`、`log_bytes_per_package=4MB`、`log_count_per_package=4096`、`compress_type=lz4`、`request_timeout_ms=50000`。
- 说明：记录目标写入速率下的成功率、请求量、CPU、RSS 和 drain 时间；`tls5120` 高倍率使用 `256MB` 内存预算，实际业务日志应按自己的字段、压缩率和限流策略复测。

| Profile | 目标写入速率 | 内存预算 | 日志数 | 入队丢弃 | 请求数 | 请求失败 | 重试 | 平均入队耗时 | close 耗时 | 峰值 buffer | CPU cores | CPU total | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `tls200` | `10000 logs/s` | `64MB` | `100000` | `0` | `25` | `0` | `0` | `0.33us/log` | `149.73ms` | `2.35MB` | `0.10` | `0.61%` | `39.28MB` |
| `tls200` | `30000 logs/s` | `64MB` | `300000` | `0` | `74` | `0` | `0` | `0.32us/log` | `438.89ms` | `5.77MB` | `0.35` | `2.20%` | `40.45MB` |
| `tls200` | `50000 logs/s` | `64MB` | `500000` | `0` | `123` | `0` | `0` | `0.31us/log` | `123.53ms` | `9.13MB` | `0.56` | `3.50%` | `56.41MB` |
| `tls700` | `10000 logs/s` | `64MB` | `100000` | `0` | `25` | `0` | `0` | `0.65us/log` | `122.02ms` | `9.87MB` | `0.13` | `0.78%` | `96.02MB` |
| `tls700` | `30000 logs/s` | `64MB` | `300000` | `0` | `74` | `0` | `0` | `0.60us/log` | `116.07ms` | `25.88MB` | `0.36` | `2.23%` | `118.77MB` |
| `tls700` | `50000 logs/s` | `64MB` | `500000` | `0` | `123` | `0` | `0` | `0.56us/log` | `125.33ms` | `37.95MB` | `0.58` | `3.65%` | `138.46MB` |
| `tls5120` | `10000 logs/s` | `256MB` | `100000` | `0` | `123` | `0` | `0` | `2.66us/log` | `3.85ms` | `53.02MB` | `0.60` | `3.73%` | `182.48MB` |
| `tls5120` | `30000 logs/s` | `256MB` | `300000` | `0` | `370` | `0` | `0` | `2.37us/log` | `10.90ms` | `172.03MB` | `0.72` | `4.49%` | `268.09MB` |
| `tls5120` | `50000 logs/s` | `256MB` | `500000` | `0` | `616` | `0` | `0` | `2.65us/log` | `109.90ms` | `247.26MB` | `0.88` | `5.52%` | `345.91MB` |

更多参数和场景建议见 [docs/tuning.md](docs/tuning.md)。

## 退出语义

- `ve_tls_producer_close(p, timeout_ms)`：停止接收新写入，触发 flush，等待队列和在途发送 drain；超时返回 `VE_TLS_TIMEOUT`。
- `ve_tls_producer_destroy(p)`：停止 worker/sender 并释放资源，允许丢弃未处理数据。
- 推荐顺序：先停止业务侧产生日志，再 `close`，最后 `destroy`。

## 可靠性边界

该 SDK 是内存队列 Producer。它能提供正常进程内的 drain、重试和背压治理，但不保证进程崩溃后的本地恢复。

如果业务要求进程崩溃后继续发送未完成日志，应在业务侧使用外部持久化或重放机制。

## 文档

- [配置字段](docs/config-fields.md)
- [调优与性能测试](docs/tuning.md)
- [重试策略](docs/retry-policy.md)
- [签名与鉴权](docs/signing.md)
- [错误模型](docs/error-model.md)
- [指标与观测](docs/metrics.md)
- [安全建议](docs/security.md)

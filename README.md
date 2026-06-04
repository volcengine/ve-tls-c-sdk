# ve-tls-c-sdk

`ve-tls-c-sdk` 是火山引擎日志服务 TLS 的 C11 Producer SDK。它适用于 Linux 服务器和嵌入式 Linux：业务线程写入日志，SDK 在后台完成聚合、压缩、签名、发送和重试。

这个 SDK 使用进程内队列，不做本地落盘恢复。需要进程崩溃后继续补发日志的场景，应在业务侧接入持久化或重放机制。

## 核心能力

- 异步发送：写入接口返回后，后台线程继续处理日志批次。建议按进程或业务日志流复用 producer，不要按单条日志频繁创建和销毁。
- 批量聚合：通过 `flush_interval_ms`、`log_count_per_package` 和 `log_bytes_per_package` 控制发送粒度。低延迟场景调小 flush interval，高吞吐场景增大批次并增加发送线程。
- 压缩：支持 `lz4`、`zlib` 和 `none`。日志文本通常优先使用 `lz4`。
- hashKey 顺序：同一 hashKey 内按顺序发送，不同 hashKey 可并行处理。需要分区内有序时传稳定 hashKey；不需要顺序时可以不传。
- 背压：写入队列支持 `DROP` / `BLOCK`，发送队列支持 `DROP` / `BLOCK` / `DROP_SAMPLED`。实时观测日志通常选择丢弃优先，关键日志建议选择阻塞并设置有限超时。
- 有界内存：`max_buffer_bytes` 约束写入队列、发送队列预留、inflight 批次和构建缓冲。小内存设备应先定预算，再调包大小和线程数。
- 临时凭证：支持 `credentials_provider`，SDK 会在凭证接近过期时刷新。不要在日志中打印 AK/SK/token。
- 观测与退出：提供发送回调、累计 metrics、metrics sink、buffered bytes 查询，以及 `close` / `destroy` 两阶段退出。

架构概览见 [docs/architecture.svg](docs/architecture.svg)。

## 构建

依赖：

- CMake 3.16+
- C11 编译器
- pthread，默认开启
- libcurl，用于真实网络发送
- lz4 默认内置，zlib 可选

真实发送需要启用 libcurl：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

常用 CMake 选项：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `VE_TLS_ENABLE_PTHREAD` | `ON` | pthread 运行时 |
| `VE_TLS_ENABLE_CURL` | `OFF` | libcurl HTTP adapter；真实网络发送需要开启 |
| `VE_TLS_ENABLE_LZ4` | `ON` | 内置 lz4 压缩 |
| `VE_TLS_ENABLE_ZLIB` | `OFF` | zlib 压缩 |
| `VE_TLS_BUILD_TESTS` | `ON` | 构建并注册 `ve_tls_test_basic` |
| `VE_TLS_BUILD_TOOLS` | `ON` | 构建 demo 和 benchmark 工具 |
| `VE_TLS_ENABLE_ASAN` / `VE_TLS_ENABLE_UBSAN` | `OFF` | Sanitizer |

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

    ve_tls_producer *p = ve_tls_producer_create(&cfg);
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

## 配置

所有参数通过 `ve_tls_config` 设置。先调用 `ve_tls_config_init()` 获取默认值，再覆盖需要的字段。

| 参数 | 说明 | 常见取值 |
| --- | --- | --- |
| `endpoint` | TLS endpoint | `https://...` |
| `region` | TLS region | `cn-beijing` |
| `topic_id` | 目标 topic | 字符串 |
| `access_key_id` / `access_key_secret` | 静态 AK/SK | 字符串 |
| `security_token` | 临时凭证 token | 可选 |
| `credentials_provider` | 临时凭证刷新回调 | 可选 |
| `compress_type` | 压缩类型 | `lz4` / `zlib` / `none` |
| `max_buffer_bytes` | Producer 总缓存预算 | 默认 `64MB` |
| `log_bytes_per_package` | 单批日志字节阈值 | 默认按内存预算派生 |
| `log_count_per_package` | 单批日志条数阈值 | 默认 `4096` |
| `flush_interval_ms` | 聚合等待时间 | 默认 `1000` |
| `send_thread_count` | 发送线程数 | 默认按内存预算派生 |
| `pack_thread_count` | 打包线程数 | 默认跟随发送线程数 |
| `send_queue_size` | manager 到 sender 的队列容量 | 默认按内存预算派生 |
| `buffer_full_policy` | 写入队列满策略 | `DROP` / `BLOCK` |
| `send_queue_full_policy` | send queue 满策略 | `DROP` / `BLOCK` / `DROP_SAMPLED` |
| `connect_timeout_ms` | 连接超时 | 默认 `10000` |
| `request_timeout_ms` | 单请求超时 | 默认 `50000` |
| `tls_verify_peer` / `tls_verify_host` | TLS 证书校验 | 默认开启 |

完整字段见 [docs/config-fields.md](docs/config-fields.md)，调优建议见 [docs/tuning.md](docs/tuning.md)。

## 写入接口

常用写入方式：

- KV 写入：`ve_tls_producer_add_log_kv()`。
- Raw 写入：`ve_tls_producer_add_log_raw()`。
- 指定 hashKey：使用 `*_hashkey` 变体。
- 指定时间字段：使用 `*_time_parts` 变体。
- 返回 log id：使用 `*_with_id` 变体。
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

`ve_tls_demo_real` 支持从 env 文件读取配置。仓库里的 `tools/real_demo.env` 是占位示例，运行前需要替换 topic 和凭证。

```sh
./build/ve_tls_demo_real --config tools/real_demo.env --count 1000 --wait-ms 3000
```

## 性能测试

真实网络 benchmark 使用 `ve_tls_benchmark_tls`，会通过 libcurl 向 TLS endpoint 发送日志。运行前准备好 endpoint、topic、AK/SK 或临时凭证，不要把真实凭证写入命令行历史或提交到仓库。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j --target ve_tls_benchmark_tls

set -a
. /path/to/real_demo.env
set +a

TLS_BENCH_MODE=curl TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 10000 10 tls200
```

本地开销测试使用 `ve_tls_bench`，默认走 mock HTTP 200 响应，不代表真实网络吞吐。

```sh
cmake --build build -j --target ve_tls_bench
./build/ve_tls_bench --duration-s 5 --writer-threads 4 --message-bytes 256 --write-mode kv --send-thread-count 4 --compress-type lz4
```

测试方法和参考数据见 [docs/tuning.md](docs/tuning.md)。

## 退出语义

- `ve_tls_producer_close(p, timeout_ms)`：停止接收新写入，触发 flush，等待队列和在途发送 drain；超时返回 `VE_TLS_TIMEOUT`。
- `ve_tls_producer_destroy(p)`：停止 worker/sender 并释放资源，允许丢弃未处理数据。

推荐顺序：先停止业务侧产生日志，再调用 `close`，最后调用 `destroy`。

## 文档

- [配置字段](docs/config-fields.md)
- [调优与性能测试](docs/tuning.md)
- [重试策略](docs/retry-policy.md)
- [签名与鉴权](docs/signing.md)
- [错误模型](docs/error-model.md)
- [指标与观测](docs/metrics.md)
- [安全建议](docs/security.md)
- [架构图](docs/architecture.svg)

## Security and privacy
This project takes security seriously. 
For vulnerability reporting and supported versions, see [SECURITY.md](SECURITY.md)

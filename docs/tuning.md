# 调优指南

本文面向 `live` 分支的 C Producer：内存队列、异步发送、无本地落盘恢复。Linux、macOS 和 Windows 使用同一套资源预算和队列语义；平台差异主要在网络 adapter、线程实现和进程资源统计。

## 关键参数

### 内存预算

- `max_buffer_bytes` 是 producer 总体缓存预算，不只是写入队列上限。
- 预算覆盖写入队列、send_queue 预留、inflight 批次、TLS batching 以及压缩 scratch。
- 包大小过大时会挤压队列与 inflight 空间；`log_bytes_per_package` 不能超过 `max_buffer_bytes / 2`。

### 聚合

- `flush_interval_ms` 越小延迟越低，请求数越多。
- `log_count_per_package` 越大吞吐越好，但单批延迟和内存占用上升。
- `log_bytes_per_package` 越大越能合并 IO，但在小内存场景会放大瞬时占用。

### 队列与背压

- `buffer_full_policy=DROP`：写入侧不阻塞，满时丢弃并计入 dropped。
- `buffer_full_policy=BLOCK`：写入侧等待预算释放，必须设置正数 `buffer_full_block_timeout_ms`。
- `send_queue_full_policy=DROP`：manager 无法入 send_queue 时丢批。
- `send_queue_full_policy=BLOCK`：manager 等待 send_queue 空位，适合“不丢优先”的低并发场景。
- `send_queue_full_policy=DROP_SAMPLED`：按采样比例丢弃，用于写入高峰下折中。
- `breaker_ingress_policy=ALLOW`：全局 breaker open 时仍允许写入排队，保持默认兼容行为。
- `breaker_ingress_policy=FAIL_FAST` / `DROP_WITH_CALLBACK`：全局 breaker open 时在写入侧直接失败或带回调丢弃，适合低资源和故障风暴场景。

## 默认派生档位

| 场景 | 建议 `max_buffer_bytes` | 派生包大小 | 派生线程 | 派生 `send_queue_size` |
| --- | --- | --- | --- | --- |
| 嵌入式/小内存 | `16MB..64MB` | `2MB` | `2` | `8 + max_buffer/package` |
| 通用服务器 | `64MB..256MB` | `2MB..4MB` | `2..4` | `8 + max_buffer/package` |
| 高吞吐服务器 | `>256MB` | `4MB` | `8` | 上限 `128` |

显式配置优先于派生值；如果你已经指定 `send_thread_count`、`pack_thread_count`、`log_bytes_per_package` 或 `send_queue_size`，producer 不会覆盖。

## 推荐配置

### 小内存设备

- `max_buffer_bytes=16MB`
- `log_bytes_per_package=1MB`
- `send_thread_count=1`
- `pack_thread_count=1`
- `send_queue_size=16`
- `buffer_full_policy=DROP` 或 `BLOCK` 加有限超时

### 通用服务

- `max_buffer_bytes=64MB`
- 使用派生默认值：`2MB` 包、`2` 个发送/打包线程、`send_queue_size=40`
- `flush_interval_ms=1000`
- `send_queue_full_policy=DROP` 或 `DROP_SAMPLED`

### 高吞吐写入

- `max_buffer_bytes=256MB` 或更高
- `log_bytes_per_package=4MB`
- `send_thread_count=4..8`
- `pack_thread_count=4..8`
- `send_queue_full_policy=DROP_SAMPLED`
- 必须通过真实环境压测确认 HTTP 限流、网络带宽和 request latency。

## 性能测试

### 真实网络 benchmark

`ve_tls_benchmark_tls` 使用内置日志模板向真实 endpoint 发送数据，适合评估接入环境下的发送吞吐、请求数、失败率和资源占用。

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

测试环境为 Linux x86_64 / Debian 5.15 / 16 vCPU Intel Xeon Platinum 8260 / libcurl 7.88.1 / Release / 真实 TLS endpoint，配置为 `send_thread_count=10`、`pack_thread_count=10`、`send_queue_size=10000`、`flush_interval_ms=1000`、`compress_type=lz4`。`CPU cores` 表示进程消耗的平均核心数，`CPU total` 表示占整机 16 vCPU 的比例。实际业务日志应按自己的字段和压缩率复测。

Windows 和 macOS 的真实发送验证记录在 [platform-support.md](platform-support.md)。同一参数在不同平台上的 RSS 口径不完全一致：POSIX 使用 `getrusage`，Windows 使用 `GetProcessMemoryInfo`。

### 本地开销 benchmark

`ve_tls_bench` 使用进程内 mock HTTP 200 响应，只用于衡量 Producer 本地写入、聚合、压缩和发送调度开销。

```sh
cmake --build build -j --target ve_tls_bench
./build/ve_tls_bench --duration-s 5 --writer-threads 4 --rate-lps 0 --message-bytes 256 --write-mode kv --send-thread-count 4 --compress-type lz4
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--duration-s` | 测试时长 |
| `--rate-lps` | 目标写入速率 |
| `--message-bytes` | 单条日志大小 |
| `--writer-threads` | 写入线程数 |
| `--write-mode` | `raw` / `kv` / `template` |
| `--send-thread-count` | 发送线程数 |
| `--compress-type` | `none` / `lz4` / `zlib` |
| `--queue-full-policy` | `block` / `drop` / `drop_sampled` |
| `--max-buffer-bytes` | Producer 缓存预算 |
| `--send-queue-size` | send_queue 容量 |

本地 benchmark 输出关注：

- `throughput logs_per_s`：写入吞吐。
- `logs_dropped_total`：背压丢弃数量。
- `requests_total` / `requests_failed_total`：请求量与失败量。
- `bytes_sent_total`：发送字节量。
- `p99_ms_upper`：请求延迟桶估算值。

本地开销参考数据：

| 环境 | 场景 | 吞吐 | 丢弃 | 请求数 | p99 上界 | 峰值 RSS |
| --- | --- | --- | --- | --- | --- | --- |
| Apple M4 Pro / Darwin arm64 / `cc -O2` | 4 writer、4 sender、KV、256B、lz4、mock HTTP 200、5s | `6329015.80 logs/s` | `0` | `61805` | `5ms` | `179355648 bytes` |

该数据只反映本地 Producer 开销，不代表真实网络发送吞吐。

矩阵测试脚本：

```sh
tools/performance_run.sh DURATION_S=10 RATE_LPS=0 MESSAGE_BYTES=256
```

脚本会覆盖 raw/kv/template、不同 writer/sender 数、压缩类型和队列策略，并输出 Markdown 表格，便于保存到性能报告中。

# 调优与性能测试

本文面向开启真实网络发送的 Producer，并补充 Persistent 模式下的磁盘和恢复调优。性能数据只能作为参考，接入方需要在自己的机器、日志模板、网络和服务配额下复测。

## 内存预算

- `max_buffer_bytes` 是 Producer 主要内存预算，不只是写入队列上限。
- 预算覆盖写入队列、send queue 预留、inflight 批次、raw 导入和压缩 scratch。
- `log_bytes_per_package` 不能超过 `max_buffer_bytes / 2`。包太大会挤压队列和 inflight 空间。
- `send_thread_count` 越大，连接数和 inflight 内存也越大。

## Persistent 磁盘预算

Persistent 模式还需要单独控制磁盘：

- `persistent_max_bytes` 控制总字节上限。
- `persistent_max_records` 控制总记录数上限。
- `persistent_max_segments` 控制 segment 数量。
- `persistent_high_watermark_pct` 和 `persistent_low_watermark_pct` 控制水位回收。

不要只调大磁盘上限。网络长期不可用时，越大的 backlog 代表越长的恢复时间，也代表越大的重复窗口。

## 聚合

- `flush_interval_ms` 越小，延迟越低，请求数越多。
- `log_count_per_package` 越大，吞吐通常越好，但单批延迟和内存占用也会上升。
- `log_bytes_per_package` 越大，越能合并 IO；小内存场景要控制瞬时占用。
- 大日志模板建议先限制 `log_bytes_per_package`，再调线程数。

## 队列与背压

- `buffer_full_policy=DROP`：写入侧不阻塞，满时丢弃并计入 dropped。
- `buffer_full_policy=BLOCK`：写入侧等待预算释放，应设置正数 `buffer_full_block_timeout_ms`。
- `send_queue_full_policy=BLOCK`：manager 等待 send queue 空位，适合低并发、不丢优先的场景。
- `send_queue_full_policy=DROP`：manager 无法入 send queue 时丢批。
- `send_queue_full_policy=DROP_SAMPLED`：按采样间隔丢弃，用于写入高峰下的折中策略。

Persistent 的 overflow policy 决定磁盘满后的行为。默认 `REJECT_NEW` 比静默丢弃更容易排查。

## 默认派生档位

| 场景 | 建议 `max_buffer_bytes` | 派生包大小 | 派生线程 | 派生 `send_queue_size` |
| --- | --- | --- | --- | --- |
| 嵌入式/小内存 | `16 MiB..64 MiB` | `2 MiB` | `2` | `8 + max_buffer/package` |
| 通用服务器 | `64 MiB..256 MiB` | `2 MiB..4 MiB` | `2..4` | `8 + max_buffer/package` |
| 高吞吐服务器 | `>256 MiB` | `4 MiB` | `8` | 上限 `128` |

显式配置优先于派生值。已经设置 `send_thread_count`、`pack_thread_count`、`log_bytes_per_package` 或 `send_queue_size` 时，Producer 不会覆盖。

## 推荐配置

小内存设备：

```text
max_buffer_bytes=16 MiB
log_bytes_per_package=1 MiB
send_thread_count=1
pack_thread_count=1
send_queue_size=16
buffer_full_policy=DROP 或 BLOCK 加有限超时
```

通用 Linux 服务：

```text
max_buffer_bytes=64 MiB
flush_interval_ms=1000
使用派生默认值：2 MiB 包、2 个发送/打包线程、send_queue_size 约 40
send_queue_full_policy=BLOCK 或 DROP_SAMPLED
```

Persistent 场景：

```text
use_persistent=1
persistent_file_path=/var/lib/ve-tls/<producer-name>
max_persistent_file_size=8 MiB
max_persistent_file_count=32
persistent_max_records 按可接受 backlog 设置
persistent_overflow_policy=VE_TLS_POVERFLOW_REJECT_NEW
```

## 真实网络 benchmark

非 Persistent 发送路径可以用 `ve_tls_benchmark_tls`：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j --target ve_tls_benchmark_tls

set -a
. .local/config/real_demo.env
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

Persistent 发送路径用 `ve_tls_persistent_real_bench`：

```sh
cmake --build build -j --target ve_tls_persistent_real_bench

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

## 参考数据

下面数据来自一次真实发送测试，测试对象是非 Persistent 发送路径。环境：Linux x86_64 / Debian 5.15 / 16 vCPU Intel Xeon Platinum 8260 / libcurl 7.88.1 / Release / 真实 TLS endpoint。主要配置：`send_thread_count=10`、`pack_thread_count=10`、`send_queue_size=10000`、`flush_interval_ms=1000`、`compress_type=lz4`。

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

`CPU cores` 表示进程消耗的平均核心数，`CPU total` 表示占整机 16 vCPU 的比例。Persistent 模式会额外增加本地 append、checkpoint 和 recover 成本，不能直接套用这张表。

## 本地开销 benchmark

`ve_tls_bench` 使用进程内 mock HTTP 200 响应，只用于衡量本地写入、聚合、压缩和发送调度开销。

```sh
cmake --build build -j --target ve_tls_bench
./build/ve_tls_bench --duration-s 5 --writer-threads 4 --rate-lps 0 --message-bytes 256 --write-mode kv --send-thread-count 4 --compress-type lz4
```

本地 benchmark 输出重点看：

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

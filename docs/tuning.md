# 调优指南

当前分支有两个 profile：Full Producer 和 Bricks tiny core。Full Producer 调优关注队列、线程、聚合、重试和内存预算；Bricks 调优关注单次 pack 成本、body ownership、压缩开关和调用方 transport。

## 关键参数

### 内存预算

Full Producer：

- `max_buffer_bytes` 是 producer 总体缓存预算，不只是写入队列上限。
- 预算覆盖写入队列、send_queue 预留、inflight 批次以及构建阶段缓冲。
- 包大小过大时会挤压队列与 inflight 空间；`log_bytes_per_package` 不应超过 `max_buffer_bytes / 2`。

Bricks：

- 没有 `max_buffer_bytes`。单次调用的输入 body 大小由调用方控制。
- `compress_type=none` 且 `body_no_copy=1` 时，输出 body 不复制输入 buffer。
- 开启 LZ4/ZLIB 会分配压缩输出 buffer，并增加静态库和可执行文件体积。
- benchmark 的 `sdk_heap_peak_bytes` 只统计 SDK allocator，不包含 libc、curl、调用方队列或 transport。

### 聚合

Full Producer：

- `flush_interval_ms` 越小延迟越低，请求数越多。
- `log_count_per_package` 越大吞吐越好，但单批延迟和内存占用上升。
- `log_bytes_per_package` 越大越能合并 IO，但在小内存场景会放大瞬时占用。

Bricks：

- Bricks 不做自动聚合。调用方应先决定一批包含多少条 log，再生成 LogGroupList body。
- 低内存场景优先小批量、`none` 压缩、no-copy body。
- 高吞吐场景应在 Bricks 外层做并发发送，但要控制同时存在的 request/body 数量。

### 队列与背压

Full Producer：

- `buffer_full_policy=DROP`：写入侧不阻塞，满时丢弃并计入 dropped。
- `buffer_full_policy=BLOCK`：写入侧等待预算释放，必须设置正数 `buffer_full_block_timeout_ms`。
- `send_queue_full_policy=DROP`：manager 无法入 send_queue 时丢批。
- `send_queue_full_policy=BLOCK`：manager 等待 send_queue 空位，适合“不丢优先”的低并发场景。
- `send_queue_full_policy=DROP_SAMPLED`：按采样比例丢弃，用于写入高峰下折中。

Bricks：

- 没有 SDK 内部队列，也没有 drop/block 策略。
- 调用方队列应按内存预算限制待发送 body 总大小。
- 如果使用 no-copy，队列项必须持有 protobuf buffer，直到 HTTP 发送结束。
- 如果要重试，重试队列应持有原始 body 或重新编码所需的业务数据。

## 默认派生档位

Full Producer：

| 场景 | 建议 `max_buffer_bytes` | 派生包大小 | 派生线程 | 派生 `send_queue_size` |
| --- | --- | --- | --- | --- |
| 嵌入式/小内存 | `16MB..64MB` | `2MB` | `2` | `8 + max_buffer/package` |
| 通用服务器 | `64MB..256MB` | `2MB..4MB` | `2..4` | `8 + max_buffer/package` |
| 高吞吐服务器 | `>256MB` | `4MB` | `8` | 上限 `128` |

显式配置优先于派生值；如果已经指定 `send_thread_count`、`pack_thread_count`、`log_bytes_per_package` 或 `send_queue_size`，Full Producer 不会覆盖。

Bricks 没有派生档位。建议按目标环境选择：

| 场景 | 建议 |
| --- | --- |
| 极小二进制 | Bricks LZ4/ZLIB off，`compress_type=none`，no-copy body，链接时启用 section GC 和 strip |
| 小内存设备 | 小批量 LogGroupList，限制并发 request 数，不在 SDK 外堆积大 body |
| 低带宽链路 | 可启用 `VE_TLS_BRICKS_ENABLE_LZ4`，但要接受静态库从 `40298B` 增至 `70784B` |
| 已有 HTTP 栈 | 直接发送 Bricks 输出的 URL/headers/body，保留空值签名头 |

## 推荐配置

### 小内存设备

Full Producer：

- `max_buffer_bytes=16MB`
- `log_bytes_per_package=1MB`
- `send_thread_count=1`
- `pack_thread_count=1`
- `send_queue_size=16`
- `buffer_full_policy=DROP` 或 `BLOCK` 加有限超时

Bricks：

- `VE_TLS_BRICKS_ENABLE_LZ4=OFF`
- `VE_TLS_BRICKS_ENABLE_ZLIB=OFF`
- `compress_type="none"`
- `body_no_copy=1`
- 调用方限制单批 body 和并发发送数量

### 通用 Linux 服务

Full Producer：

- `max_buffer_bytes=64MB`
- 使用派生默认值：`2MB` 包、`2` 个发送/打包线程、`send_queue_size=40`
- `flush_interval_ms=1000`
- `send_queue_full_policy=DROP` 或 `DROP_SAMPLED`

Bricks：

- 如果服务已有成熟 HTTP client、retry 和指标系统，可以用 Bricks 替代 SDK 内部 producer 链路。
- 如果希望 SDK 自带队列、重试、callback 和 metrics，应使用 Full Producer，而不是 Bricks。

### 高吞吐写入

Full Producer：

- `max_buffer_bytes=256MB` 或更高
- `log_bytes_per_package=4MB`
- `send_thread_count=4..8`
- `pack_thread_count=4..8`
- `send_queue_full_policy=DROP_SAMPLED`
- 必须通过真实环境压测确认 HTTP 限流、网络带宽和 request latency。

Bricks：

- 当前 `ve_tls_bricks_demo_real` 是顺序发送工具，不代表并发吞吐上限。
- 高吞吐需要调用方实现并发 transport、重试队列和限流。
- 并发压测应记录 pack time、HTTP latency、失败率、重试次数、队列长度和 body 总内存。

## 性能测试

### 真实网络 benchmark

Full Producer 使用 `ve_tls_benchmark_tls` 向真实 endpoint 发送数据，适合评估完整 SDK 的发送吞吐、失败率和资源占用。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j --target ve_tls_benchmark_tls

set -a
. /path/to/real_demo.env
set +a

TLS_BENCH_MODE=curl TLS_CLOSE_TIMEOUT_MS=300000 ./build/ve_tls_benchmark_tls 10000 10 tls200
```

Full Producer 的真实网络数据需要按接入环境重新跑。不要把 Full Producer 的吞吐表直接套到 Bricks tiny core 上。

Bricks 真实发送 demo：

```sh
cmake -S . -B build-bricks-real \
  -DCMAKE_BUILD_TYPE=Release \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_BUILD_TOOLS=ON \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=ON \
  -DVE_TLS_BRICKS_ENABLE_LZ4=ON
cmake --build build-bricks-real --target ve_tls_bricks_demo_real -j

VE_TLS_ENDPOINT=... \
VE_TLS_REGION=... \
VE_TLS_TOPIC_ID=... \
VE_TLS_ACCESS_KEY_ID=... \
VE_TLS_ACCESS_KEY_SECRET=... \
VE_TLS_COMPRESS_TYPE=lz4 \
./build-bricks-real/ve_tls_bricks_demo_real --count 300 --timeout-ms 15000 --quiet
```

顺序发送参考结果：

| 场景 | 成功率 | 吞吐/延迟 |
| --- | ---: | --- |
| `none`, 单次 | `1/1`, `http=200` | latency `178.984 ms` |
| `lz4`, 单次 | `1/1`, `http=200` | latency `158.703 ms` |
| `lz4`, 顺序 300 次 | `300/300` | `27.79 req/s`, avg `35.973 ms` |

### 本地开销 benchmark

Full Producer 使用 `ve_tls_bench`，衡量进程内 mock HTTP 200 下的写入、聚合、压缩和发送调度开销。

```sh
cmake --build build -j --target ve_tls_bench
./build/ve_tls_bench --duration-s 5 --writer-threads 4 --rate-lps 0 --message-bytes 256 --write-mode kv --send-thread-count 4 --compress-type lz4
```

Bricks 使用 `ve_tls_bricks_bench`，衡量 protobuf encode + request pack 成本：

```sh
cmake -S . -B build-bricks-bench \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_BUILD_TOOLS=ON \
  -DVE_TLS_ENABLE_CURL=OFF \
  -DVE_TLS_BRICKS_ENABLE_LZ4=OFF
cmake --build build-bricks-bench --target ve_tls_bricks_bench -j

./build-bricks-bench/ve_tls_bricks_bench \
  --iterations 100000 \
  --logs 10 \
  --message-bytes 256 \
  --compress-type none \
  --copy-body 0 \
  --track-alloc 1
```

当前 Bricks 本地开销参考数据：

| 场景 | 平均耗时 | 吞吐 | SDK heap peak |
| --- | ---: | ---: | ---: |
| `100000 x 10 logs x 256B`, `none`, zero-copy | `41.139 us/req` | `24307.85 req/s` | `13312 bytes` |
| `10000 x 1 log x 16B`, `none`, zero-copy | `12.074 us/req` | `82821.22 req/s` | `2736 bytes` |

矩阵测试脚本 `tools/performance_run.sh` 仍面向 Full Producer。Bricks 当前没有并发压测脚本；如果文档需要并发数据，应先新增或外部实现并发发送工具。

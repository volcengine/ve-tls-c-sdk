# 调优指南（master）

本文面向 `master` 分支（内存队列 + 异步发送，不含落盘与崩溃恢复），用于在不同资源与写入压力下选择合适的参数组合。

## 关键参数与联动关系

### 内存上限与队列

- `max_buffer_bytes`
  - 控制 producer 侧可缓存的总字节数上限（超过上限后写入会被丢弃并产生 dropped 指标）
  - 该值越大，能吸收的突发写入越多，但占用内存越高
- `send_queue_size`
  - 控制 manager → sender 的有界队列容量（按“批次任务”计数）
  - 写入高峰下 send_queue 满将触发 `send_queue_full_policy`
- `send_queue_full_policy`
  - `DROP`：不阻塞写入侧，允许丢弃（推荐默认）
  - `BLOCK`：阻塞等待（适合“不丢优先”但允许写入变慢的场景）
  - `DROP_SAMPLED`：部分阻塞 + 部分丢弃，适合折中

### 聚合参数

- `flush_interval_ms`
  - 聚合触发的时间上限；值越小延迟越低，但请求数越多
- `log_count_per_package` / `log_bytes_per_package`
  - 聚合触发的条数/字节阈值；值越大吞吐更好但延迟更高
- `agg_max_*_bytes_per_request`
  - 控制单请求大小上限（raw/compressed）；过大可能导致单请求耗时上升或服务端限制

### 并发

- `send_thread_count`
  - sender 线程数；对“多 hashKey 并发”吞吐影响明显
  - 线程数过大可能导致 CPU 抢占与队列抖动，建议按压测结果调整

## 推荐配置档位

以下档位以默认值为基础，按场景提供更易落地的组合建议（你可以按实际压测微调）。

### 资源受限（嵌入式/小内存）

- `max_buffer_bytes=8~16MB`
- `send_queue_size=128~256`
- `flush_interval_ms=1000`
- `log_count_per_package=512~1024`
- `send_thread_count=1`
- `send_queue_full_policy=DROP`

### 通用服务器（默认推荐）

- `max_buffer_bytes=64MB`（默认）
- `send_queue_size=1024`（默认）
- `flush_interval_ms=1000`（默认）
- `log_count_per_package=2048`（默认）
- `send_thread_count=2~4`
- `send_queue_full_policy=DROP` 或 `DROP_SAMPLED`

### 高吞吐（写入高峰明显）

- `max_buffer_bytes=128~256MB`
- `send_queue_size=2048~4096`
- `flush_interval_ms=200~500`
- `log_count_per_package=4096`（结合服务端限制评估）
- `send_thread_count=4~8`
- `send_queue_full_policy=DROP_SAMPLED`（避免长时间阻塞写入侧）

## 基准测试（本地）

仓库提供 `ve_tls_bench`，用于在不依赖真实网络的情况下测量基础吞吐与资源趋势：

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/ve_tls_bench --duration-s 10 --writer-threads 4 --rate-lps 5000 --message-bytes 256
```

输出包含：
- `logs_enqueued_total`、`logs_dropped_total`
- `requests_total`、`requests_failed_total`、`retries_total`
- `bytes_sent_total`
- 估算吞吐：`logs/s`、`bytes/s`

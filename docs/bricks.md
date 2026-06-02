# Bricks

`ve_tls_bricks_core` 是 `bricks` 分支里的 tiny profile。它接收 LogGroupList protobuf body，输出调用方可直接发送的 HTTP method、URL、headers 和 body。它不发送网络请求。

这个目标适合资源受限设备、已有 HTTP 栈的嵌入式环境、以及希望把传输和重试策略留在业务侧的场景。它不是完整 Producer 的替代品：完整 Producer 的异步队列、后台线程、重试、背压、metrics、callback、动态凭证和环境生命周期都不在 Bricks core 内。

## 构建

最小构建：

```sh
cmake -S . -B build-bricks \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_ENABLE_CURL=OFF \
  -DVE_TLS_BRICKS_ENABLE_LZ4=OFF \
  -DVE_TLS_BRICKS_ENABLE_ZLIB=OFF
cmake --build build-bricks --target ve_tls_bricks_core -j
```

压缩选项和完整 SDK 选项分离。`VE_TLS_ENABLE_LZ4` 影响 full core；`VE_TLS_BRICKS_ENABLE_LZ4` 才影响 Bricks core。保持 Bricks LZ4/ZLIB 关闭可以获得最小静态库和最小可执行文件。

真实发送 demo 构建：

```sh
cmake -S . -B build-bricks-real \
  -DCMAKE_BUILD_TYPE=Release \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_BUILD_TOOLS=ON \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=ON \
  -DVE_TLS_BRICKS_ENABLE_LZ4=ON \
  -DVE_TLS_BRICKS_ENABLE_ZLIB=OFF
cmake --build build-bricks-real --target ve_tls_bricks_demo_real -j
```

`ve_tls_bricks_demo_real` 链接 curl 只是为了演示真实发送。curl 不会进入 `ve_tls_bricks_core`。

最低 heap 和最低可执行文件体积的建议配置：

- `compress_type="none"`
- `body_no_copy=1`
- 调用方自己持有 protobuf body，直到发送完成
- 编译可执行文件时使用 `-ffunction-sections -fdata-sections`，链接时使用 `-Wl,--gc-sections -s`

## 能力边界

Bricks core 包含：

- protobuf log 和 LogGroupList 编码 helper
- MD5、SHA256、HMAC 和 TLS V4 signing
- `POST /PutLogs?TopicId=...` URL 和 header 组装
- `none` 压缩类型的 copy / no-copy body 处理
- 可选 LZ4/ZLIB 压缩
- 自定义 allocator hook，供 benchmark 和嵌入式接入做 heap 观测或替换

Bricks core 不包含：

- HTTP transport、curl、socket、TLS 证书校验
- producer queue、worker thread、sender thread、全局 env
- retry、退避、限流、熔断、drop policy、持久化
- metrics API、metrics sink、send_done callback
- 动态 credential provider 或凭证刷新调度

调用方必须负责：

- 生成或提供 LogGroupList protobuf body
- 发送 `req.method` / `req.url` / `req.headers` / `req.body`
- 根据 HTTP code、网络错误和 TLS 错误执行重试
- 管理队列、背压、并发、超时、凭证刷新和日志脱敏
- 在 body 借用模式下保证 buffer 生命周期覆盖发送过程

`req.headers` 是以 `\n` 分隔的 `Key: Value` 文本。使用 libcurl 发送时要保留空值签名头，例如 `x-tls-hashkey: `。libcurl 会把 `Header:` 解释成删除 header，因此 demo 会把空值 header 转成 `Header;`。

## SLS Bricks 对照

Aliyun SLS `bricks-https` 的思路是把 SDK 缩到 request packing 和少量 protobuf builder，HTTP、retry、drop、MD5/HMAC/time hook 都交给 sample 或调用方。

TLS Bricks 借鉴了这个边界，但没有完全复制：

- TLS Bricks 内置 TLS V4 signing，因此比把 crypto/time 全部交给调用方的实现更大。
- TLS Bricks 默认保留 protobuf helper，调用方也可以绕过 helper 自己提供 raw body。
- TLS Bricks 用 `body_no_copy=1` 复用 SLS no-copy body ownership 思路。
- TLS Bricks 的 curl 只在 `ve_tls_bricks_demo_real`，不是 core 依赖。

因此，和 SLS bricks 的“极限最小数字”只能作为方向参考，不能直接等价对比。TLS Bricks 的硬约束是：core 中没有 producer、pthread、curl、retry、metrics、persistence 和 file runtime 符号。

## 体积与性能参考

参考环境：

- Linux x86_64 / Debian
- GCC 12.2.0 / CMake 3.25.1
- 默认 size report：`CMAKE_BUILD_TYPE=MinSizeRel`
- 裁剪可执行文件：`-Os -ffunction-sections -fdata-sections -Wl,--gc-sections -s`

复现命令：

```sh
./tools/bricks_size_report.sh /tmp/ve-tls-bricks-size-none
VE_TLS_SIZE_BRICKS_ENABLE_LZ4=ON ./tools/bricks_size_report.sh /tmp/ve-tls-bricks-size-lz4

cmake -S . -B /tmp/ve-tls-bricks-bench \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_BUILD_TOOLS=ON \
  -DVE_TLS_BUILD_TESTS=OFF \
  -DVE_TLS_ENABLE_CURL=OFF \
  -DVE_TLS_BRICKS_ENABLE_LZ4=OFF \
  -DVE_TLS_BRICKS_ENABLE_ZLIB=OFF
cmake --build /tmp/ve-tls-bricks-bench --target ve_tls_bricks_bench -j
/tmp/ve-tls-bricks-bench/ve_tls_bricks_bench --iterations 100000 --logs 10 --message-bytes 256 --compress-type none --copy-body 0 --track-alloc 1
```

静态库体积：

| target/config | archive bytes | ratio vs full core |
| --- | ---: | ---: |
| `ve_tls_core`, full core, LZ4 on | `201030` | `100.0%` |
| `ve_tls_bricks_core`, LZ4 off | `40298` | `20.0%` |
| `ve_tls_bricks_core`, LZ4 on | `70784` | `35.2%` |

`nm -g` forbidden-symbol check passed for `pthread`、`curl`、`ve_tls_producer`、`ve_tls_env`、retry、metrics、persistence 和 file runtime。

最小集成可执行文件体积：

| mode | file bytes | text | data | bss | dec |
| --- | ---: | ---: | ---: | ---: | ---: |
| pack-only：调用方提供 raw body，只调用 `ve_tls_bricks_pack_request()` | `27024` | `18252` | `720` | `2232` | `21204` |
| proto+pack：SDK 编 protobuf 后再 pack | `31120` | `20541` | `720` | `2232` | `23493` |
| `ve_tls_bricks_bench`，裁剪后 | `35256` | `24196` | `760` | `2232` | `27188` |
| `ve_tls_bricks_demo_real`，Release + curl + LZ4 | `133304` | `115911` | `904` | `2232` | `119047` |

注意：可执行文件本体不包含动态 libc、libcurl、OpenSSL 等系统库体积。真实部署包如果把动态库也打进去，体积会明显大于上表。

CPU-only benchmark：

| workload | avg time | req/s | raw throughput | SDK heap peak | SDK heap current |
| --- | ---: | ---: | ---: | ---: | ---: |
| `100000 x 10 logs x 256B`, `none`, zero-copy | `41.139 us` | `24307.85` | `65.47 MiB/s` | `13312 bytes` | `0` |
| `10000 x 1 log x 16B`, `none`, zero-copy | `12.074 us` | `82821.22` | `4.03 MiB/s` | `2736 bytes` | `0` |

`sdk_heap_peak_bytes` 通过 `ve_tls_alloc_set_hooks()` 统计，只覆盖 TLS SDK allocator；不包含进程、loader、libc 或调用方 transport 的内存。

## 真实发送验证

真实发送 demo：

```sh
VE_TLS_ENDPOINT=... \
VE_TLS_REGION=... \
VE_TLS_TOPIC_ID=... \
VE_TLS_ACCESS_KEY_ID=... \
VE_TLS_ACCESS_KEY_SECRET=... \
VE_TLS_COMPRESS_TYPE=none \
build-bricks-real/ve_tls_bricks_demo_real --count 1 --timeout-ms 15000
```

使用真实 TLS endpoint 和临时凭证跑过下面几组顺序发送：

| run | success | elapsed / latency | request bytes | response bytes |
| --- | ---: | ---: | ---: | ---: |
| `none`, single request | `1/1`, `http=200` | `178.984 ms` | `86` | `0` |
| `lz4`, single request | `1/1`, `http=200` | `158.703 ms` | `77` | `0` |
| `lz4`, sequential 300 requests | `300/300` | `10793.774 ms`, avg `35.973 ms`, min `7.289 ms`, max `244.350 ms` | `23592` | `0` |

这说明 Bricks 生成的 protobuf body、TLS V4 signature、signed headers 和 curl sample transport 能被服务端接受。

边界：

- 当前 `ve_tls_bricks_demo_real` 是顺序发送工具，不是并发压测工具。
- 真实网络 latency 受 endpoint、代理、TLS 握手复用、网络抖动影响；CPU-only pack 成本以 `ve_tls_bricks_bench` 为准。
- 如果接入环境有代理，确认 TLS endpoint 的代理策略。代理配置错误时，失败会出现在调用方 transport 层。

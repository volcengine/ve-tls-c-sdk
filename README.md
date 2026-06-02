# ve-tls-c-sdk

`bricks` 分支包含两个 profile：完整异步 Producer，以及本分支新增的 Bricks tiny request packer。Bricks 是分支重点：它把一段已经编码好的 LogGroupList protobuf body 打包成可发送的 `POST /PutLogs?TopicId=...` 请求，包含 URL、请求头、TLS V4 签名和请求 body；HTTP 发送、重试、队列、背压、指标和凭证刷新都由调用方负责。

## 核心能力与最佳实践

- Full Producer：保留 `ve_tls_core` 的异步写入、聚合、压缩、HTTP 发送、重试、背压、metrics、callback 和受控退出能力。需要 SDK 接管完整发送链路时使用它。
- Tiny core：`ve_tls_bricks_core` 只链接 `alloc/hash/sign/proto/compress/bricks` 这几类源文件，不链接 producer、pthread、curl、retry、metrics、persistence 或 env runtime。
- Pack-only：公开入口是 `ve_tls_bricks_pack_request()`，输出 `method`、`url`、换行分隔的 headers、body 指针和元数据。SDK 不发网络请求。
- TLS V4 签名内置：SDK 生成 `X-Date`、`X-Content-Sha256`、`Authorization`，并支持可选 `X-Security-Token`。
- Protobuf helper 可选使用：调用方可以使用 `ve_tls_proto_encode_log*()` / `ve_tls_proto_encode_log_group_list*()` 生成 body，也可以自己提供已编码 body。
- body 零拷贝：`compress_type=none` 且 `body_no_copy=1` 时，返回 request 的 body 指向调用方传入 buffer，`ve_tls_bricks_request_free()` 不释放该 body。
- 可选压缩：Bricks 默认关闭 LZ4/ZLIB，最小二进制建议保持 `none`；需要压缩时显式打开 `VE_TLS_BRICKS_ENABLE_LZ4` 或 `VE_TLS_BRICKS_ENABLE_ZLIB`。
- 真实发送 demo 独立：`ve_tls_bricks_demo_real` 只作为 libcurl 样例存在，curl 不进入 `ve_tls_bricks_core`。
- 明确边界：Bricks profile 不提供异步队列、后台线程、批量调度、重试、限流、熔断、metrics、send callback、动态凭证 provider、本地落盘恢复或全局 env。

| Profile | 适用场景 | SDK 负责 | 调用方负责 |
| --- | --- | --- | --- |
| Full Producer | 希望 SDK 接管发送链路的 Linux 服务 | 队列、聚合、压缩、签名、HTTP、重试、背压、metrics、callback | 配置、业务日志、进程退出顺序 |
| Bricks tiny core | 资源受限设备、已有 HTTP 栈、需要极小二进制 | protobuf helper、可选压缩、TLS V4 签名、request packing | HTTP、retry、队列、并发、凭证刷新、metrics、可靠性 |

## 安装与构建

依赖：

- CMake 3.16+
- C11 编译器
- tiny core：默认只需要 libc；Linux 下链接 `m`
- 真实发送 demo：额外需要 libcurl
- 可选压缩：LZ4 使用仓库内 `third_party/lz4`，ZLIB 需要系统 zlib

Full Producer 构建：

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DVE_TLS_ENABLE_CURL=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

最小 Bricks 构建：

```sh
cmake -S . -B build-bricks \
  -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DVE_TLS_BUILD_BRICKS=ON \
  -DVE_TLS_ENABLE_CURL=OFF \
  -DVE_TLS_BRICKS_ENABLE_LZ4=OFF \
  -DVE_TLS_BRICKS_ENABLE_ZLIB=OFF
cmake --build build-bricks --target ve_tls_bricks_core -j
```

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

常用 CMake 选项：

| 选项 | 默认值 | Bricks 语义 |
| --- | --- | --- |
| `VE_TLS_BUILD_BRICKS` | `ON` | 构建 `ve_tls_bricks_core` |
| `VE_TLS_BRICKS_ENABLE_LZ4` | `OFF` | 只给 Bricks target 启用 LZ4 |
| `VE_TLS_BRICKS_ENABLE_ZLIB` | `OFF` | 只给 Bricks target 启用 ZLIB |
| `VE_TLS_ENABLE_CURL` | `OFF` | 只影响完整 core 和 demo；Bricks core 不链接 curl |
| `VE_TLS_BUILD_TOOLS` | `ON` | 构建 `ve_tls_bricks_bench`；curl 开启时构建 `ve_tls_bricks_demo_real` |
| `VE_TLS_BUILD_TESTS` | `ON` | 构建并注册 `ve_tls_test_basic` |
| `VE_TLS_ENABLE_ASAN` / `VE_TLS_ENABLE_UBSAN` | `OFF` | Sanitizer |

## 快速开始

Full Producer：

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
    if (!p) return 1;

    ve_tls_kv kvs[1] = {{"message", "hello"}};
    ve_tls_result rc = ve_tls_producer_add_log_kv(p, 0, kvs, 1, 1);
    if (rc == VE_TLS_OK) {
        rc = ve_tls_producer_close(p, 3000);
    }
    ve_tls_producer_destroy(p);
    return rc == VE_TLS_OK ? 0 : 2;
}
```

Bricks tiny core：

```c
#include "ve_tls_bricks.h"
#include "ve_tls_proto.h"

#include <string.h>

int main(void) {
    ve_tls_kv kv = {"message", "hello"};
    ve_tls_bytes log;
    ve_tls_bytes group;
    ve_tls_bricks_config cfg;
    ve_tls_bricks_request req;

    memset(&log, 0, sizeof(log));
    memset(&group, 0, sizeof(group));
    memset(&cfg, 0, sizeof(cfg));
    memset(&req, 0, sizeof(req));

    if (ve_tls_proto_encode_log(1710000000000LL, &kv, 1, &log) != 0) return 1;
    if (ve_tls_proto_encode_log_group_list(&log, 1, "source", "file", &group) != 0) return 2;

    cfg.endpoint = "https://tls-cn-beijing.volces.com";
    cfg.region = "cn-beijing";
    cfg.topic_id = "your-topic-id";
    cfg.api_version = "0.3.0";
    cfg.access_key_id = "your-ak";
    cfg.access_key_secret = "your-sk";
    cfg.security_token = NULL;
    cfg.compress_type = "none";
    cfg.hash_key = "";
    cfg.body_no_copy = 1;

    if (ve_tls_bricks_pack_request(&cfg, group.data, group.size, 1,
                                   1710000000000LL, 1710000000000LL, &req) != 0) {
        ve_tls_bytes_free(&group);
        ve_tls_bytes_free(&log);
        return 3;
    }

    /*
     * 调用方在这里发送：
     * method: req.method
     * url: req.url
     * headers: req.headers, each line is "Key: Value\n"
     * body: req.body, req.body_size
     */

    ve_tls_bricks_request_free(&req);
    ve_tls_bytes_free(&group);
    ve_tls_bytes_free(&log);
    return 0;
}
```

## 配置参数

Full Producer 使用 `ve_tls_config`，字段覆盖目标、鉴权、聚合、队列、重试、网络、metrics 和 callback。Bricks 使用 `ve_tls_bricks_config`，所有字段由调用方直接赋值。

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `endpoint` | 是 | TLS endpoint，例如 `https://tls-cn-beijing.volces.com` |
| `region` | 是 | 签名 scope 中的 region |
| `topic_id` | 是 | 写入目标 topic，进入 query `TopicId=` |
| `api_version` | 否 | 默认使用 SDK API version；通常填 `0.3.0` |
| `access_key_id` / `access_key_secret` | 是 | 静态 AK/SK |
| `security_token` | 否 | 临时凭证 token |
| `compress_type` | 否 | `none` / `lz4` / `zlib`；默认视为 `none` |
| `hash_key` | 否 | 进入 `x-tls-hashkey`，空值也会参与签名 |
| `xdate` | 否 | 固定签名时间，主要用于测试；为空则由签名模块生成 |
| `body_no_copy` | 否 | `compress_type=none` 时允许返回 body 借用调用方 buffer |

`ve_tls_bricks_pack_request()` 的 `log_count`、`earliest_log_time_ms`、`latest_log_time_ms` 会写入 `log-count`、`earliest-log-time`、`latest-log-time` 请求头。

完整字段说明见 [docs/config-fields.md](docs/config-fields.md)。

## 写入接口

Full Producer 常用写入方式：

- KV 写入：`ve_tls_producer_add_log_kv()`。
- Raw 写入：`ve_tls_producer_add_log_raw()`。
- 指定 hashKey：使用 `*_hashkey` 变体。
- 指定时间字段：使用 `*_time_parts` 变体。
- 返回 log_id：使用 `*_with_id` 变体。
- 固定 key 模板：`ve_tls_template_create()` + `ve_tls_template_add_values()`。

Full Producer 运行期能力：

- 更新目标：`ve_tls_producer_update_endpoint()`。
- 更新静态凭证：`ve_tls_producer_update_static_credentials()`。
- 拉取指标：`ve_tls_producer_get_metrics()`。
- 查询缓存估算值：`ve_tls_producer_get_buffered_bytes()`。
- 设置发送回调：`ve_tls_producer_set_send_done_v2()`。

Bricks 没有“写入 SDK 内部队列”的接口。它的入口是：

- `ve_tls_proto_encode_log*()`：可选，用于生成单条 log protobuf。
- `ve_tls_proto_encode_log_group_list*()`：可选，用于生成 LogGroupList protobuf body。
- `ve_tls_bricks_pack_request()`：把 raw LogGroupList body 打成 PutLogs request。
- `ve_tls_bricks_request_free()`：释放 pack 结果。

## Demo

Full Producer demo：

```sh
VE_TLS_ENDPOINT=https://tls-cn-beijing.volces.com \
VE_TLS_REGION=cn-beijing \
VE_TLS_TOPIC_ID=your-topic-id \
VE_TLS_ACCESS_KEY_ID=your-ak \
VE_TLS_ACCESS_KEY_SECRET=your-sk \
./build/ve_tls_demo_real --count 1 --wait-ms 15000
```

Bricks 真实发送 demo 从环境变量读取 endpoint、topic 和凭证：

```sh
VE_TLS_ENDPOINT=https://tls-cn-beijing.volces.com \
VE_TLS_REGION=cn-beijing \
VE_TLS_TOPIC_ID=your-topic-id \
VE_TLS_ACCESS_KEY_ID=your-ak \
VE_TLS_ACCESS_KEY_SECRET=your-sk \
VE_TLS_COMPRESS_TYPE=none \
./build-bricks-real/ve_tls_bricks_demo_real --count 1 --timeout-ms 15000
```

如果用 libcurl 直接发送 Bricks 输出的 headers，注意保留空值签名头。`x-tls-hashkey: ` 即使为空也参与签名；libcurl 中不能把它变成删除 header 的 `Header:` 语义，demo 会把空值 header 转成 `Header;`。

## 性能与体积

2026-06-02 在开发机 Linux x86_64 / Debian / GCC 12.2.0 / commit `ce5dfcc` 实测：

| 目标 | 构建参数 | 文件大小 |
| --- | --- | ---: |
| `libve_tls_core.a` | `MinSizeRel`, full core, LZ4 on | `201030 bytes` |
| `libve_tls_bricks_core.a` | `MinSizeRel`, Bricks LZ4 off | `40298 bytes` |
| `libve_tls_bricks_core.a` | `MinSizeRel`, Bricks LZ4 on | `70784 bytes` |
| pack-only 最小可执行文件 | `-Os -ffunction-sections -fdata-sections -Wl,--gc-sections -s` | `27024 bytes` |
| proto+pack 最小可执行文件 | 同上 | `31120 bytes` |
| `ve_tls_bricks_demo_real` | Release, curl + LZ4 | `133304 bytes` |

`nm -g` forbidden-symbol 检查确认 `ve_tls_bricks_core` 中没有 `pthread`、`curl`、`ve_tls_producer`、`ve_tls_env`、retry、metrics、persistence、file runtime 符号。

CPU-only benchmark：

| 场景 | 结果 |
| --- | --- |
| `100000 x 10 logs x 256B`, `none`, zero-copy | `41.139 us/req`, `24307.85 req/s`, `65.47 MiB/s`, SDK heap peak `13312 bytes` |
| `10000 x 1 log x 16B`, `none`, zero-copy | `12.074 us/req`, `82821.22 req/s`, SDK heap peak `2736 bytes` |

更多体积和调优数据见 [docs/bricks.md](docs/bricks.md) 与 [docs/tuning.md](docs/tuning.md)。

## 真实环境验证

同一开发机上，读取真实 TLS BOE 环境变量并绕过代理后实测：

| 场景 | 结果 |
| --- | --- |
| `compress_type=none`, 单次发送 | `curl=0`, `http=200`, request body `86 bytes`, latency `178.984 ms` |
| `compress_type=lz4`, 单次发送 | `curl=0`, `http=200`, request body `77 bytes`, latency `158.703 ms` |
| `compress_type=lz4`, 顺序 300 次 | `300/300` 成功，`27.79 req/s`, 平均 `35.973 ms`, min `7.289 ms`, max `244.350 ms` |

该数据验证 Bricks 生成的 protobuf body、TLS V4 签名、签名头和 curl 样例 transport 可被服务端接受。它不是并发压测；当前 demo 是顺序发送工具。

## 退出语义与可靠性边界

Full Producer 的推荐退出顺序是：先停止业务侧产生日志，再 `ve_tls_producer_close()` 等待 drain，最后 `ve_tls_producer_destroy()` 释放资源。

Bricks 没有 producer 生命周期。调用方只需要在发送完成后调用 `ve_tls_bricks_request_free()`，并按 body ownership 规则管理传入的 protobuf buffer。

Bricks 不提供进程崩溃后的本地恢复，也不保证请求重试成功。需要可靠投递时，调用方必须在 Bricks 外部实现持久化、重放、重试、限流和监控。

## 文档

- [Bricks 设计、体积和真实验证](docs/bricks.md)
- [配置字段](docs/config-fields.md)
- [调优与性能测试](docs/tuning.md)
- [重试策略](docs/retry-policy.md)
- [签名与鉴权](docs/signing.md)
- [错误模型](docs/error-model.md)
- [指标与观测](docs/metrics.md)
- [安全建议](docs/security.md)

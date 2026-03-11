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

### 真实环境 Demo

- 可执行 demo：`tools/real_demo.c`
- 支持通过环境变量或配置文件注入参数：`tools/real_demo.env`

示例：

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DVE_TLS_ENABLE_CURL=ON
cmake --build build
./build/ve_tls_demo_real --config tools/real_demo.env --duration-s 60 --wait-ms 3000
```

## 退出语义

- 优雅退出：`ve_tls_producer_close(p, timeout_ms)`
  - 停止接收新写入
  - 触发 flush 并等待队列与在途发送 drain（超时返回 `VE_TLS_TIMEOUT`）
- 强制退出：`ve_tls_producer_destroy(p)`
  - 立即停止 worker/sender 并释放资源，允许丢弃未处理数据

## 文档索引

- master 能力清单：docs/master-capabilities.md
- 配置字段：docs/config-fields.md
- 重试策略：docs/retry-policy.md
- 签名：docs/signing.md
- 错误模型：docs/error-model.md
- 指标：docs/metrics.md
ve_tls_producer_destroy(p);
```

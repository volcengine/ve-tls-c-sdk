# 错误模型

## 错误结构

Full Producer 的发送错误对象应包含：

- request_id
- http_code
- error_code
- error_message
- retryable
- result
- log_id 范围

写入接口也会直接返回错误。队列预算不足、全局 breaker 入口快速失败、或 `DROP_WITH_CALLBACK` 入口丢弃时，返回值是 `VE_TLS_DROP_ERROR`。`DROP_WITH_CALLBACK` 不是成功入队，不能返回 `VE_TLS_OK`。

Bricks tiny core 没有发送错误对象，也没有 callback。公开错误面是 `ve_tls_bricks_pack_request()` 的 `int` 返回值，以及调用方 transport 自己产生的 HTTP/网络错误。

Bricks pack 返回值：

| rc | 含义 |
| ---: | --- |
| `0` | pack 成功，`out` 已填充 |
| `-1` | 参数非法、内存分配失败、URL/header/signing 构造失败，或压缩内部失败 |
| `-3` | 请求了未知压缩类型，或请求了未编译进 Bricks target 的 LZ4/ZLIB |

`ve_tls_bricks_request_free()` 可以安全释放成功生成的 request，并会清零结构体。失败时 `ve_tls_bricks_pack_request()` 会清理内部临时资源。

## 错误分类

Full Producer：

- ClientError：参数非法、配置缺失、序列化失败
- NetworkError：DNS、连接、超时、EOF 等
- ServerError：HTTP 5xx
- Throttled：HTTP 429
- AuthError：签名错误、过期、权限不足

Bricks：

- PackInputError：`config`、body 或 `out` 为空，body size 为 0。
- PackAllocError：URL、headers、signature 或 body copy 分配失败。
- PackCompressionError：压缩失败、压缩类型未知、或压缩支持未编译。
- SigningError：签名输入不足、签名计算失败。
- TransportError：HTTP client 产生，Bricks core 不感知。
- ServiceError：TLS 服务端返回，Bricks core 不解析。

## 可重试判定

Full Producer：

- Throttled、ServerError、部分 NetworkError 可重试。
- AuthError 默认不可重试，除非上层能刷新凭证并重新签名。

Bricks：

- `rc=-1` 通常不可盲目重试，应先判断是否是调用方参数、内存压力或 body 生命周期问题。
- `rc=-3` 不可通过重试解决，需要改 `compress_type` 或重新编译 Bricks 压缩选项。
- HTTP 429/5xx/网络超时等 transport 错误可按调用方 retry policy 重试。
- `RequestExpired`、签名时间漂移或 token 过期需要刷新时间/凭证并重新 pack。

## 回调语义

Full Producer 的 `send_done` / `send_done_v2` 回调返回：

- result
- request_id
- http_code
- error_code
- error_message
- retryable
- log_id 范围

Bricks 没有回调。调用方应在 transport 完成后自己构造等价事件，例如：

```text
result=success|failed
pack_rc=0
http_code=200
request_id=...
retry_attempt=0
body_bytes=...
```

如果需要和 Full Producer 指标兼容，建议在调用方事件中保留 `request_id`、`http_code`、`error_code`、`error_message`、`retryable` 这几个字段。

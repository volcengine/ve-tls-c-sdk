# 错误模型

发送失败时，`send_done_v2` 回调会收到 `ve_tls_error`。成功发送时该参数可以为空。

## 错误字段

| 字段 | 说明 |
| --- | --- |
| `request_id` | TLS 服务端返回的 request id。请求未到达服务端时可能为空。 |
| `http_code` | HTTP 状态码。网络层错误通常为 `0`。 |
| `error_code` | 服务端或 SDK 生成的错误码。 |
| `error_message` | 错误说明。 |
| `transport_kind` / `transport_code` | HTTP adapter 提供的传输层错误信息。 |
| `retryable` | SDK 对该错误的重试判断。 |

## 常见分类

- `ClientError`：参数非法、配置缺失、序列化失败。
- `NetworkError`：DNS、连接、超时、EOF 等传输层错误。
- `ServerError`：HTTP 5xx。
- `Throttled`：HTTP 429。
- `AuthError`：签名错误、凭证过期或权限不足。

## 重试判断

SDK 会重试部分 `NetworkError`、`ServerError` 和 `Throttled`。`AuthError` 默认不重试；使用临时凭证时，应先确认 `credentials_provider` 能在凭证过期前返回新凭证。

业务侧记录失败日志时，建议带上 `result`、`request_id`、`http_code`、`error_code`、`retryable` 和 log id 范围。不要打印请求体、AK/SK、security token 或完整 Authorization header。

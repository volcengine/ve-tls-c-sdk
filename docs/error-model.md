# 错误模型

发送完成时，`send_done_v2` 回调会返回 `ve_tls_result`、批次 log id 范围和 `ve_tls_error`。成功发送时 `ve_tls_error` 可以为空。

## `ve_tls_result`

| 值 | 说明 |
| --- | --- |
| `VE_TLS_OK` | 当前操作成功，或批次发送成功。 |
| `VE_TLS_INVALID` | 参数非法、配置缺失或状态不允许。 |
| `VE_TLS_DROP_ERROR` | 因背压、队列满、终态失败或策略选择导致丢弃。 |
| `VE_TLS_PERSISTENT_ERROR` | Persistent append、recover、checkpoint 或目录操作失败。 |
| `VE_TLS_CLOSED` | Producer 已关闭。 |
| `VE_TLS_TIMEOUT` | 阻塞等待或 close 超时。 |

## `ve_tls_error`

| 字段 | 说明 |
| --- | --- |
| `request_id` | 服务端返回的 request id。请求未到达服务端时可能为空。 |
| `http_code` | HTTP 状态码。网络层错误通常为 `0`。 |
| `error_code` | 服务端或 SDK 生成的错误码。 |
| `error_message` | 错误说明。 |
| `transport_kind` / `transport_code` | HTTP adapter 提供的传输层错误信息。 |
| `retryable` | SDK 对该错误的重试判断。 |

## 常见分类

- 参数或配置错误：endpoint、region、topic、凭证、persistent 路径或日志内容非法。
- 网络错误：DNS、连接失败、超时、EOF、连接重置。
- 服务端错误：HTTP 5xx 或限流。
- 鉴权错误：签名错误、凭证过期或权限不足。
- 本地资源错误：内存预算不足、send queue 满、persistent quota 不足。

## Persistent 相关错误

Persistent 模式下，失败可能发生在发送前：

- append segment 失败：通常是目录不可写、磁盘不足或参数不合法。
- sync segment 失败：`add_log` 或 flush/close 返回 `VE_TLS_PERSISTENT_ERROR`；write 已完成时记录仍可能被 recover。
- recover 失败：通常是目录格式异常、lease 冲突或存储文件损坏超过可修复范围。
- checkpoint 写入失败：可能导致下一次 recover 重放更多日志。
- quota 命中：按 `persistent_overflow_policy` 返回失败、阻塞或丢弃。

业务侧记录失败日志时，建议带上 `result`、`request_id`、`http_code`、`error_code`、`retryable`、`start_id` 和 `end_id`。不要打印请求体、AK/SK、security token 或完整 Authorization header。

# 签名与鉴权

SDK 发送 PutLogs 请求时使用 TLS V4 签名。业务侧只需要提供 endpoint、region、topic 和凭证；签名、摘要和必要请求头由 SDK 完成。

## 凭证

支持两种方式：

- 静态凭证：设置 `access_key_id`、`access_key_secret`，可选 `security_token`。
- 动态凭证：设置 `credentials_provider`，由回调返回 AK/SK/token 和过期时间。

使用临时凭证时，建议设置：

- `credentials_expire_advance_ms`：在过期前提前刷新。
- `credentials_refresh_min_interval_ms`：避免失败时频繁刷新。

## 签名输入

签名前会对 URI、query 和参与签名的 header 做 canonicalization。实现需要保持这些行为稳定：

- URI 编码规则固定。
- query 中空格和 `+` 的处理一致。
- body 摘要参与签名。
- 临时凭证请求会携带 security token。

接入方不需要手写签名。只有在排查签名失败时，才需要检查本机时间、region、endpoint、topic 和凭证是否匹配。

## 常见问题

- 本机时间漂移过大：可能导致请求过期或签名校验失败。
- region 和 endpoint 不匹配：签名作用域错误。
- 临时凭证已过期：检查 `credentials_provider` 是否提前刷新。
- 打印敏感信息：排障日志不要输出 AK/SK、security token、完整 Authorization header 或完整请求体。

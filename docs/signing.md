# 签名与鉴权

SDK 发送 PutLogs 请求时使用 TLS V4 签名。业务侧只需要提供 endpoint、region、topic 和凭证；签名细节由 SDK 完成。

## 请求头

SDK 会写入以下请求头：

- `X-Date`
- `X-Content-Sha256`
- `Authorization`
- `X-Security-Token`，仅临时凭证需要

## 归一化规则

签名前会对 URI、query 和 header 做 canonicalization。实现需要保持以下行为稳定：

- URI 编码规则固定。
- query 中空格和 `+` 的处理一致。
- 参与签名的 header 集合固定，包含需要签名的 `X-` 前缀请求头。

## 内容摘要

- `X-Content-Sha256` 参与签名。
- body 存在时，SDK 会按 TLS 服务端兼容规则处理 `Content-MD5`。
- 临时凭证请求会带上 `X-Security-Token`，该 token 不应出现在业务日志中。

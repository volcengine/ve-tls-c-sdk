# 安全建议

本文档给 SDK 使用方看。漏洞披露流程见根目录 [SECURITY.md](../SECURITY.md)。

## 凭证

- 不要把 AK/SK/security_token 写进源码、README 命令行、CI 日志或 benchmark 输出。
- 真实发送测试使用进程环境变量或本地 env 文件。env 文件不要提交到仓库。
- 使用临时凭证时优先接入 `credentials_provider`，并设置合理的提前刷新时间。
- 发送回调和 metrics sink 里不要输出完整 `Authorization` header、AK/SK 或 token。

## 日志与调试

- `http_debug` 只适合本地排查。线上开启前先确认日志会脱敏。
- 业务日志可以记录 `request_id`、HTTP code、错误码和批次 log_id 范围。
- 不要记录完整请求体。必须采样时，只保留脱敏后的字段。

## 签名与时间

- SDK 生成 `X-Date`、`X-Content-Sha256` 和 `Authorization` 请求头。
- 本地时间漂移会导致 `RequestExpired` 或签名失败。生产机器需要可靠的时间同步。
- `security_token` 存在时会写入 `X-Security-Token`。

## 传输安全

- 默认使用 HTTPS，并开启 peer/host 证书校验。
- 只有受控测试环境可以关闭 `tls_verify_peer` 或 `tls_verify_host`。不要把关闭校验的配置带到生产。
- 使用代理时，确认代理不会记录敏感 header。

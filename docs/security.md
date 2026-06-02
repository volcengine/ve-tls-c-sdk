# 安全规范

## 机密信息

Full Producer 和 Bricks 都必须遵守：

- 禁止在日志、metrics label、callback 或错误事件中输出 AK/SK/security token。
- 禁止输出完整 Authorization header。
- 禁止默认输出完整请求体；排障采样必须脱敏。
- 凭证建议来自进程安全配置、临时凭证服务或调用方安全存储，不要提交到仓库。

Bricks 额外注意：

- `req.headers` 中包含 Authorization 和可选 `X-Security-Token`，不能原样打印。
- `ve_tls_bricks_demo_real` 从环境变量读取凭证，仅用于验证；不要把真实 env 文件纳入版本控制。
- `xdate` 可用于确定性测试；生产中固定过旧时间会触发 `RequestExpired` 风险。

## 签名与时间

Full Producer：

- SDK 内部生成 `X-Date` 并签名。
- 使用临时凭证时可通过 `credentials_provider` 刷新。
- 本地时间漂移导致的签名过期应在错误回调中体现。

Bricks：

- `ve_tls_bricks_pack_request()` 内置 TLS V4 signing。
- `config->xdate` 为空时由签名模块生成时间；非空时使用调用方提供的固定时间。
- Bricks 不会自动向服务端校时，也不会自动刷新凭证。
- 重试时如果复用已 pack 的 request，要确保 `X-Date` 仍在服务端接受窗口内；更稳妥的方式是重新 pack 并重新签名。

## 传输安全

Full Producer：

- 使用 libcurl adapter 时可配置 `tls_verify_peer`、`tls_verify_host`、`ca_cert_path`、`proxy`、`tcp_keepalive` 等字段。
- 生产环境应默认开启证书校验。

Bricks：

- Bricks core 没有 transport 层，不做 TLS 握手或证书校验。
- 证书校验、代理、超时、HTTP debug、连接复用都由调用方 HTTP client 负责。
- 调用方发送时必须保留 Bricks 输出的签名头，包括空值 `x-tls-hashkey`。
- 如果接入环境有企业代理，需确认 TLS endpoint 是否应该走代理。开发机实测中默认代理会对目标 endpoint CONNECT 返回 403，直连后请求成功。

# 签名与鉴权规范

## 目标

说明当前分支发送 TLS PutLogs 请求时的签名和鉴权规则，并区分 Full Producer 与 Bricks tiny core 的责任边界。

Full Producer 在 SDK 内部完成编码、压缩、签名和发送。Bricks 只完成编码 helper、可选压缩、签名和 request packing，调用方负责发送。

## 签名算法

当前实现使用 TLS V4 签名：

- scope 包含 `region` 与 `service=TLS`
- method 固定为 `POST`
- path 固定为 `/PutLogs`
- query 为 `TopicId={topic_id}`
- body 参与 `X-Content-Sha256`

必须写入或参与签名的请求头：

- `Content-Type: application/x-protobuf`
- `Content-MD5`
- `x-tls-apiversion`
- `x-tls-bodyrawsize`
- `x-tls-compresstype`
- `x-tls-hashkey`
- `X-Date`
- `X-Content-Sha256`
- `Authorization`
- `X-Security-Token`，仅当 `security_token` 非空

Bricks 在签名后追加业务统计头：

- `log-count`
- `earliest-log-time`
- `latest-log-time`

## Canonicalization

签名输入规则：

- endpoint host 参与签名。
- canonical URI 使用 `/PutLogs`。
- canonical query 使用 `TopicId={topic_id}`。
- body 使用最终发送 body：如果压缩开启，签名压缩后的 body。
- 空 hash key 仍输出 `x-tls-hashkey: ` 并参与签名。

Bricks 输出的 `req.headers` 是换行分隔文本，调用方 transport 必须逐行发送。不要过滤空值签名头。使用 libcurl 时，空值 header 需要转换成 `Header;`，否则 `Header:` 会被 libcurl 当作删除 header。

## 内容摘要

SDK 会生成：

- `Content-MD5`：最终发送 body 的 MD5 hex。
- `X-Content-Sha256`：最终发送 body 的 SHA256 hex，参与 Authorization。
- `x-tls-bodyrawsize`：压缩前 raw LogGroupList body size。
- `x-tls-compresstype`：`none` / `lz4` / `zlib`。

如果 `compress_type=none` 且 `body_no_copy=1`，body 指向调用方传入的 raw buffer；摘要仍基于该 buffer 计算。调用方在发送前不能改写 buffer。

## 预签名 URL（可选）

当前分支没有公开的预签名 URL API。不要在文档或接入方案中承诺该能力。

如果后续需要预签名 URL，应新增明确 API，并单独验证 canonical query、过期时间、header 白名单和服务端兼容性。

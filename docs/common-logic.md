# 通用逻辑对齐（volc-sdk-golang / TLS）

## 目标
在 C SDK 中复用火山引擎 TLS 的通用处理逻辑，确保签名、重试、错误结构与请求头行为一致。

## 对齐点
- 签名：V4 签名与认证头写入
- 端点：endpoint/region 校验与拼接规则一致
- 请求头：x-tls-apiversion 与 Content-MD5 处理一致
- 重试：429/5xx/超时/连接异常可重试，支持指数退避与抖动
- 错误：错误码结构与 requestID 解析一致

## TLS Client 重试策略
- 策略模型：指数退避 + 抖动 + 最大间隔 + 总耗时上限 + 最大尝试次数
- 触发条件：HTTP 429/500/502/503、超时、EOF、连接重置/拒绝/不可达等网络错误
- 约束语义：总耗时由 TotalTimeout 控制，单次尝试由请求超时控制

## Producer 重试策略
- 触发条件：非 NoRetryStatusCodeList 且未超出最大重试次数
- 退避算法：首次 baseBackoff，之后随机增量并 clamp 到 maxBackoff
- 重试队列：按 nextRetryMs 排序的延迟队列

## 参考实现
- base/sign.go
- base/client.go
- base/utils.go
- service/tls/client.go
- service/tls/retry.go
- service/tls/errors.go
- service/tls/retry_policy.go
- service/tls/producer/sender.go
- service/tls/producer/retry_queue.go

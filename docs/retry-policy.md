# 重试策略

## 范围

当前分支有两个 profile：

- Full Producer：SDK 内部包含面向批次的 retry policy、延迟队列和可重试错误判定。
- Bricks tiny core：不实现重试，只生成一次 PutLogs 请求；调用方 transport 负责重试。

因此，本文件同时定义 Full Producer 的内置语义，以及 Bricks 调用方应实现的外部语义。

## RetryPolicy（面向请求）

Full Producer 的请求级 retry policy 包含：

- 指数退避（Exponential Backoff）
- 抖动（Randomization Factor）
- 最大间隔（Max Interval）
- 总耗时上限（Total Timeout）
- 最大尝试次数（Max Attempts）

Bricks 没有 `retry_policy` 字段。调用方可以直接复用上述模型，但必须自己保存可重试请求所需的数据：

- 原始 LogGroupList body，或重新编码 body 所需的业务日志
- `endpoint`、`region`、`topic_id`、AK/SK/token
- `log_count`、`earliest_log_time_ms`、`latest_log_time_ms`
- 每次重试的最新 `X-Date`，除非业务明确需要固定时间测试

## 可重试条件

### HTTP 可重试

建议可重试：

- `429`
- `500`
- `502`
- `503`

建议不可重试：

- 签名错误、凭证错误、权限错误
- 参数错误、topic 不存在、body 格式错误
- 明确的服务端不可重试业务错误

Bricks core 看不到 HTTP code。`ve_tls_bricks_demo_real` 只把 libcurl 结果打印出来，不做自动 retry。

### 网络可重试

建议可重试：

- 连接超时、读写超时
- EOF / connection reset
- `ECONNRESET`
- `EPIPE`
- `ETIMEDOUT`
- `ECONNREFUSED`
- `EHOSTUNREACH`
- `ENETUNREACH`

证书校验失败、代理鉴权失败、DNS 配置错误是否重试，应由调用方按接入环境判断。配置类错误通常应先修配置，不要靠重试掩盖。

## 停止条件

Full Producer：

- 超出 Total Timeout
- 达到 Max Attempts；若 MaxAttempts <= 0，则仅受 TotalTimeout 限制
- 错误不满足可重试条件
- producer shutdown 或队列策略要求丢弃

Bricks 调用方：

- 超出调用方定义的总超时
- 达到调用方定义的最大尝试次数
- 原始 body 生命周期无法继续保证
- 凭证已过期且无法刷新
- 队列或持久化预算不足
- 错误被判定为不可重试

## 约束语义

Full Producer：

- 总重试上下文限制整次请求耗时。
- 单次尝试上下文限制一次 HTTP 请求耗时，避免错误 cancel 传播影响请求结果判定。
- retry delay 期间批次仍占用 SDK 内部预算。

Bricks：

- `ve_tls_bricks_pack_request()` 是一次同步 pack 调用，不持有全局重试上下文。
- 如果每次重试都重新 pack，请重新生成签名时间，避免 `RequestExpired`。
- 如果复用已 pack 好的 request，需要确认 `X-Date` 仍在服务端接受窗口内。
- no-copy body 模式下，重试期间调用方不能释放或改写 body。

## Producer 重试（面向批次）

Full Producer 内部语义：

- 不重试：命中 NoRetryStatusCodeList、已 shutdown、达到最大重试次数。
- 退避：首次 baseBackoff，后续每次增加随机增量并 clamp 到 maxBackoff。
- 队列：以 nextRetryMs 排序的延迟队列。
- 观测：通过 send callback、metrics 和错误结构暴露最终结果。

Bricks 没有批次队列。外部实现如果需要与 Full Producer 类似的语义，应至少记录：

- `attempts_total`
- `retry_delay_ms`
- `last_http_code`
- `last_error_code`
- `last_request_id`
- `body_bytes`
- `topic_id`
- `hash_key`

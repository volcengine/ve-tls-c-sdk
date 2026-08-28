# 重试策略

SDK 的重试分两层：请求级重试策略和 Producer 批次重试队列。Persistent 模式会把“已进入本地持久化”的日志作为 recover 范围，但不会改变请求级重试规则。

## 请求级策略

`ve_tls_retry_policy` 控制单个 HTTP 请求的重试节奏：

| 字段 | 说明 |
| --- | --- |
| `initial_interval_ms` | 首次退避时间。 |
| `max_interval_ms` | 单次退避上限。 |
| `multiplier` | 退避倍数。 |
| `randomization_factor` | 随机抖动比例。 |
| `total_timeout_ms` | 整次请求重试的总耗时上限。 |
| `max_attempts` | 最大尝试次数。小于等于 `0` 时主要受 `total_timeout_ms` 限制。 |

`request_timeout_ms` 是单次 HTTP 请求超时，当前默认 `50000`。它不等于整批日志从入队到最终回调的总耗时。

## 可重试错误

HTTP 状态码：

- `429`
- `500`
- `502`
- `503`
- `504`

常见网络错误：

- 超时
- EOF
- `ECONNRESET`
- `EPIPE`
- `ETIMEDOUT`
- `ECONNREFUSED`
- `EHOSTUNREACH`
- `ENETUNREACH`

不在可重试列表里的错误会进入最终失败回调。

## 停止条件

重试会在这些情况停止：

- 达到 `total_timeout_ms`。
- 达到 `max_attempts`。
- 错误不满足可重试条件。
- Producer 正在关闭，且无法在 close 超时内继续 drain。

## Producer 批次重试

发送失败但仍可重试时，批次会进入延迟队列。延迟队列按下一次重试时间排序，到期后重新交给 sender。

达到最大重试次数或总超时后，Memory 模式会结束该批次并返回终态回调。Persistent 模式若最后一次错误仍标记为 retryable，则不会把这次“请求级预算耗尽”当成日志终态：对应 WAL 保持未 ACK，live Producer 会按带抖动的指数退避自动调度下一轮请求级重试。跨轮退避上限固定为 5 分钟。

命中不可重试状态码时不会进入下一轮自动重试，WAL 仍保持未 ACK；接入方必须修正配置或 payload，再通过重启/recover 重新处理。Producer close/destroy 时，已进入跨轮退避的任务会释放内存态、保留 WAL，避免停机被最长 5 分钟的延迟队列阻塞。

## Persistent 下的处理边界

- 批次最终成功后，SDK 会推进 checkpoint。
- 默认情况下发送失败不推进 checkpoint，包括 retryable exhausted、不可重试响应和内部 queue/budget 失败。Retryable exhausted 会在 live Producer 内自动开启下一轮；不可重试失败需要显式修正后 recover。
- `401/403` 和凭证刷新失败会分类为 authentication failure。`VE_TLS_PAUTH_RETAIN` 是兼容默认：保留 WAL 并等待凭证版本更新，本轮认证失败只计入失败指标，不发终态 callback；凭证更新后成功发送时只发一次成功 callback。只有用户显式选择 `VE_TLS_PAUTH_DROP` 时才把对应范围作为终态 drop 推进 checkpoint 并报告失败 callback。
- 除显式认证 drop 和 persistent max-age drop 外，当前没有发送失败后的通用永久 drop/quarantine 策略。无法发送的毒丸记录会在 recover 时继续出现，接入方应监控失败 callback 并隔离错误配置或 payload。
- success callback 与 checkpoint 持久化之间存在窗口；进程在这个窗口崩溃时，recover 可能重放少量已经成功发送过的日志。
- checkpoint 保存失败会保留 dirty 状态，并通过 `persistent_checkpoint_save_failed` metric 暴露对应 log id 范围。
- 如果网络长期不可用，日志会继续占用 persistent 空间，直到触发 overflow policy。

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

达到最大重试次数、命中不可重试状态码或 Producer 关闭时，批次不会再入队。最终结果通过发送回调返回。

## Persistent 下的处理边界

- 批次最终成功后，SDK 会推进 checkpoint。
- 不可重试终态失败也会作为已处理范围推进，避免 recover 后无限重放同一批毒丸日志。
- success callback 与 checkpoint 持久化之间存在窗口；进程在这个窗口崩溃时，recover 可能重放少量已经成功发送过的日志。
- 如果网络长期不可用，日志会继续占用 persistent 空间，直到触发 overflow policy。

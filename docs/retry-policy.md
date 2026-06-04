# 重试策略

SDK 的重试分两层：请求级重试策略和 Producer 批次重试队列。

## 请求级策略

`ve_tls_retry_policy` 控制单个 HTTP 请求的重试节奏：

- `initial_interval_ms`：首次退避时间。
- `max_interval_ms`：单次退避上限。
- `multiplier`：退避倍数。
- `randomization_factor`：随机抖动比例。
- `total_timeout_ms`：整次请求的总耗时上限。
- `max_attempts`：最大尝试次数。小于等于 `0` 时只受 `total_timeout_ms` 限制。

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

不在可重试列表里的错误会直接进入最终失败回调。

## 停止条件

重试会在以下情况停止：

- 达到 `total_timeout_ms`。
- 达到 `max_attempts`。
- 错误不满足可重试条件。
- Producer 已关闭。

## Producer 批次重试

发送失败但仍可重试时，批次会进入延迟队列。延迟队列按下一次重试时间排序，到期后重新交给 sender。

达到最大重试次数、命中不可重试状态码或 producer 正在关闭时，批次不会再入队。最终结果会通过发送回调返回。

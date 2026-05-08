# 重试策略规范

## 范围
本文件定义 C SDK 的重试策略，并说明 Producer 异步队列中的批次重试模型。

## RetryPolicy（面向请求）
- 指数退避（Exponential Backoff）
- 抖动（Randomization Factor）
- 最大间隔（Max Interval）
- 总耗时上限（Total Timeout）
- 最大尝试次数（Max Attempts）

## 可重试条件
### HTTP 可重试
- 429
- 500/502/503

### 网络可重试
- 超时（net.Error.Timeout）
- EOF
- 连接异常：ECONNRESET/EPIPE/ETIMEDOUT/ECONNREFUSED/EHOSTUNREACH/ENETUNREACH 等

## 停止条件
- 超出 Total Timeout
- 达到 Max Attempts（若 MaxAttempts<=0，则仅受 TotalTimeout 限制）
- 错误不满足可重试条件

## 约束语义
- 总重试上下文限制整次请求耗时
- 单次尝试上下文限制一次 HTTP 请求耗时，避免错误 cancel 传播影响请求结果判定

## Producer 重试（面向批次）
- 不重试：命中 NoRetryStatusCodeList、已 shutdown、达到最大重试次数
- 退避：首次 baseBackoff，后续每次增加随机增量并 clamp 到 maxBackoff
- 队列：以 nextRetryMs 排序的延迟队列

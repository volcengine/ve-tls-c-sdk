# Persistent 模式

Persistent 模式用于“写入 SDK 后，进程崩溃或短时网络失败仍要补发”的场景。它不是 exactly-once，也不是业务侧永久队列。

## 写入和恢复链路

开启 `use_persistent=1` 后，SDK 会先把日志 append 到本地 segment，再进入内存队列和发送路径。进程重启后，接入方需要调用 `ve_tls_producer_recover()`，把 checkpoint 之后的记录重新送回发送路径。

推荐启动顺序：

1. 初始化 `ve_tls_config`，设置 `use_persistent=1` 和 `persistent_file_path`。
2. 创建 Producer。
3. 调用 `ve_tls_producer_recover()`。
4. recover 成功后再接收新的业务日志。

如果新日志先写入，再 recover backlog，业务看到的发送顺序会变得更难解释。除非上层已经接受这种交错，否则不要这么做。

## 文件布局

Persistent 目录包含这些文件：

| 文件 | 说明 |
| --- | --- |
| `manifest` | 记录 persistent store 的基础元信息。 |
| `lease` | 记录当前 owner 和心跳。 |
| `checkpoint` | 记录已经处理到的 log id。 |
| `seg-*.log` | append-only segment 文件，保存待发送或未确认记录。 |

每个 Producer 或进程建议使用独立目录。多个活跃进程写同一个目录会破坏语义，`lease` 只能降低误用概率，不能把它变成多写者队列。

## 语义边界

- SDK 提供 at-least-once。崩溃、重试和 checkpoint 持久化边界可能带来少量重复。
- `success callback` 表示请求已经进入发送成功路径，不表示 checkpoint 已经 durable 落盘。
- 只有服务端请求成功才推进 checkpoint。重试预算耗尽、不可重试响应、凭证刷新失败和内部 queue/budget 暂时失败都不会隐式 ACK 已 append 的记录。
- 发送失败 callback 描述的是本轮发送结果，不代表 persistent 记录已经永久丢弃。当前没有“发送失败后显式永久丢弃”的公共策略。
- 本轮发送结束后，未 ACK 记录保留在 WAL 中；当前实现不会自动开启下一轮长期重试，需要进程重启或再次调用 `ve_tls_producer_recover()` 才会重新入队。
- `add_log` 在 persistent append 之前失败时不在恢复范围内；如果 append 已成功、后续内存入队失败，接口可能返回失败但记录仍会被 recover，调用方需要用 log id 或业务主键处理潜在重复。
- checkpoint 保存失败时保持 dirty，不回收对应记录，并发出 `persistent_checkpoint_save_failed` metric；metric 的两个值分别是本次完成范围的 `start_id` 和 `end_id`。
- checkpoint 损坏时，SDK 会优先保证不漏发；代价是可能扩大重复范围。
- 当前 C core 不对每条日志 append 执行 `fsync`。如果业务需要进程外掉电级保证，需要在上层设计额外的持久化策略。

如果业务不能接受重复，必须使用业务主键或消费侧去重。不要把 SDK 的 at-least-once 解释成 exactly-once。

## 溢出策略

| 策略 | 行为 | 适用场景 |
| --- | --- | --- |
| `VE_TLS_POVERFLOW_REJECT_NEW` | 空间不足时拒绝新日志，`add_log` 返回失败。 | 默认策略，适合不想静默丢弃的业务。 |
| `VE_TLS_POVERFLOW_BLOCK` | 等待回收空间，超过 `persistent_block_timeout_ms` 后返回超时。 | 可以接受业务线程短暂等待的业务。 |
| `VE_TLS_POVERFLOW_DROP_OLDEST_UNACKED` | 删除最老未 ack segment 换空间。 | 明确“保新不保旧”的场景。会牺牲 at-least-once 完整性。 |
| `VE_TLS_POVERFLOW_DROP_NEWEST_SAMPLE` | 按 `persistent_sample_every_n` 采样丢弃新日志。 | 高峰期降采样。 |

## lease 与 stale takeover

`persistent_open_mode` 默认是 `VE_TLS_POPEN_TAKEOVER_IF_STALE`。它适合进程崩溃后由新进程接管同一个目录。

接入时要注意：

- 正常运行的两个进程不应共享一个 `persistent_file_path`。
- `persistent_lease_timeout_ms` 不要设得过小，否则慢机器或长调度停顿可能造成误接管。
- `FAIL_IF_OWNED` 更保守，适合不允许接管的部署方式。

## 关闭

正常退出建议：

1. 先停止业务侧写入。
2. 调用 `ve_tls_producer_close(producer, timeout_ms)`。
3. close 返回后调用 `ve_tls_producer_destroy(producer)`。

如果 close 超时，未完成的日志会留在 persistent 目录中。下一次启动 recover 时会继续处理，可能带来重复。

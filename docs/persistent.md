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

`manifest` 当前格式版本为 V2。V1 会在打开时兼容升级；未知版本或损坏内容会使打开失败，SDK 不会先覆盖原文件。WAL record V2 在扩展字段中保存 `enqueue_time_ms`，没有该字段的旧记录按 V1 读取且时间为 `0`。只有显式配置 max-age 后，该时间才会在 recover 时参与超龄判断；时间为 `0` 或无法判断年龄的旧记录不会被误删。

## Recover max-age

Core 默认 `persistent_max_log_delay_ms=0`，即关闭 max-age，保持已有调用方行为。
启用后只在 `ve_tls_producer_recover()` 读取 WAL 时处理超龄记录：

- `VE_TLS_PEXPIRED_REWRITE`：把可解析日志的时间字段重写为本次 recover 时间后继续发送；原 WAL record 不就地改写。无法解析的 raw payload 保留原样发送，不会因重写失败被误删。
- `VE_TLS_PEXPIRED_DROP`：把该记录作为显式终态 drop，记录指标并推进连续 checkpoint。
- `enqueue_time_ms <= 0`、本地时钟回退或年龄无法判断：按未过期处理。

语言 wrapper 可以定义自己的公开默认。例如 iOS 第一阶段可显式使用“7 天 + rewrite”；
这不改变 C Core 默认，也不要求 manifest 或 WAL 升级到 V3。

## 落盘模式

| 模式 | `add_log` 成功边界 | 主动同步边界 |
| --- | --- | --- |
| `VE_TLS_PDURABILITY_BUFFERED_WAL` | segment `write` 成功，数据可能仍在 OS page cache | segment rotation、`ve_tls_producer_flush()` 和正常 close |
| `VE_TLS_PDURABILITY_SYNC_WAL` | segment `write` 及该文件的 `fsync` 成功 | 每条 append；无 dirty 数据时 flush 不重复 `fsync` |

`VE_TLS_PDURABILITY_DEFAULT` 当前解析为 buffered WAL。旧字段 `force_flush_disk=1` 在 durability 未显式设置时兼容映射为 sync WAL。

## 容量与水位

`persistent_max_bytes`、`persistent_max_records` 和 `persistent_max_segments` 是独立硬上限。预测 append 后任一维度超过硬上限时，SDK 先回收可安全删除的 durable ACK closed segment；仍无空间时才执行 overflow policy。

软水位采用 hysteresis：bytes、records、segments 任一已配置维度达到 high 即触发压力回收；回收按 segment 从旧到新进行，直到所有已配置维度都不高于 low，或遇到最旧的不可回收 segment。配置必须满足 `0 < low < high <= 100`。

active segment、未 durable ACK segment 和 replay cursor 对应 segment 不会被水位回收。replay cursor 形成顺序屏障，清除后后续压力回收会从该 segment 继续。

## 语义边界

- SDK 提供 at-least-once。崩溃、重试和 checkpoint 持久化边界可能带来少量重复。
- `success callback` 表示请求已经进入发送成功路径，不表示 checkpoint 已经 durable 落盘。
- 服务端请求成功会推进 checkpoint。重试预算耗尽、普通不可重试响应和内部 queue/budget 暂时失败不会隐式 ACK 已 append 的记录。
- `401/403` 与凭证刷新失败属于 authentication failure。默认 `VE_TLS_PAUTH_RETAIN` 保留 WAL；用户显式选择 `VE_TLS_PAUTH_DROP` 时，才作为终态 drop 推进 checkpoint。发送失败 callback 仍描述本轮失败。
- recover 发现超龄记录且配置 `VE_TLS_PEXPIRED_DROP` 时，也会作为显式终态 drop 推进 checkpoint。除这些明确策略外，发送失败不代表 persistent 记录永久丢弃。
- 本轮发送结束后，未 ACK 记录保留在 WAL 中；当前实现不会自动开启下一轮长期重试，需要进程重启或再次调用 `ve_tls_producer_recover()` 才会重新入队。
- `add_log` 在 persistent append 之前失败时不在恢复范围内；如果 append 已成功、后续内存入队失败，接口可能返回失败但记录仍会被 recover，调用方需要用 log id 或业务主键处理潜在重复。
- sync WAL 中，record `write` 成功但 `fsync` 失败时，`add_log` 返回 `VE_TLS_PERSISTENT_ERROR`，已写 record 仍保留并可在后续 flush/recover 中出现。调用方重试可能形成重复。
- checkpoint 保存失败时保持 dirty，不回收对应记录，并发出 `persistent_checkpoint_save_failed` metric；metric 的两个值分别是本次完成范围的 `start_id` 和 `end_id`。
- checkpoint 损坏时，SDK 会优先保证不漏发；代价是可能扩大重复范围。
- WAL 中的 backlog 不绑定写入时的 endpoint、region 或 topic。调用 `ve_tls_producer_update_endpoint()` 后，尚未进入发送路径的旧 backlog 和后续 recover 记录都会使用当前 target；已经捕获发送快照的请求可能仍使用旧 target。
- 如果业务不能接受旧 backlog 改投新 target，不要在同一个 persistent 目录上更新 target。当前 SDK 不提供 drain old target、target fingerprint 或自动拆分 store；调用更新接口表示接入方接受改投风险。
- target 更新时若本地仍有 backlog，SDK 发出 `persistent_backlog_retarget(records, wal_bytes)` 事件用于告警，不阻止更新。

如果业务不能接受重复，必须使用业务主键或消费侧去重。不要把 SDK 的 at-least-once 解释成 exactly-once。

## 溢出策略

| 策略 | 行为 | 适用场景 |
| --- | --- | --- |
| `VE_TLS_POVERFLOW_REJECT_NEW` | 空间不足时拒绝新日志，旧 WAL 不变，`add_log` 返回失败。 | 默认策略，适合不想静默删除已接受日志的业务。 |
| `VE_TLS_POVERFLOW_BLOCK` | 旧 WAL 不变；等待回收空间，超过 `persistent_block_timeout_ms` 后返回超时。 | 可以接受业务线程短暂等待的业务。 |
| `VE_TLS_POVERFLOW_DROP_OLDEST_UNACKED` | 删除最老未 ack closed segment 换空间，并发出 `persistent_overflow_drop_oldest_unacked`。 | 明确“保新不保旧”的场景。会牺牲已接受日志的 at-least-once 完整性。 |
| `VE_TLS_POVERFLOW_DROP_NEWEST_SAMPLE` | 按 `persistent_sample_every_n` 对新日志选择等待或拒绝；不会删除旧 WAL。 | 高峰期优先保留既有 backlog。 |

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

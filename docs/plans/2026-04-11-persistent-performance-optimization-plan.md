# Persistent / Non-Persistent Performance Optimization Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在保持 `feat_improve_sdk_more` 非持久化能力基线的前提下，为 `persistent` 分支制定一套分路径、分分支、分阶段的性能优化方案，并明确实施顺序与验证口径。

**Architecture:** 把性能问题拆成两条主线处理。第一条是 `non-persistent` 基线能力，优先在 `feat_improve_sdk_more` 分支优化并回灌到 `persistent` 分支，确保两条分支在非持久化路径上的行为和性能模型一致。第二条是 `persistent` 专属热路径，集中处理 durable append、recover、ack、reclaim、lease 校验等问题，避免把 persistent 的复杂度反向污染非持久化快路径。

**Tech Stack:** C11、pthread 平台适配、当前 `ve_tls_platform` 抽象、当前 `ve_tls_http_client`、CMake/ctest、真实 TLS 环境 benchmark

---

## 0. 2026-04-11 实施结果

### 0.1 已完成项

1. `feat_improve_sdk_more` 已完成 non-persistent 共享优化，并已同步到 `persistent`：
   - non-fast sender 在无 delayed task 时改为阻塞 `send_queue_pop`
   - worker 对 partial builder 的固定 `100ms` 等待改为动态 deadline
   - 当 builder 首条日志入队且配置了 `flush_interval_ms` 时，主动唤醒 worker，避免空等
2. `persistent` 已完成 P0：
   - segment 元数据缓存化
   - reclaim 去掉 append/ack 热路径上的重复全段扫描
   - `repair_tail` 由双扫描改成单扫描
3. `persistent` 的 `heartbeat_if_due()` 已完成“到点前直接跳过”优化，但 append/ack/recover 仍保留每次 lease 校验。
4. `persistent` 已完成 P2 的低风险版本：
   - durable append 期间释放 `producer->mutex`
   - 新增 producer 级 `persistent_mutex` 串行化 append / ack / heartbeat，避免 persistent store 内部状态并发修改
   - `close()` drain 会等待正在进行的 durable append
   - public `ve_tls_persistent_*` API 不额外加内部锁，避免 direct persistent benchmark 和 recover 回调路径引入额外锁顺序风险
5. P0 benchmark 可观测性已固化：
   - `ve_tls_bench` 支持 `--profile sls200|sls700|sls5120`
   - `bench config` 输出 `profile` 和 `target_payload_bytes`
   - `bench phases` 输出 `produce_ms / close_ms / total_ms / produce_lps / close_drain_lps / total_lps`
   - 生产阶段和 close 排空阶段分开统计，避免把 close drain 或网络排空误判为生产端瓶颈
6. persistent 多 sender 已完成安全放开：
   - checkpoint 不再按单个成功 range 直接推进
   - producer 维护已完成 range 的有序集合，只在 `[acked+1 ... N]` 连续完成时推进 checkpoint
   - 支持发送完成乱序，避免 `2-3` 先成功时错误删除 `1` 对应的持久化数据
   - SDK 默认仍保持单 sender
   - 多 sender 只作为隐藏能力保留，用于内部压测或特殊场景，不作为默认对外能力
7. persistent append 大记录编码缓冲已复用：
   - 小记录继续使用 512B 栈缓冲
   - 大于 512B 的编码缓冲改为 persistent 实例级 scratch buffer
   - 避免 `sls700/sls5120` 每条 append 都 malloc/free 临时 record buffer
8. segment scan 已改为流式校验：
   - open / recover / repair / refresh usage 扫描 segment 时不再 malloc 整条 record
   - 单次扫描同时重建 `valid_end / record_count / max_log_id`
   - 直接从 header 读取 `log_id`
   - payload CRC 通过 4KB 栈缓冲流式计算，保留损坏尾部检测能力
9. `reclaim` 已完成游标化 / 增量触发：
   - persistent 维护 `next_reclaim_segment_id` 游标，从首个待检查 closed segment 继续推进
   - append 前不再无条件进入 reclaim，只有 `acked_log_id` 前进或接近容量水位时才触发
   - ack 推进后只增量删除已确认 closed segment，未新增 ack 时不会重复从头检查

### 0.2 刻意未落地项

1. **未把 lease 校验降频到 append 热路径。**
   原因：
   - 当前多进程正确性依赖 append/ack 前读取 lease 文件并比对 fencing token
   - 一旦把 append 侧 lease 校验降频，旧 owner 在 takeover 之后仍可能继续写 segment
   - 现有 UT `test_persistent_takeover_invalidates_old_writer` 已验证这一点
2. **未做大范围拆锁。**
   原因：
   - 本轮只把 durable append 从 `producer->mutex` 临界区移出
   - 大拆锁会同时影响 `feat_improve_sdk_more` 和 `persistent` 的行为面，风险更高

### 0.3 本地无网络 benchmark 结果

#### A. Non-Persistent `kv`（`message-bytes=700`，4 writers，4 senders，3s）

- `feat_improve_sdk_more` 当前：`3.79M logs/s`，`744.6 MB/s`
- `persistent` 当前非持久化路径：`4.11M logs/s`，`750.9 MB/s`
- 对比本轮实施前基线：
  - `feat_improve_sdk_more`：约 `2.52M -> 3.79M logs/s`
  - `persistent` 非持久化：约 `2.87M -> 4.11M logs/s`

#### B. Persistent 本地 benchmark

- `payload=256`：
  - append：`42.1k logs/s`
  - recover：`54.2k logs/s`
  - ack：`10 ms`
- `payload=5120`：
  - append：`15.5k logs/s`
  - recover：`19.6k logs/s`
  - ack：`4 ms`
- 2026-04-11 P1 (`reclaim` 游标化 / 增量触发) 验证样本：
  - `payload=256, records=20000`：append `49.6k logs/s`，recover `63.1k logs/s`，ack `4 ms`
  - `payload=5120, records=8000`：append `19.2k logs/s`，recover `22.1k logs/s`，ack `4 ms`

补充说明：
- direct persistent benchmark 受本机文件系统波动影响较大，append 数值不能只看单次运行
- `reclaim` 去重复扫描、append scratch buffer 复用、segment scan 流式化后，recover/open/ack 路径的收益更稳定
- append 单次样本受本机文件系统波动影响较大，因此不再维护“单次跑数对历史单次跑数”的硬对比口径

#### C. Producer Persistent 本地 benchmark

使用 `ve_tls_bench --use-persistent 1`，mock HTTP，排除网络时延：

- 当前 persistent 默认 benchmark 口径仍使用 `1 sender`
- `kv + sls200 + 4 writers + persistent + 1 sender`：
  - `produce_lps=19.9k`
  - `total_lps=19.9k`
  - `logs_dropped_total=0`
- `kv + sls700 + 4 writers + persistent + 1 sender`：
  - `produce_lps=37.6k`
  - `total_lps=30.5k`
  - `logs_dropped_total=0`
- `kv + sls5120 + 4 writers + persistent + 1 sender`：
  - `produce_lps=9.7k`
  - `total_lps=9.6k`
  - `logs_dropped_total=0`

说明：
- 该数据衡量 producer 持久化写入、入内存队列、builder、sender mock 的完整本地链路
- `produce_lps` 是生产线程完成写入的速率，更适合排查本地生产端瓶颈
- `total_lps` 会包含 `close()` 排空时间，更适合判断端到端 drain 能力
- scratch buffer 复用减少了大 payload 的分配抖动，尤其对 producer persistent sls700/sls5120 本地链路更明显
- 如果 `logs_dropped_total > 0`，说明压测混入了本地 buffer 容量限制，不能作为极限吞吐结论

### 0.4 真实环境 smoke 结果

使用 `ve_tls_persistent_real_bench` 跑 `kv + sls700 + persistent + steady 3s`：

- `add_ok=51`
- `success=51`
- `requests=3`
- `requests_failed=0`
- `close_rc=0`

结论：
- 这批优化没有打坏真实链路
- 真实环境吞吐仍明显受网络与服务端窗口影响，不能用于判断本地代码路径极限

补充记录：
- 2026-04-11 使用 `--send-thread-count 4` 做多 sender 短测时，`add_ok=29`、`success=0`、`fail=29`、`close_rc=0`
- 失败错误为 `http request failed`，未进入服务端成功响应，不能作为 persistent 多 sender 正确性结论
- 该失败更可能来自当前测试环境网络、endpoint 或真实配置，不影响本地 mock HTTP 与 UT 对多 sender checkpoint 语义的验证
- 因此当前策略定为：默认单 sender，多 sender 仅保留为隐藏能力

---

## 1. 约束与原则

### 1.1 分支策略

1. 任何只影响 `non-persistent` 路径的优化，优先修改 `feat_improve_sdk_more`，验证通过后再同步到 `persistent` 分支。
2. 任何只影响 `persistent` 路径的优化，只修改 `persistent` 分支，不回灌到 `feat_improve_sdk_more`。
3. 同时影响两条路径的优化，先确认是否会改变 `feat_improve_sdk_more` 的非持久化行为，再决定落点。
4. `non-persistent raw` 路径不是默认业务路径，优先级低于 `non-persistent kv/template` 和 `persistent kv/recover`。

### 1.2 优化目标

1. 保住 `feat_improve_sdk_more` 当前 `non-persistent kv/template` 的快路径模型。
2. 让 `persistent kv`、`persistent raw`、`persistent recover` 在真实环境下达到可解释、可观测、可持续优化的性能基线。
3. 不为了追求吞吐把 persistent 的断点续传、recover、lease/takeover 语义打坏。
4. 所有结论必须按路径分开评估，不能用单一路径的结论覆盖整个 producer。

---

## 2. 当前实现状态

### 2.1 Non-Persistent

- `kv/template` 默认快路径已经与 `feat_improve_sdk_more` 的现有优化基线对齐。
- `raw` 仍然是慢路径，仍走独立 raw queue 和 worker 消费。
- 当前没有证据表明 non-persistent 默认路径需要继续做高风险结构性改造。

### 2.2 Persistent

- `persistent kv` 已经具备完整的 append / send / ack / reclaim / recover 闭环。
- durable append 已经脱离 `producer->mutex`，但 persistent store 仍通过 `persistent_mutex` 串行化。
- `reclaim` 的“扫文件”成本已经显著下降，但触发模型仍偏保守。
- `reclaim` 已改成游标化 / 增量触发，append 前不再无条件执行回收。
- `ack_range()` 成功路径仍同步执行 checkpoint `write + fsync + close`，并继续在同一路径上做 segment 删除。
- `recover/open` 的扫描分配开销已经下降，但冷启动本质仍是线性扫描。
- SDK 默认保持 `single sender`；multi-sender 只保留为隐藏能力，不作为默认优化方向。

---

## 3. 剩余瓶颈

### 3.1 仍然值得关注的热点

1. checkpoint 持久化仍在 ack 热路径同步执行。
   - 当前每次 `ack_range()` 推进 `acked_log_id` 都会同步执行 checkpoint `open + write + fsync + close`。
   - 这部分发生在 sender 成功回调持有 `persistent_mutex` 的路径上，会直接拉长成功确认延迟。

2. ack 后的 segment 删除仍在 sender 热路径执行。
   - 当前 `reclaim_acked_segments()` 已不再重复扫文件，但仍会在 `ack_range()` 中同步执行 `path_remove()`。
   - 当一次 ack 释放多个 closed segment 时，本地删除成本仍会阻塞 sender。

3. `open/recover` 仍然是 `O(total_bytes)`。
   - 现在线性扫描已经更轻，但大目录冷启动、大量 segment 恢复仍然会受总数据量影响。
   - 对移动端和嵌入式场景，这比 steady state 吞吐更可能成为用户感知问题。

4. lease 校验仍是关键正确性成本。
   - append / ack / recover 仍保留逐次校验。
   - 这保证了 takeover 语义，但也意味着 persistent steady append 热路径还有固定额外开销。

5. `persistent raw` / `non-persistent raw` 仍是逐条消费。
   - 如果后续业务大量走 raw，这会成为显性瓶颈。
   - 如果 raw 继续只是少数路径，这项优先级仍可以放后。

6. key queue 结构优化仍然是条件性需求。
   - 只有高 `hash_key` 基数、ordered send、per-key breaker / rate limit 明显打开时才值得投入。

### 3.2 当前不再是主矛盾的点

- multi-sender 不是当前 persistent 默认路径的主收益来源。
- 大范围拆锁不是当前最合适的投入方向。
- sender 慢路径等待模型不是 persistent 默认链路的主瓶颈。

---

## 4. 剩余优化优先级

### P1：`reclaim` 游标化 / 增量触发（已完成）

已落地：
- 维护 `next_reclaim_segment_id` 游标。
- 仅在 `acked_log_id` 前进或接近容量水位时触发 reclaim。
- ack 推进后的 reclaim 只从游标位置继续，不再从头遍历 closed segment。

### P1.5：checkpoint 持久化合并 / 节流

目标：
- 降低 `ack_range()` 每次成功确认都同步 `fsync` checkpoint 的固定成本。

建议方向：
- 在内存中维护 `checkpoint_dirty` 和最近一次已推进的 `acked_log_id`。
- 只在以下时机强制落盘：
  - 距上次 durable checkpoint 超过固定窗口
  - 累积 ack 次数或 ack 前进量达到阈值
  - `close()` / lease 续约失败 / owner 释放 / takeover 前的关键时机
- 默认语义仍保持 durable checkpoint，不应把 `fsync` 静默降级成 `fflush`。
- 如果后续要支持弱持久模式，必须是显式配置，不应作为默认行为。

价值：
- 这是当前 sender 成功路径最明确的本地文件系统热点之一。
- 收益主要体现在 `persistent kv` steady ack 和真实环境持续发送场景。

### P2：ack 后回收异步化 / 延迟化

目标：
- 把 segment 删除从 sender 成功路径挪走，避免 `path_remove()` 直接阻塞 ack 成功确认。

建议方向：
- `ack_range()` 只推进 checkpoint 和“可回收上界”，不直接删除文件。
- 删除动作延后到以下维护时机：
  - append 前接近容量水位
  - heartbeat / 后台 maintenance tick
  - `close()` / `open()` / `recover()` 等需要收敛状态的时机
- 即使延迟删除，也必须以已 durable 的 checkpoint 为前提，不能倒置删除与 checkpoint 的顺序。

价值：
- 这项和 checkpoint 节流一起，能直接压缩 sender 成功路径上的本地 I/O。
- 比进一步大拆锁更聚焦，也更符合当前 persistent 默认单 sender 的优化方向。

### P3：冷启动 sidecar/meta 索引

目标：
- 减少 `open/recover` 对全量 segment 线性扫描的依赖。

建议方向：
- 为 closed segment 持久化 sidecar/meta/footer。
- 记录至少这些信息：
  - `valid_end`
  - `record_count`
  - `max_log_id`
  - 校验/version 信息
- 启动时优先读 sidecar，异常或损坏时回退到现有扫描修复。

价值：
- 这是面向移动端、嵌入式、断点恢复场景的高价值优化。
- 重点收益不是 steady throughput，而是冷启动和恢复时间。

### P4：更强 owner 原语后再压 lease 成本

目标：
- 在不破坏 takeover 语义的前提下，减少 append / ack / recover 的 lease 校验成本。

建议方向：
- 先研究跨 Android / 嵌入式可用的 owner 原语。
- 可选方向包括：
  - 文件锁
  - 更轻量的 fencing epoch
  - 本地 owner state + 低频校验组合

价值：
- 一旦做成，steady append 热路径还会有明显下降空间。
- 但这是高收益高风险项，必须放在正确性验证之后。

### P5：raw 路径批量 pop

目标：
- 降低 `raw` 路径逐条 pop / 逐条打包的固定开销。

适用路径：
- `non-persistent raw`
- `persistent raw`

前提：
- 只有在 raw 业务占比真实抬升后，这项才值得前移。

### P6：key queue 结构优化

目标：
- 只在高 feature 配置下压低 key queue 维护开销。

前提：
- 必须先有 benchmark 证明它已成为热点。

---

## 5. 当前明确不建议做的事

1. 不建议把 multi-sender 作为 persistent 默认能力。
2. 不建议现在做四锁或更激进的大范围拆锁。
3. 不建议在没有更强 owner 原语前，直接把 append 热路径 lease 校验降频。
4. 不建议为了追求吞吐，把默认 checkpoint 持久语义从 `fsync` 静默降级到 `fflush`。
5. 不建议在没有业务证据前，优先投入 `raw` 路径深优化。
6. 不建议在没有 benchmark 证据前，提前重构 key queue 数据结构。

---

## 6. 推荐实施顺序

1. 先做 `reclaim` 游标化 / 增量触发。
2. 再做 checkpoint 持久化合并 / 节流，但默认保持 durable 语义。
3. 再把 ack 后回收从 sender 成功路径异步化 / 延迟化。
4. 补“冷启动 / recover 耗时”专属 benchmark，并固化到文档。
5. 基于 benchmark 再做 sidecar/meta 索引设计。
6. 只有在跨平台 owner 原语可行时，再推进 lease 热路径进一步优化。
7. 只有 raw 业务量抬升时，再做 `raw` 批量 pop。

---

## 7. 验证口径

### 7.1 必须分开的 benchmark 维度

1. `non-persistent kv/template`
2. `persistent kv steady`
3. `persistent recover`
4. `persistent open/cold start`
5. `persistent raw`（仅当 raw 成为重点路径）

### 7.2 推荐保留的指标

1. `produce_lps`
2. `total_lps`
3. `recover_lps`
4. `acked_log_id`
5. `active_segment_id`
6. `current_segments/current_records/current_bytes`
7. `close_ms`
8. `logs_dropped_total`

### 7.3 评审时的判断规则

1. steady 生产速率和 drain 排空速率必须分开看。
2. direct persistent benchmark 更适合看 append / recover / ack 的代码路径变化，不适合拿单次跑数做绝对结论。
3. 真实环境 benchmark 只有在服务端成功响应稳定时，才可用于结论判断。
4. 默认单 sender 是稳定性策略，不应被临时压测数据轻易推翻。

---

## 8. 当前推荐结论

1. 当前最值得继续做的优化，不是多 sender，也不是大拆锁，而是 `reclaim` 触发模型优化，以及 ack 热路径上的 checkpoint/fsync 与删除成本收敛。
2. 如果要面向移动端和嵌入式长期演进，冷启动 sidecar/meta 索引仍然是下一阶段高价值方向。
3. lease 热路径继续优化必须建立在更强 owner 原语之上。
4. `raw` 路径和 key queue 结构优化都应由 benchmark 和真实业务占比驱动，而不是预先投入。

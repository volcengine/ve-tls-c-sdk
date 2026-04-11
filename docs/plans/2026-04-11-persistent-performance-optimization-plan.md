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
   - `send_thread_count > 1` 可用于 persistent producer，真实收益取决于网络/HTTP 发送是否是瓶颈

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
  - `persistent` 非持久化：约 `2.87M -> 4.28M logs/s`

#### B. Persistent 本地 benchmark

- `payload=256`：
  - append：`53.9k logs/s`
  - recover：`66.4k logs/s`
  - ack：`6 ms`
- `payload=5120`：
  - append：`20.0k logs/s`
  - recover：`21.6k logs/s`
  - ack：`4 ms`
- 对比本轮实施前基线：
  - `payload=256` append：约 `51.7k -> 53.9k logs/s`
  - `payload=5120` append：约 `18.5k -> 20.0k logs/s`
  - `ack` 从数百毫秒降到个位数毫秒，收益主要来自 reclaim 不再重复扫描 segment

#### C. Producer Persistent 本地 benchmark

使用 `ve_tls_bench --use-persistent 1`，mock HTTP，排除网络时延：

- 当前 producer 已允许 persistent 模式配置多个 sender；如需验证纯生产端瓶颈，可以固定 `--send-thread-count 1`，如需验证发送排空能力，可以提高 sender 数
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
- `kv + sls700 + 4 writers + persistent + 4 senders`：
  - `produce_lps=23.8k`
  - `total_lps=23.7k`
  - `close_ms=7`
  - `logs_dropped_total=0`
- `kv + sls5120 + 4 writers + persistent + 4 senders`：
  - `produce_lps=12.5k`
  - `total_lps=12.4k`
  - `logs_dropped_total=0`

说明：
- 该数据衡量 producer 持久化写入、入内存队列、builder、sender mock 的完整本地链路
- `produce_lps` 是生产线程完成写入的速率，更适合排查本地生产端瓶颈
- `total_lps` 会包含 `close()` 排空时间，更适合判断端到端 drain 能力
- 多 sender 对 mock HTTP 下的 `produce_lps` 提升不稳定，说明当前本地生产端仍主要受 durable append、序列化持久化写入和文件系统影响
- 多 sender 对 close drain 更直接有效，真实环境下如果网络/服务端 RTT 是瓶颈，收益会比 mock HTTP 更明显
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

## 2. 当前路径模型

### 2.1 Non-Persistent 路径

#### A. `kv/template` 默认快路径

- 入口：`ve_tls_producer_add_log_kv_*`
- 特征：
  - 默认命中 thread-local TLS batching
  - 默认命中 `fast_builder=1`
  - 默认命中 `fast_send=1`
- 结果：
  - 这是当前非持久化主业务路径
  - 应尽量保持与 `feat_improve_sdk_more` 一致

#### B. `raw` 路径

- 入口：`ve_tls_producer_add_log_raw_*`
- 特征：
  - 仍走 `producer->mutex + raw queue`
  - worker 逐条 `queue_pop`
- 结果：
  - 不是默认主路径
  - 性能优化优先级低于 `kv/template`

### 2.2 Persistent 路径

#### A. `persistent kv`

- 当前模型：
  - `producer->mutex`
  - `persistent append`
  - `ingress queue`
  - `builder merge`
  - `send`
- 现状：
  - 已经修正了“逐条直接发”的问题
  - 但仍存在 durable append 与 reclaim 的热点

#### B. `persistent raw`

- 当前模型：
  - `producer->mutex`
  - `persistent append`
  - `raw queue`
  - worker 逐条 `queue_pop`
- 现状：
  - 相对 `persistent kv` 更偏慢路径
  - 但业务优先级低

#### C. `persistent recover`

- 当前模型：
  - recover 从磁盘读取 raw record
  - 重新进入 ingress 聚合链路
  - 走正常发送/ack/reclaim
- 现状：
  - 语义已闭环
  - 仍受 reclaim 和 lease 校验影响

---

## 3. 性能热点重新定性

### 3.1 跨路径共性问题

#### 问题 1：`producer->mutex` 全局大锁

成立，但影响程度分路径不同。

- 对 `persistent kv/raw`：影响大，因为每条日志都要在持锁状态下做 durable append。
- 对 `non-persistent raw`：影响中等，因为仍走 raw queue。
- 对 `non-persistent kv/template`：影响相对小，因为 thread-local batching 先吸收了大部分写入。

结论：
- 这是整体结构性问题。
- 但不是第一步就要做“大拆锁”。

#### 问题 2：worker 逐条 pop raw queue

成立，但主要影响：

- `non-persistent raw`
- `persistent raw`

对 `persistent kv` 和 `non-persistent kv/template` 不是主热点，因为它们主要走 ingress/builder。

#### 问题 3：sender 慢路径等待模型

只在 `non-fast sender` 下成立。

- `fast_send` 路径已经是阻塞 `send_queue_pop(..., -1)`
- 非 `fast_send` 路径才有 `send_queue_pop(..., 0)` 加 `cond_timedwait_ms(<=100ms)` 的轮询模型

结论：
- 这是慢路径和 feature-rich 路径的问题
- 不是默认 persistent benchmark 的第一主因

#### 问题 4：key queue/ready/delayed/idle 结构维护

存在，但要分场景。

- 无 `hash_key`、无 ordered/per-key 限流时，多数默认快路径会绕过大部分 key queue 热点
- 有 `hash_key`、ordered、key breaker、key rate limit 时，这部分会变重

结论：
- 这是 feature 开关敏感的问题
- 不是默认 persistent 单 key/无 key benchmark 的头号瓶颈

### 3.2 Persistent 专属问题

#### 问题 5：`reclaim_acked_segments()` 热路径过重

这是当前最重的 persistent 问题。

- `append` 前会触发 `ensure_capacity_for_append()`
- `ack_range()` 后还会再次触发 reclaim
- 每次 reclaim 会遍历旧 segment
- 每个 segment 当前会：
  - `path_stat`
  - 扫文件拿 `valid_end/record_count`
  - 再扫文件拿 `max_log_id`

结论：
- 这是 persistent 版本相对 `feat_improve_sdk_more` 真正新增的核心热路径问题
- 优先级最高

#### 问题 6：`lease` 校验粒度过细

当前 `ve_tls_persistent_heartbeat_if_due()` 在判断是否需要 heartbeat 之前，先读 lease 文件做 `validate_current_lease()`。

结论：
- 这对正确性有帮助
- 但在单 writer 持续 append 场景下偏重
- 不能直接在 append/ack 热路径降频，否则会破坏 takeover 后旧 writer 立刻失效的语义
- 后续若要继续优化，前提是引入更强的 owner 原语，例如文件锁或更便宜的 fencing 机制

#### 问题 7：persistent 写入持有 `producer->mutex`

当前 durable append 是在 `producer->mutex` 持锁区内完成。

结论：
- 这是 persistent 写路径相对 `feat_improve_sdk_more` 变重的主要结构性原因
- 优先级仅次于 reclaim

---

## 4. 推荐优化路线

### 4.1 第一阶段：先保住 Non-Persistent 基线

这部分优先在 `feat_improve_sdk_more` 上实施，再同步到 `persistent`。

#### 优先做

1. 明确 benchmark 口径，分别测：
   - `non-persistent kv/template`
   - `non-persistent raw`
   - `persistent kv`
   - `persistent recover`
2. 保证 `non-persistent kv/template` 的快路径不被 persistent 改动破坏。
3. 对非 fast sender 做阻塞等待优化，减少 `send_queue_pop(..., 0)` 的轮询开销。
4. 把 worker 的固定 `100ms` partial builder 等待改成动态 deadline。

#### 暂不做

1. 不在这一阶段拆 producer 全局锁。
2. 不在这一阶段重构 key queue 数据结构。
3. 不优先处理 `non-persistent raw` 的细致优化。

### 4.2 第二阶段：Persistent 内部热路径优化

这部分只在 `persistent` 分支实施。

#### P0：segment 元数据缓存化

目标：让 reclaim 不再重复扫描 segment 文件。

建议设计：

- 在 `persistent` 内部维护 `segment_meta[]`
- 每个 segment 维护：
  - `segment_id`
  - `valid_end`
  - `record_count`
  - `max_log_id`
  - `closed`
- `open/recover` 时一次性重建
- `append` 时增量更新 active segment
- `rotate` 时固化 closed segment 元数据
- `ack/reclaim` 时只查内存元数据，不再扫文件

收益：

- 去掉 `append` 和 `ack_range` 上的双重全段扫描
- 这是当前收益最高、风险最低的优化

#### P1：lease 校验优化改为“只优化 heartbeat，不优化写前 fencing”

目标：在不破坏多进程 takeover 正确性的前提下，减少重复 lease 读取。

当前实施结论：

1. `heartbeat_if_due()` 在未到 heartbeat 时间前直接返回，不再做无意义 lease reload。
2. append / ack / recover 仍保留写前或关键路径上的 lease 校验。
3. append 热路径如果要继续降频，必须先引入文件锁或其他强 owner 原语，否则会让旧 writer 在 takeover 后继续写入。

收益：

- 去掉 heartbeat 未到期时的重复 lease reload
- 保住 takeover 语义，不引入写时一致性回退

#### P2：persistent append 脱离 `producer->mutex`

目标：降低 persistent 写线程之间的串行化。

建议设计：

1. `next_id` 改原子递增
2. `persistent` 自己持有内部锁
3. producer 主锁只负责：
   - queue/ingress
   - flush signal
   - builder 状态
4. durable append 完成后再回到 producer 主锁推进内存队列

收益：

- 明显降低 `persistent kv/raw` 的写侧竞争
- 风险远低于一次性拆成四把锁

### 4.3 第三阶段：慢路径和结构性优化

#### P3：raw 路径批量 pop

适用路径：

- `non-persistent raw`
- `persistent raw`

方法：

- worker 一次拿出 `N` 条 raw item，再批量处理

#### P4：慢路径 sender 阻塞化

适用路径：

- `non-fast sender`
- 有 ordered/per-key 限流/熔断功能的路径

方法：

- 减少 `send_queue_pop(..., 0)` 轮询
- 用更明确的条件驱动等待

#### P5：key queue 数据结构再优化

只在这些场景证明已成为热点后再做：

- 高 `hash_key` 基数
- ordered send
- per-key breaker / rate limit

---

## 5. 分支实施策略

### 5.1 先落 `feat_improve_sdk_more`

以下改动优先在 `feat_improve_sdk_more` 做：

1. `non-persistent kv/template` 的 benchmark 与回归基线固化
2. non-fast sender 阻塞等待优化
3. worker partial builder 的 `100ms` 等待优化
4. 如果需要，对 `non-persistent raw` 做批量 pop，但优先级较低

### 5.2 只落 `persistent`

以下改动只在 `persistent` 分支做：

1. segment 元数据缓存化
2. reclaim 逻辑改造
3. `heartbeat_if_due()` 级别的 lease 优化
4. persistent append 从 `producer->mutex` 中拆出
5. recover / ack / reclaim 的专属 benchmark 与真实环境验证

### 5.3 两边同步原则

1. 如果某个优化只改善 non-persistent 路径，就不要直接先改 `persistent`。
2. 如果某个优化对两条路径都有收益，优先在 `feat_improve_sdk_more` 落地，再同步。
3. `persistent` 分支永远不应该退化 non-persistent 默认路径。

---

## 6. 验证矩阵

### 6.1 必须分开的 benchmark 维度

1. `non-persistent kv/template`
2. `non-persistent raw`
3. `persistent kv`
4. `persistent raw`
5. `persistent recover`

### 6.2 日志模板

统一使用：

1. `sls200`
2. `sls700`
3. `sls5120`

### 6.3 输出指标

统一要求输出：

1. `enqueue_lps`
2. `enqueue_lps_avg`
3. `success_lps`
4. `success_lps_avg`
5. `enqueue_bytes_ps`
6. `send_bytes_ps`
7. `buffered_bytes`
8. `acked_log_id`
9. `active_segment_id`
10. `current_segments/current_records/current_bytes`

### 6.4 验证结论写法

评审时必须区分：

1. steady 生产速率
2. drain 排空速率
3. recover 回灌速率
4. 是否因 ack 未推进导致 segment 暂不删除

---

## 7. 实施任务拆分

### Task 1: 固化整体性能设计与分支策略

**Files:**
- Create: `docs/plans/2026-04-11-persistent-performance-optimization-plan.md`

**Step 1: 固化路径分类**

- `non-persistent kv/template`
- `non-persistent raw`
- `persistent kv`
- `persistent raw`
- `persistent recover`

**Step 2: 固化分支策略**

- non-persistent 优化先落 `feat_improve_sdk_more`
- persistent 专属优化只落 `persistent`

### Task 2: 先做 non-persistent 基线优化

**Branch:**
- First: `feat_improve_sdk_more`
- Then: `persistent`

**Focus:**

1. 慢路径 sender 阻塞等待
2. worker partial builder 等待模型优化
3. 非持久化 benchmark 固化

### Task 3: 再做 persistent P0/P1

**Branch:**
- `persistent`

**Focus:**

1. segment 元数据缓存化
2. reclaim 去文件重复扫描
3. lease 校验降频

### Task 4: persistent P2

**Branch:**
- `persistent`

**Focus:**

1. `next_id` 原子化
2. persistent 内部锁
3. durable append 与 producer 主锁解耦

### Task 5: 最后补慢路径优化

**Branch:**
- `feat_improve_sdk_more` for non-persistent shared path
- `persistent` for persistent-only path

**Focus:**

1. raw queue 批量 pop
2. key queue 结构优化（仅当 benchmark 证明需要）

---

## 8. 推荐实施顺序

1. 文档确认
2. `feat_improve_sdk_more`：
   - non-fast sender 等待优化
   - worker `100ms` 等待优化
   - non-persistent benchmark 固化
3. 同步上述 non-persistent 优化到 `persistent`
4. `persistent`：
   - segment 元数据缓存化
   - reclaim 改造
   - `heartbeat_if_due()` 级别的 lease 优化
5. `persistent`：
   - append 脱离 `producer->mutex`
6. 重新跑真实环境 benchmark 与 recover 验证

---

## 9. 当前推荐结论

1. 不建议第一步就全面拆成 `write_mutex/builder_mutex/send_mutex/persistent mutex` 四锁架构。
2. 第一优先级不是 sender，也不是 key queue，而是 `persistent reclaim + lease validate`。
3. `non-persistent raw` 不是默认业务路径，优先级应低于：
   - `non-persistent kv/template`
   - `persistent kv`
   - `persistent recover`
4. 所有 non-persistent 共享优化，优先落 `feat_improve_sdk_more`，再同步到 `persistent`。
